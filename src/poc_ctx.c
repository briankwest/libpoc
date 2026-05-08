/*
 * poc_ctx.c — Context lifecycle, I/O thread, ring-based poll
 *
 * Threading:
 *   I/O thread: tight poll loop on TCP+UDP fds, decodes audio into
 *               rx_ring, encodes from tx_ring, handles heartbeats.
 *   Caller:     poc_poll() drains rx_ring → on_audio_frame callbacks,
 *               drains evt_queue → on_state_change/on_ptt_* callbacks.
 *               poc_ptt_send_audio() pushes PCM into tx_ring.
 */

#include "poc_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <math.h>

/* Forward declaration */
static int locked_tcp_send(poc_ctx_t *ctx, const uint8_t *payload, uint16_t len);

static _Atomic int g_tx_drop_count = 0;

/* ── I/O thread ─────────────────────────────────────────────────── */

static void io_drain_tx(poc_ctx_t *ctx)
{
    poc_ring_frame_t frame;
    int drained = 0;
    while (poc_ring_pop(&ctx->tx_ring, &frame)) {
        drained++;
        uint8_t encoded[POC_CODEC_MAX_ENCODED_SIZE];
        int enc_len = poc_codec_encode(ctx->codec, frame.samples,
                                       frame.n_samples, encoded, sizeof(encoded));
        if (enc_len <= 0) {
            poc_log_at(POC_LOG_WARNING, "opus encode failed: %d", enc_len);
            continue;
        }

        uint8_t send_buf[POC_CODEC_MAX_ENCODED_SIZE + 16];
        int send_len = enc_len;
        const uint8_t *send_data = encoded;

        /* Encrypt if enabled — drop frame on failure (never send plaintext) */
        if (ctx->encrypt.enabled) {
            int elen = poc_encrypt_audio(&ctx->encrypt, ctx->active_group_id,
                                         encoded, enc_len, send_buf, sizeof(send_buf));
            if (elen > 0) {
                send_data = send_buf;
                send_len = elen;
            } else {
                poc_log_at(POC_LOG_ERROR, "encrypt failed, dropping frame");
                continue;
            }
        }

        /* Opus carries inband FEC inside each packet — no parity frames. */
        poc_udp_send(ctx, send_data, send_len);
    }
    if (drained > 0)
        poc_log_at(POC_LOG_WARNING, "tx: drained %d frames, sent via UDP", drained);
}

static void io_check_timers(poc_ctx_t *ctx)
{
    uint64_t now = poc_mono_ms();

    /* Login timeout */
    login_state_t ls = atomic_load(&ctx->login_state);
    if (ls == LOGIN_SENT_LOGIN && now - ctx->login_sent_at > LOGIN_TIMEOUT_MS) {
        poc_log_at(POC_LOG_WARNING, "login: timed out, retrying (%d/%d)...",
                   ctx->login_retries + 1, MAX_LOGIN_RETRIES);
        if (++ctx->login_retries < MAX_LOGIN_RETRIES) {
            uint8_t buf[256];
            int len = poc_build_login(ctx, buf, sizeof(buf));
            if (len > 0)
                poc_tcp_send_frame(ctx, buf, len);
            ctx->login_sent_at = now;
        } else {
            atomic_store(&ctx->login_state, LOGIN_FAILED);
            atomic_store(&ctx->state, POC_STATE_OFFLINE);
            poc_event_t evt = { .type = POC_EVT_LOGIN_ERROR,
                                .login_error = { .code = POC_ERR_TIMEOUT }};
            snprintf(evt.login_error.msg, sizeof(evt.login_error.msg), "login timeout");
            poc_evt_push(&ctx->evt_queue, &evt);
        }
    }

    /* Validate timeout */
    if (ls == LOGIN_SENT_VALIDATE && now - ctx->login_sent_at > VALIDATE_TIMEOUT_MS) {
        poc_log_at(POC_LOG_WARNING, "login: server did not respond to auth (timed out)");
        atomic_store(&ctx->login_state, LOGIN_FAILED);
        poc_event_t evt = { .type = POC_EVT_LOGIN_ERROR,
                            .login_error = { .code = POC_ERR_TIMEOUT }};
        snprintf(evt.login_error.msg, sizeof(evt.login_error.msg), "validate timeout");
        poc_evt_push(&ctx->evt_queue, &evt);
    }

    /* Heartbeat */
    if (atomic_load(&ctx->state) == POC_STATE_ONLINE &&
        now - ctx->last_heartbeat > (uint64_t)ctx->heartbeat_ms) {
        uint8_t buf[16];
        int len = poc_build_heartbeat(ctx, buf, sizeof(buf));
        if (len > 0) {
            poc_tcp_send_frame(ctx, buf, len);
            ctx->last_heartbeat = now;
        }
    }
}

static void io_start_reconnect(poc_ctx_t *ctx)
{
    /* Close dead sockets */
    poc_tcp_close(ctx);
    poc_udp_close(ctx);

    /* Reset PTT state */
    atomic_store(&ctx->ptt_active, false);
    atomic_store(&ctx->ptt_rx_active, false);

    /* Start exponential backoff: 2s, 4s, 8s, ... 512s, then give up */
    if (!ctx->reconnect_active) {
        ctx->reconnect_delay_ms = RECONNECT_INIT_MS;
        ctx->reconnect_active = true;
    } else {
        ctx->reconnect_delay_ms *= 2;
    }

    if (ctx->reconnect_delay_ms > RECONNECT_MAX_MS) {
        poc_log_at(POC_LOG_ERROR, "gave up reconnecting after %ds", RECONNECT_MAX_MS / 1000);
        ctx->reconnect_active = false;
        atomic_store(&ctx->state, POC_STATE_OFFLINE);
        atomic_store(&ctx->login_state, LOGIN_IDLE);
        poc_event_t evt = { .type = POC_EVT_STATE_CHANGE,
                            .state_change = { .state = POC_STATE_OFFLINE }};
        poc_evt_push(&ctx->evt_queue, &evt);
        poc_event_t err = { .type = POC_EVT_LOGIN_ERROR,
                            .login_error = { .code = POC_ERR_NETWORK }};
        snprintf(err.login_error.msg, sizeof(err.login_error.msg),
                 "reconnect failed after backoff");
        poc_evt_push(&ctx->evt_queue, &err);
        return;
    }

    ctx->reconnect_at = poc_mono_ms() + ctx->reconnect_delay_ms;
    poc_log("reconnecting in %ds...", ctx->reconnect_delay_ms / 1000);

    atomic_store(&ctx->state, POC_STATE_CONNECTING);
    poc_event_t evt = { .type = POC_EVT_STATE_CHANGE,
                        .state_change = { .state = POC_STATE_CONNECTING }};
    poc_evt_push(&ctx->evt_queue, &evt);
}

static bool io_try_reconnect(poc_ctx_t *ctx)
{
    if (!ctx->reconnect_active) return false;
    if (poc_mono_ms() < ctx->reconnect_at) return false;

    poc_log("connecting to %s:%u...", ctx->server_host, ctx->server_port);

    int rc = poc_tcp_connect(ctx);
    if (rc != POC_OK) {
        poc_log_at(POC_LOG_WARNING, "connection to %s:%u failed", ctx->server_host, ctx->server_port);
        io_start_reconnect(ctx);  /* double the backoff */
        return false;
    }

    poc_udp_open(ctx);

    /* Send login */
    uint8_t buf[256];
    int len = poc_build_login(ctx, buf, sizeof(buf));
    if (len > 0)
        poc_tcp_send_frame(ctx, buf, len);

    atomic_store(&ctx->login_state, LOGIN_SENT_LOGIN);
    ctx->login_sent_at = poc_mono_ms();
    ctx->login_retries = 0;
    ctx->reconnect_active = false;

    poc_log("connected, authenticating...");
    return true;
}

static void *io_thread_fn(void *arg)
{
    poc_ctx_t *ctx = (poc_ctx_t *)arg;
    poc_log_at(POC_LOG_DEBUG, "I/O thread started (ctx=%p, tx_ring.cap=%d)",
               (void *)ctx, ctx->tx_ring.capacity);
    uint64_t loop_count = 0;

    while (atomic_load(&ctx->io_running)) {
        loop_count++;

        /* Log first 50 iterations in detail, then every 50 */
        bool do_log = (loop_count <= 50) || ((loop_count % 50) == 0);
        if (do_log)
            poc_log_at(POC_LOG_WARNING, "I/O #%llu TOP reconnect=%d tcp=%d udp=%d",
                       (unsigned long long)loop_count, ctx->reconnect_active,
                       ctx->tcp_fd, ctx->udp_fd);

        /* If we're in reconnect backoff, check if it's time to retry */
        if (ctx->reconnect_active) {
            if (do_log) poc_log_at(POC_LOG_WARNING, "I/O #%llu in RECONNECT", (unsigned long long)loop_count);
            io_try_reconnect(ctx);
            struct pollfd wfd = { .fd = ctx->io_wakeup[0], .events = POLLIN };
            poll(&wfd, 1, 100);
            if (wfd.revents & POLLIN) {
                char tmp[64];
                while (read(ctx->io_wakeup[0], tmp, sizeof(tmp)) > 0);
            }
            continue;
        }

        struct pollfd fds[3];
        int nfds = 0;

        fds[nfds].fd = ctx->io_wakeup[0];
        fds[nfds].events = POLLIN;
        nfds++;

        if (ctx->tcp_fd >= 0) {
            fds[nfds].fd = ctx->tcp_fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        if (ctx->udp_fd >= 0) {
            fds[nfds].fd = ctx->udp_fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        if (do_log)
            poc_log_at(POC_LOG_WARNING, "I/O #%llu POLL nfds=%d", (unsigned long long)loop_count, nfds);

        int rc = poll(fds, nfds, 20);

        if (do_log)
            poc_log_at(POC_LOG_WARNING, "I/O #%llu POLL returned rc=%d", (unsigned long long)loop_count, rc);

        if (rc < 0) {
            if (errno == EINTR) continue;
            poc_log_at(POC_LOG_ERROR, "I/O: poll error: %s", strerror(errno));
            break;
        }

        if (!atomic_load(&ctx->io_running)) break;

        /* Drain wakeup pipe */
        if (fds[0].revents & POLLIN) {
            char tmp[64];
            while (read(ctx->io_wakeup[0], tmp, sizeof(tmp)) > 0);
        }

        /* TCP */
        bool tcp_dead = false;
        for (int i = 1; i < nfds; i++) {
            if (fds[i].fd == ctx->tcp_fd) {
                if (fds[i].revents & POLLIN) {
                    if (do_log) poc_log_at(POC_LOG_WARNING, "I/O #%llu TCP recv...", (unsigned long long)loop_count);
                    rc = poc_tcp_recv(ctx);
                    if (do_log) poc_log_at(POC_LOG_WARNING, "I/O #%llu TCP recv rc=%d", (unsigned long long)loop_count, rc);
                    if (rc == POC_ERR_NETWORK) tcp_dead = true;
                }
                if (fds[i].revents & (POLLERR | POLLHUP))
                    tcp_dead = true;
            }

            if (fds[i].fd == ctx->udp_fd && (fds[i].revents & POLLIN))
                poc_udp_recv(ctx);
        }

        if (tcp_dead) {
            poc_log_at(POC_LOG_ERROR, "I/O: connection lost, reconnecting");
            io_start_reconnect(ctx);
            continue;
        }

        if (atomic_load(&ctx->login_state) == LOGIN_FAILED) {
            poc_log_at(POC_LOG_ERROR, "I/O: login failed — exiting");
            break;
        }

        {
            int tx_count = poc_ring_count(&ctx->tx_ring);
            if (tx_count > 0 || (do_log && atomic_load(&ctx->ptt_active)))
                poc_log_at(POC_LOG_WARNING, "I/O #%llu DRAIN tx=%d ptt=%d",
                           (unsigned long long)loop_count, tx_count,
                           (int)atomic_load(&ctx->ptt_active));
            io_drain_tx(ctx);
        }
        io_check_timers(ctx);
        poc_gps_tick(ctx);

        if (do_log)
            poc_log_at(POC_LOG_WARNING, "I/O #%llu BOTTOM", (unsigned long long)loop_count);
    }

    poc_log_at(POC_LOG_WARNING, "I/O thread EXITING (running=%d, login=%d, loop=%llu)",
               atomic_load(&ctx->io_running), atomic_load(&ctx->login_state),
               (unsigned long long)loop_count);
    return NULL;
}

static void io_wakeup(poc_ctx_t *ctx)
{
    char c = 1;
    if (write(ctx->io_wakeup[1], &c, 1) < 0) { /* best-effort */ }
}

/* ── Public API ─────────────────────────────────────────────────── */

poc_ctx_t *poc_create(const poc_config_t *cfg, const poc_callbacks_t *cb)
{
    if (!cfg || !cfg->server_host || !cfg->account || !cfg->password)
        return NULL;

    poc_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    snprintf(ctx->server_host, sizeof(ctx->server_host), "%s", cfg->server_host);
    ctx->server_port = cfg->server_port ? cfg->server_port : 29999;
    snprintf(ctx->account, sizeof(ctx->account), "%s", cfg->account);
    poc_sha1(cfg->password, ctx->password_sha1);

    if (cfg->imei)
        snprintf(ctx->imei, sizeof(ctx->imei), "%s", cfg->imei);
    if (cfg->iccid)
        snprintf(ctx->iccid, sizeof(ctx->iccid), "%s", cfg->iccid);

    ctx->heartbeat_ms = cfg->heartbeat_ms > 0 ? cfg->heartbeat_ms : HEARTBEAT_DEFAULT_MS;

    /* TLS */
    ctx->tls_enabled = cfg->tls;
    ctx->tls_verify = cfg->tls_verify;
    if (cfg->tls_ca_path)
        snprintf(ctx->tls_ca_path, sizeof(ctx->tls_ca_path), "%s", cfg->tls_ca_path);
    else
        ctx->tls_ca_path[0] = '\0';

    atomic_store(&ctx->state, POC_STATE_OFFLINE);
    atomic_store(&ctx->login_state, LOGIN_IDLE);
    atomic_store(&ctx->io_running, false);
    atomic_store(&ctx->ptt_active, false);
    atomic_store(&ctx->ptt_rx_active, false);
    pthread_mutex_init(&ctx->sig_mutex, NULL);
    ctx->tcp_fd = -1;
    ctx->udp_fd = -1;
    ctx->io_wakeup[0] = -1;
    ctx->io_wakeup[1] = -1;

    if (cb)
        ctx->cb = *cb;

    /* Init dynamic arrays */
    ctx->groups = calloc(DEFAULT_GROUPS, sizeof(poc_group_t));
    ctx->group_cap = ctx->groups ? DEFAULT_GROUPS : 0;
    ctx->users = calloc(DEFAULT_USERS, sizeof(poc_user_t));
    ctx->user_cap = ctx->users ? DEFAULT_USERS : 0;
    if (!ctx->groups || !ctx->users) {
        free(ctx->groups); free(ctx->users);
        pthread_mutex_destroy(&ctx->sig_mutex);
        free(ctx);
        return NULL;
    }

    /* Init rings and event queue */
    int rx_frames = cfg->rx_ring_frames > 0 ? cfg->rx_ring_frames : RX_RING_FRAMES;
    int tx_frames = cfg->tx_ring_frames > 0 ? cfg->tx_ring_frames : TX_RING_FRAMES;
    poc_ring_init(&ctx->rx_ring, rx_frames);
    poc_ring_init(&ctx->tx_ring, tx_frames);
    poc_evt_init(&ctx->evt_queue);

    /* Init codec (Opus SWB, hardcoded) */
    ctx->codec = poc_codec_create();
    if (!ctx->codec) {
        poc_log_at(POC_LOG_ERROR, "failed to create Opus codec");
        poc_ring_destroy(&ctx->rx_ring);
        poc_ring_destroy(&ctx->tx_ring);
        pthread_mutex_destroy(&ctx->sig_mutex);
        free(ctx);
        return NULL;
    }

    /* Init encryption */
    poc_encrypt_init(&ctx->encrypt);

    /* Init receive jitter buffer (default 120 ms = 6 frames at 20 ms). */
    int jitter_ms = cfg->jitter_ms > 0 ? cfg->jitter_ms : 120;
    int depth = jitter_ms / 20;
    if (depth < 2) depth = 2;
    if (poc_jb_init(&ctx->jb, depth) < 0) {
        poc_log_at(POC_LOG_ERROR, "failed to allocate jitter buffer");
        poc_codec_destroy(ctx->codec);
        poc_encrypt_destroy(&ctx->encrypt);
        poc_ring_destroy(&ctx->rx_ring);
        poc_ring_destroy(&ctx->tx_ring);
        pthread_mutex_destroy(&ctx->sig_mutex);
        free(ctx);
        return NULL;
    }

    /* Init GPS */
    ctx->gps_interval_ms = cfg->gps_interval_ms > 0 ? cfg->gps_interval_ms
                                                     : GPS_DEFAULT_INTERVAL_MS;
    atomic_store(&ctx->gps_valid, false);
    atomic_store(&ctx->gps_updated, false);

    poc_log("client: %s@%s:%u ready", ctx->account, ctx->server_host, ctx->server_port);
    return ctx;
}

void poc_destroy(poc_ctx_t *ctx)
{
    if (!ctx) return;
    poc_disconnect(ctx);
    poc_codec_destroy(ctx->codec);
    poc_encrypt_destroy(&ctx->encrypt);
    poc_jb_destroy(&ctx->jb);
    poc_ring_destroy(&ctx->rx_ring);
    poc_ring_destroy(&ctx->tx_ring);
    free(ctx->groups);
    free(ctx->users);
    pthread_mutex_destroy(&ctx->sig_mutex);
    free(ctx);
}

int poc_connect(poc_ctx_t *ctx)
{
    if (!ctx) return POC_ERR;
    if (atomic_load(&ctx->state) == POC_STATE_ONLINE)
        return POC_OK;

    atomic_store(&ctx->state, POC_STATE_CONNECTING);
    atomic_store(&ctx->login_state, LOGIN_CONNECTING);
    ctx->login_retries = 0;

    /* Wakeup pipe for I/O thread */
    if (pipe(ctx->io_wakeup) < 0)
        return POC_ERR;

    /* TCP connect (blocking, before thread starts) */
    int rc = poc_tcp_connect(ctx);
    if (rc != POC_OK) {
        close(ctx->io_wakeup[0]); close(ctx->io_wakeup[1]);
        ctx->io_wakeup[0] = ctx->io_wakeup[1] = -1;
        atomic_store(&ctx->state, POC_STATE_OFFLINE);
        return rc;
    }

    /* UDP */
    poc_udp_open(ctx);

    /* Start I/O thread BEFORE sending login so it's already polling
     * when the server's challenge response arrives. Avoids a race
     * where the response arrives before the thread's first poll(). */
    atomic_store(&ctx->io_running, true);
    if (pthread_create(&ctx->io_thread, NULL, io_thread_fn, ctx) != 0) {
        atomic_store(&ctx->io_running, false);
        poc_tcp_close(ctx);
        poc_udp_close(ctx);
        return POC_ERR;
    }

    /* Set login state BEFORE sending — the I/O thread may process the
     * server's response before we get back from the send call. */
    atomic_store(&ctx->login_state, LOGIN_SENT_LOGIN);
    ctx->login_sent_at = poc_mono_ms();

    /* Send login — I/O thread is already running and will catch the response */
    uint8_t buf[256];
    int len = poc_build_login(ctx, buf, sizeof(buf));
    if (len < 0) {
        atomic_store(&ctx->login_state, LOGIN_IDLE);
        poc_disconnect(ctx);
        return POC_ERR;
    }
    rc = locked_tcp_send(ctx, buf, len);
    if (rc != POC_OK) {
        atomic_store(&ctx->login_state, LOGIN_IDLE);
        poc_disconnect(ctx);
        return rc;
    }

    /* Push CONNECTING event for caller */
    poc_event_t evt = { .type = POC_EVT_STATE_CHANGE,
                        .state_change = { .state = POC_STATE_CONNECTING }};
    poc_evt_push(&ctx->evt_queue, &evt);

    poc_log("connecting to %s:%u, authenticating...", ctx->server_host, ctx->server_port);
    return POC_OK;
}

int poc_disconnect(poc_ctx_t *ctx)
{
    if (!ctx) return POC_ERR;

    /* Stop I/O thread: close sockets first to unblock any pending
     * send/recv, then signal and join. */
    if (atomic_load(&ctx->io_running)) {
        atomic_store(&ctx->io_running, false);
        /* Close sockets to break any blocking send/recv in the I/O thread */
        poc_tcp_close(ctx);
        poc_udp_close(ctx);
        io_wakeup(ctx);

        /* Timed join — don't hang forever if I/O thread is stuck */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 500000000;  /* 500ms max wait */
        if (ts.tv_nsec >= 1000000000) { ts.tv_nsec -= 1000000000; ts.tv_sec++; }
#if (defined(__linux__) || defined(__GLIBC__)) && !defined(__ANDROID__)
        int jrc = pthread_timedjoin_np(ctx->io_thread, NULL, &ts);
        if (jrc != 0) {
            poc_log_at(POC_LOG_WARNING, "I/O thread join timed out, detaching");
            pthread_detach(ctx->io_thread);
        }
#else
        pthread_join(ctx->io_thread, NULL);
#endif
    } else {
        poc_tcp_close(ctx);
        poc_udp_close(ctx);
    }

    if (ctx->io_wakeup[0] >= 0) { close(ctx->io_wakeup[0]); ctx->io_wakeup[0] = -1; }
    if (ctx->io_wakeup[1] >= 0) { close(ctx->io_wakeup[1]); ctx->io_wakeup[1] = -1; }

    atomic_store(&ctx->state, POC_STATE_OFFLINE);
    atomic_store(&ctx->login_state, LOGIN_IDLE);
    atomic_store(&ctx->ptt_active, false);
    atomic_store(&ctx->ptt_rx_active, false);

    poc_ring_flush(&ctx->rx_ring);
    poc_ring_flush(&ctx->tx_ring);

    return POC_OK;
}

/*
 * Drain rings and event queue, fire callbacks.
 * Safe to call from any thread (typically the audio/main thread).
 * timeout_ms is ignored now — always non-blocking.
 */
int poc_poll(poc_ctx_t *ctx, int timeout_ms)
{
    (void)timeout_ms;
    if (!ctx) return POC_ERR_STATE;

    /* Drain event queue → fire signaling callbacks */
    poc_event_t evt;
    while (poc_evt_pop(&ctx->evt_queue, &evt)) {
        switch (evt.type) {
        case POC_EVT_STATE_CHANGE:
            if (ctx->cb.on_state_change)
                ctx->cb.on_state_change(ctx, evt.state_change.state, ctx->cb.userdata);
            break;
        case POC_EVT_LOGIN_ERROR:
            if (ctx->cb.on_login_error)
                ctx->cb.on_login_error(ctx, evt.login_error.code,
                                       evt.login_error.msg, ctx->cb.userdata);
            break;
        case POC_EVT_PTT_START:
            if (ctx->cb.on_ptt_start)
                ctx->cb.on_ptt_start(ctx, evt.ptt_start.speaker_id,
                                     evt.ptt_start.name,
                                     evt.ptt_start.group_id, ctx->cb.userdata);
            break;
        case POC_EVT_PTT_END:
            if (ctx->cb.on_ptt_end)
                ctx->cb.on_ptt_end(ctx, evt.ptt_end.speaker_id,
                                   evt.ptt_end.group_id, ctx->cb.userdata);
            break;
        case POC_EVT_PTT_GRANTED:
            if (ctx->cb.on_ptt_granted)
                ctx->cb.on_ptt_granted(ctx, evt.ptt_granted.granted, ctx->cb.userdata);
            break;
        case POC_EVT_MESSAGE:
            if (ctx->cb.on_message)
                ctx->cb.on_message(ctx, evt.message.from_id,
                                   evt.message.text, ctx->cb.userdata);
            break;
        case POC_EVT_GROUPS_UPDATED:
            if (ctx->cb.on_groups_updated)
                ctx->cb.on_groups_updated(ctx, ctx->groups, ctx->group_count,
                                          ctx->cb.userdata);
            break;
        case POC_EVT_FORCE_EXIT:
            if (ctx->cb.on_state_change)
                ctx->cb.on_state_change(ctx, POC_STATE_OFFLINE, ctx->cb.userdata);
            break;
        case POC_EVT_USER_STATUS:
            /* Update cached user directory */
            for (int i = 0; i < ctx->user_count; i++) {
                if (ctx->users[i].id == evt.user_status.user_id) {
                    ctx->users[i].status = evt.user_status.status;
                    break;
                }
            }
            if (ctx->cb.on_user_status)
                ctx->cb.on_user_status(ctx, evt.user_status.user_id,
                                       evt.user_status.status, ctx->cb.userdata);
            break;
        case POC_EVT_USER_REMOVED:
            if (ctx->cb.on_user_status)
                ctx->cb.on_user_status(ctx, evt.user_removed.user_id,
                                       -1, ctx->cb.userdata);
            break;
        case POC_EVT_TMP_GROUP_INVITE:
            if (ctx->cb.on_tmp_group_invite)
                ctx->cb.on_tmp_group_invite(ctx, evt.tmp_group_invite.group_id,
                                            evt.tmp_group_invite.inviter_id,
                                            ctx->cb.userdata);
            break;
        case POC_EVT_PULL_TO_GROUP:
            if (ctx->cb.on_pull_to_group)
                ctx->cb.on_pull_to_group(ctx, evt.pull_to_group.group_id,
                                         ctx->cb.userdata);
            break;
        case POC_EVT_VOICE_MESSAGE:
            if (ctx->cb.on_voice_message)
                ctx->cb.on_voice_message(ctx, evt.voice_message.from_id,
                                         evt.voice_message.note_id,
                                         evt.voice_message.desc, ctx->cb.userdata);
            break;
        case POC_EVT_SOS:
            if (ctx->cb.on_sos)
                ctx->cb.on_sos(ctx, evt.sos.user_id, evt.sos.alert_type,
                               ctx->cb.userdata);
            break;
        case POC_EVT_MSG_DELIVERED:
            if (ctx->cb.on_msg_delivered)
                ctx->cb.on_msg_delivered(ctx, evt.msg_delivered.user_id, ctx->cb.userdata);
            break;
        case POC_EVT_MSG_READ:
            if (ctx->cb.on_msg_read)
                ctx->cb.on_msg_read(ctx, evt.msg_read.user_id, ctx->cb.userdata);
            break;
        case POC_EVT_TYPING:
            if (ctx->cb.on_typing)
                ctx->cb.on_typing(ctx, evt.typing.user_id, evt.typing.typing, ctx->cb.userdata);
            break;
        case POC_EVT_AUDIO:
        case POC_EVT_PUSH_TOKEN:
            break;  /* server-only events, not used in client context */
        }
    }

    /* The I/O thread is the canonical owner of socket I/O, but as a
     * fallback we also drain TX and recv from the caller thread in
     * case the I/O thread is stalled. The double-free that was
     * possible here previously is gone: poc_tcp_close / poc_udp_close
     * are now mutex-guarded and idempotent, so concurrent close from
     * the I/O thread and the caller thread is safe. */
    io_drain_tx(ctx);
    poc_udp_recv(ctx);
    if (poc_tcp_recv(ctx) == POC_ERR_NETWORK) {
        poc_log_at(POC_LOG_ERROR, "poll: connection lost — resetting to offline");
        atomic_store(&ctx->state, POC_STATE_OFFLINE);
        atomic_store(&ctx->ptt_active, false);
        atomic_store(&ctx->ptt_rx_active, false);
        poc_tcp_close(ctx);
        poc_udp_close(ctx);
        poc_event_t evt = { .type = POC_EVT_STATE_CHANGE,
                            .state_change = { .state = POC_STATE_OFFLINE }};
        poc_evt_push(&ctx->evt_queue, &evt);
    }

    /* Drain RX audio ring → fire audio callbacks */
    poc_ring_frame_t frame;
    while (poc_ring_pop(&ctx->rx_ring, &frame)) {
        if (ctx->cb.on_audio_frame) {
            poc_audio_frame_t af = {
                .samples = frame.samples,
                .n_samples = frame.n_samples,
                .sample_rate = ctx->codec->sample_rate,
                .speaker_id = frame.speaker_id,
                .group_id = frame.group_id,
            };
            ctx->cb.on_audio_frame(ctx, &af, ctx->cb.userdata);
        }
        /* Audio level metering */
        if (ctx->cb.on_audio_level && frame.n_samples > 0) {
            double sum_sq = 0;
            for (int i = 0; i < frame.n_samples; i++)
                sum_sq += (double)frame.samples[i] * frame.samples[i];
            double rms = sqrt(sum_sq / frame.n_samples);
            float rms_db = (rms > 0) ? (float)(20.0 * log10(rms / 32768.0)) : -96.0f;
            ctx->cb.on_audio_level(ctx, frame.speaker_id, rms_db, ctx->cb.userdata);
        }
    }

    return POC_OK;
}

/* ── Locked helpers for caller-thread TCP send ──────────────────── */

static int locked_tcp_send(poc_ctx_t *ctx, const uint8_t *payload, uint16_t len)
{
    pthread_mutex_lock(&ctx->sig_mutex);
    int rc = poc_tcp_send_frame(ctx, payload, len);
    pthread_mutex_unlock(&ctx->sig_mutex);
    return rc;
}

/* ── Public API — these push into rings or send on I/O thread ──── */

int poc_enter_group(poc_ctx_t *ctx, uint32_t group_id)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;

    uint8_t buf[32];
    int len = poc_build_enter_group(ctx, group_id, buf, sizeof(buf));
    if (len < 0) return len;

    pthread_mutex_lock(&ctx->sig_mutex);
    int rc = poc_tcp_send_frame(ctx, buf, len);
    if (rc == POC_OK)
        ctx->active_group_id = group_id;
    pthread_mutex_unlock(&ctx->sig_mutex);
    return rc;
}

int poc_leave_group(poc_ctx_t *ctx)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;

    uint8_t buf[16];
    int len = poc_build_leave_group(ctx, buf, sizeof(buf));
    if (len < 0) return len;

    pthread_mutex_lock(&ctx->sig_mutex);
    int rc = poc_tcp_send_frame(ctx, buf, len);
    if (rc == POC_OK)
        ctx->active_group_id = 0;
    pthread_mutex_unlock(&ctx->sig_mutex);
    return rc;
}

int poc_ptt_start(poc_ctx_t *ctx)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    if (atomic_load(&ctx->ptt_active))
        return POC_OK;

    uint8_t buf[64];
    int len = poc_build_start_ptt(ctx, buf, sizeof(buf));
    if (len < 0) return len;

    /* Flush stale audio before sending PTT start to prevent
     * cross-session audio leakage. */
    poc_ring_flush(&ctx->tx_ring);
    atomic_store(&g_tx_drop_count, 0);

    int rc = locked_tcp_send(ctx, buf, len);
    if (rc == POC_OK) {
        atomic_store(&ctx->ptt_active, true);
        poc_log("PTT start: tx_ring flushed, ring cap=%d", ctx->tx_ring.capacity);
    }
    return rc;
}

int poc_ptt_stop(poc_ctx_t *ctx)
{
    if (!ctx || !atomic_load(&ctx->ptt_active))
        return POC_ERR_STATE;

    uint8_t buf[16];
    int len = poc_build_end_ptt(ctx, buf, sizeof(buf));
    if (len < 0) return len;

    int rc = locked_tcp_send(ctx, buf, len);
    atomic_store(&ctx->ptt_active, false);
    int drops = atomic_load(&g_tx_drop_count);
    poc_log("PTT stop: %d frames dropped during session", drops);
    return rc;
}

/*
 * Push PCM into TX ring. I/O thread will encode + UDP send.
 * Non-blocking — drops frames if ring is full.
 */
int poc_ptt_send_audio(poc_ctx_t *ctx, const int16_t *pcm, int n_samples)
{
    if (!ctx || !atomic_load(&ctx->ptt_active)) {
        static int skip_log = 0;
        if (++skip_log <= 3)
            poc_log_at(POC_LOG_WARNING, "send_audio: skipped — ctx=%p ptt_active=%d",
                       (void *)ctx, ctx ? (int)atomic_load(&ctx->ptt_active) : -1);
        return POC_ERR_STATE;
    }

    int frame_samples = ctx->codec->frame_samples;
    int offset = 0;
    while (offset + frame_samples <= n_samples) {
        if (!poc_ring_push(&ctx->tx_ring, pcm + offset,
                           frame_samples, 0, 0)) {
            int drops = atomic_fetch_add(&g_tx_drop_count, 1);
            if (drops == 0 || (drops % 50) == 0)
                poc_log_at(POC_LOG_WARNING,
                           "audio TX buffer full — dropped %d frames (ring: head=%u tail=%u cap=%d)",
                           drops + 1,
                           atomic_load(&ctx->tx_ring.head),
                           atomic_load(&ctx->tx_ring.tail),
                           ctx->tx_ring.capacity);
            break;
        }
        offset += frame_samples;
    }

    /* Nudge I/O thread to drain */
    io_wakeup(ctx);

    return POC_OK;
}

int poc_set_gps(poc_ctx_t *ctx, float lat, float lng)
{
    if (!ctx) return POC_ERR;
    return poc_gps_update(ctx, lat, lng);
}

int poc_send_group_msg(poc_ctx_t *ctx, uint32_t group_id, const char *msg)
{
    if (!ctx || !msg || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[512];
    int len = poc_build_send_group_msg(ctx, group_id, msg, buf, sizeof(buf));
    if (len < 0) return len;
    return locked_tcp_send(ctx, buf, len);
}

int poc_send_user_msg(poc_ctx_t *ctx, uint32_t user_id, const char *msg)
{
    if (!ctx || !msg || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[512];
    int len = poc_build_send_user_msg(ctx, user_id, msg, buf, sizeof(buf));
    if (len < 0) return len;
    return locked_tcp_send(ctx, buf, len);
}

int poc_call_user(poc_ctx_t *ctx, uint32_t user_id)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    /* Private call: StartPTT with target user ID */
    uint8_t buf[64];
    pthread_mutex_lock(&ctx->sig_mutex); ctx->session_id++;
    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_START_PTT;
    buf[6] = POC_CODEC_OPUS_SWB;
    poc_write16(buf + 7, 0x0000);
    poc_write32(buf + 9, user_id);
    int rc = poc_tcp_send_frame(ctx, buf, 13); pthread_mutex_unlock(&ctx->sig_mutex);
    if (rc == POC_OK)
        atomic_store(&ctx->ptt_active, true);
    return rc;
}

int poc_call_end(poc_ctx_t *ctx)
{
    return poc_ptt_stop(ctx);
}

bool poc_is_encrypted(const poc_ctx_t *ctx)
{
    return ctx ? ctx->encrypt.enabled : false;
}

int poc_get_group_count(const poc_ctx_t *ctx)
{
    if (!ctx) return 0;
    pthread_mutex_lock(&((poc_ctx_t *)ctx)->sig_mutex);
    int n = ctx->group_count;
    pthread_mutex_unlock(&((poc_ctx_t *)ctx)->sig_mutex);
    return n;
}

int poc_get_groups(const poc_ctx_t *ctx, poc_group_t *out, int max)
{
    if (!ctx || !out) return 0;
    pthread_mutex_lock(&((poc_ctx_t *)ctx)->sig_mutex);
    int n = ctx->group_count < max ? ctx->group_count : max;
    memcpy(out, ctx->groups, n * sizeof(poc_group_t));
    pthread_mutex_unlock(&((poc_ctx_t *)ctx)->sig_mutex);
    return n;
}

int poc_get_user_count(const poc_ctx_t *ctx)
{
    if (!ctx) return 0;
    pthread_mutex_lock(&((poc_ctx_t *)ctx)->sig_mutex);
    int n = ctx->user_count;
    pthread_mutex_unlock(&((poc_ctx_t *)ctx)->sig_mutex);
    return n;
}

int poc_get_users(const poc_ctx_t *ctx, poc_user_t *out, int max)
{
    if (!ctx || !out) return 0;
    pthread_mutex_lock(&((poc_ctx_t *)ctx)->sig_mutex);
    int n = ctx->user_count < max ? ctx->user_count : max;
    memcpy(out, ctx->users, n * sizeof(poc_user_t));
    pthread_mutex_unlock(&((poc_ctx_t *)ctx)->sig_mutex);
    return n;
}

int poc_set_status(poc_ctx_t *ctx, int status)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[8];
    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_NOTIFY_MOD_STATUS;
    buf[6] = (uint8_t)status;
    return locked_tcp_send(ctx, buf, 7);
}

int poc_send_read_receipt(poc_ctx_t *ctx, uint32_t to_user_id)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[16];
    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_NOTIFY_EXT_DATA;
    poc_write32(buf + 6, to_user_id);
    buf[10] = 0xFD;  /* read receipt marker */
    return locked_tcp_send(ctx, buf, 11);
}

int poc_send_typing(poc_ctx_t *ctx, uint32_t to_user_id, bool typing)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[16];
    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_NOTIFY_EXT_DATA;
    poc_write32(buf + 6, to_user_id);
    buf[10] = 0xFB;  /* typing marker */
    buf[11] = typing ? 1 : 0;
    return locked_tcp_send(ctx, buf, 12);
}

poc_state_t poc_get_state(const poc_ctx_t *ctx)
{
    return ctx ? atomic_load(&ctx->state) : POC_STATE_OFFLINE;
}

uint32_t poc_get_user_id(const poc_ctx_t *ctx)
{
    return ctx ? ctx->user_id : 0;
}

const char *poc_get_account(const poc_ctx_t *ctx)
{
    return ctx ? ctx->account : "";
}

/* ── Phase 2: Temp groups + monitor + dispatch ─────────────────── */

static int send_user_id_list_cmd(poc_ctx_t *ctx, uint8_t cmd,
                                 const uint32_t *ids, int count)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[256];
    int off = 0;
    buf[off++] = ctx->session_id;
    poc_write32(buf + off, ctx->user_id); off += 4;
    buf[off++] = cmd;
    for (int i = 0; i < count && off + 4 <= (int)sizeof(buf); i++) {
        poc_write32(buf + off, ids[i]); off += 4;
    }
    return locked_tcp_send(ctx, buf, off);
}

static int send_group_cmd(poc_ctx_t *ctx, uint8_t cmd, uint32_t group_id)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[16];
    int off = 0;
    buf[off++] = ctx->session_id;
    poc_write32(buf + off, ctx->user_id); off += 4;
    buf[off++] = cmd;
    poc_write32(buf + off, group_id); off += 4;
    return locked_tcp_send(ctx, buf, off);
}

int poc_invite_tmp_group(poc_ctx_t *ctx, const uint32_t *user_ids, int count)
{
    return send_user_id_list_cmd(ctx, CMD_NOTIFY_INVITE_TMP, user_ids, count);
}

int poc_accept_tmp_group(poc_ctx_t *ctx, uint32_t group_id)
{
    return send_group_cmd(ctx, CMD_NOTIFY_ENTER_TMP, group_id);
}

int poc_reject_tmp_group(poc_ctx_t *ctx, uint32_t group_id)
{
    return send_group_cmd(ctx, CMD_NOTIFY_REJECT_TMP, group_id);
}

int poc_monitor_group(poc_ctx_t *ctx, uint32_t group_id)
{
    return send_group_cmd(ctx, CMD_NOTIFY_ENTER_GROUP, group_id);
}

int poc_unmonitor_group(poc_ctx_t *ctx, uint32_t group_id)
{
    return send_group_cmd(ctx, CMD_NOTIFY_LEAVE_TMP, group_id);
}

int poc_pull_users_to_group(poc_ctx_t *ctx, const uint32_t *user_ids, int count)
{
    return send_user_id_list_cmd(ctx, CMD_PULL_TO_GROUP, user_ids, count);
}

int poc_force_user_exit(poc_ctx_t *ctx, const uint32_t *user_ids, int count)
{
    return send_user_id_list_cmd(ctx, CMD_FORCE_EXIT, user_ids, count);
}

/* ── Phase 3: SOS + voice messages ─────────────────────────────── */

int poc_send_sos(poc_ctx_t *ctx, int alert_type)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[16];
    int off = 0;
    buf[off++] = ctx->session_id;
    poc_write32(buf + off, ctx->user_id); off += 4;
    buf[off++] = CMD_NOTIFY_EXT_DATA;  /* SOS uses ext data with special prefix */
    buf[off++] = 0xFF;  /* SOS marker */
    buf[off++] = (uint8_t)alert_type;
    return locked_tcp_send(ctx, buf, off);
}

int poc_cancel_sos(poc_ctx_t *ctx)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[16];
    int off = 0;
    buf[off++] = ctx->session_id;
    poc_write32(buf + off, ctx->user_id); off += 4;
    buf[off++] = CMD_NOTIFY_EXT_DATA;
    buf[off++] = 0xFE;  /* SOS cancel marker */
    return locked_tcp_send(ctx, buf, off);
}

int poc_request_voice_message(poc_ctx_t *ctx, uint64_t note_id)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[32];
    int off = 0;
    buf[off++] = ctx->session_id;
    poc_write32(buf + off, ctx->user_id); off += 4;
    buf[off++] = CMD_VOICE_MESSAGE;
    poc_write32(buf + off, (uint32_t)(note_id >> 32)); off += 4;
    poc_write32(buf + off, (uint32_t)(note_id & 0xFFFFFFFF)); off += 4;
    return locked_tcp_send(ctx, buf, off);
}

/* ── APNs push token (Apple PushToTalk framework support) ──────── */

/* Build and send the cached token frame. Caller MUST hold sig_mutex
 * AND must have verified state == POC_STATE_ONLINE. Internal helper
 * shared by poc_set_push_token() (when called post-login) and
 * poc_resend_push_token_if_set_locked() (called from the I/O thread
 * right after login transitions to ONLINE). */
static int send_cached_push_token_locked(poc_ctx_t *ctx)
{
    uint8_t buf[8 + sizeof(ctx->push_token) + sizeof(ctx->push_bundle_id)];
    int len = poc_build_register_push_token(ctx,
                                            ctx->push_token,
                                            ctx->push_token_len,
                                            ctx->push_bundle_id,
                                            buf, sizeof(buf));
    if (len < 0) return POC_ERR;
    return poc_tcp_send_frame(ctx, buf, (uint16_t)len);
}

int poc_set_push_token(poc_ctx_t *ctx,
                       const uint8_t *token, size_t token_len,
                       const char *bundle_id)
{
    if (!ctx) return POC_ERR_STATE;
    if (!token || token_len == 0 || token_len > sizeof(ctx->push_token))
        return POC_ERR;
    if (!bundle_id || !bundle_id[0]) return POC_ERR;
    size_t bid_len = strlen(bundle_id);
    if (bid_len >= sizeof(ctx->push_bundle_id)) return POC_ERR;

    pthread_mutex_lock(&ctx->sig_mutex);
    memcpy(ctx->push_token, token, token_len);
    ctx->push_token_len = (uint8_t)token_len;
    snprintf(ctx->push_bundle_id, sizeof(ctx->push_bundle_id), "%s", bundle_id);

    /* Only flush to wire if the session is fully online. Pre-auth
     * 0x90 frames break some servers' login state machines (the
     * server is mid-handshake and has no place to dispatch them).
     * If we're not ONLINE yet, the cache will be flushed by
     * poc_resend_push_token_if_set_locked() the moment user_data
     * arrives and login transitions to ONLINE. */
    int online = (atomic_load(&ctx->state) == POC_STATE_ONLINE);
    int sent_ok = 0;
    if (online)
        sent_ok = (send_cached_push_token_locked(ctx) == POC_OK);
    pthread_mutex_unlock(&ctx->sig_mutex);

    if (online && sent_ok)
        poc_log("push: cached and sent APNs token (%zu B, bundle=%s)",
                token_len, bundle_id);
    else if (online)
        poc_log("push: cached APNs token but TCP send failed (%zu B, bundle=%s)",
                token_len, bundle_id);
    else
        poc_log("push: cached APNs token, deferred until ONLINE "
                "(%zu B, bundle=%s)", token_len, bundle_id);
    return POC_OK;
}

size_t poc_get_push_token(const poc_ctx_t *ctx, uint8_t *out, size_t out_max)
{
    if (!ctx) return 0;
    pthread_mutex_lock(&((poc_ctx_t *)ctx)->sig_mutex);
    size_t n = ctx->push_token_len;
    if (out && n > 0 && out_max >= n)
        memcpy(out, ctx->push_token, n);
    pthread_mutex_unlock(&((poc_ctx_t *)ctx)->sig_mutex);
    return n;
}

/* Caller MUST hold sig_mutex. Called from handle_user_data() in the
 * I/O thread right after state transitions to POC_STATE_ONLINE; the
 * outer poc_parse_message() already owns the lock, so this helper
 * cannot relock without deadlocking the I/O thread. */
void poc_resend_push_token_if_set_locked(poc_ctx_t *ctx)
{
    if (!ctx || ctx->push_token_len == 0) return;
    if (atomic_load(&ctx->state) != POC_STATE_ONLINE) return;

    int rc = send_cached_push_token_locked(ctx);
    poc_log("push: re-sent cached APNs token after login (rc=%d, %u B)",
            rc, (unsigned)ctx->push_token_len);
}
