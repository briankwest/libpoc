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

/* ── I/O thread ─────────────────────────────────────────────────── */

static void io_drain_tx(poc_ctx_t *ctx)
{
    poc_ring_frame_t frame;
    while (poc_ring_pop(&ctx->tx_ring, &frame)) {
        uint8_t encoded[SPEEX_FRAME_ENC];
        int enc_len = poc_speex_encode(&ctx->speex, frame.samples, encoded);
        if (enc_len <= 0) continue;

        uint8_t send_buf[128];
        int send_len = enc_len;
        const uint8_t *send_data = encoded;

        /* Encrypt if enabled */
        if (ctx->encrypt.enabled) {
            int elen = poc_encrypt_audio(&ctx->encrypt, ctx->active_group_id,
                                         encoded, enc_len, send_buf, sizeof(send_buf));
            if (elen > 0) {
                send_data = send_buf;
                send_len = elen;
            }
        }

        /* FEC: may produce data + parity frame */
        if (ctx->fec.enabled) {
            uint8_t fec1[POC_FEC_MAX_FRAME], fec2[POC_FEC_MAX_FRAME];
            int nframes = poc_fec_encode(&ctx->fec, send_data, send_len,
                                          fec1, fec2, sizeof(fec1));
            poc_udp_send(ctx, fec1, send_len);
            if (nframes == 2)
                poc_udp_send(ctx, fec2, send_len);
        } else {
            poc_udp_send(ctx, send_data, send_len);
        }
    }
}

static void io_check_timers(poc_ctx_t *ctx)
{
    uint64_t now = poc_mono_ms();

    /* Login timeout */
    login_state_t ls = atomic_load(&ctx->login_state);
    if (ls == LOGIN_SENT_LOGIN && now - ctx->login_sent_at > LOGIN_TIMEOUT_MS) {
        poc_log("io: login timeout");
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
        poc_log("io: validate timeout");
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

static void *io_thread_fn(void *arg)
{
    poc_ctx_t *ctx = (poc_ctx_t *)arg;
    poc_log("io: thread started");

    while (atomic_load(&ctx->io_running)) {
        struct pollfd fds[3];
        int nfds = 0;

        /* Wakeup pipe (for shutdown signal and tx_ring nudge) */
        fds[nfds].fd = ctx->io_wakeup[0];
        fds[nfds].events = POLLIN;
        nfds++;

        /* TCP */
        if (ctx->tcp_fd >= 0) {
            fds[nfds].fd = ctx->tcp_fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        /* UDP */
        if (ctx->udp_fd >= 0) {
            fds[nfds].fd = ctx->udp_fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        int rc = poll(fds, nfds, 20);  /* 20ms max — matches audio frame cadence */
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Drain wakeup pipe */
        if (fds[0].revents & POLLIN) {
            char tmp[64];
            while (read(ctx->io_wakeup[0], tmp, sizeof(tmp)) > 0);
        }

        /* TCP */
        for (int i = 1; i < nfds; i++) {
            if (fds[i].fd == ctx->tcp_fd) {
                if (fds[i].revents & POLLIN) {
                    rc = poc_tcp_recv(ctx);
                    if (rc == POC_ERR_NETWORK) {
                        poc_log("io: TCP connection lost");
                        poc_event_t evt = { .type = POC_EVT_STATE_CHANGE,
                                            .state_change = { .state = POC_STATE_OFFLINE }};
                        poc_evt_push(&ctx->evt_queue, &evt);
                        atomic_store(&ctx->state, POC_STATE_OFFLINE);
                        atomic_store(&ctx->login_state, LOGIN_IDLE);
                    }
                }
                if (fds[i].revents & (POLLERR | POLLHUP)) {
                    poc_log("io: TCP error/hangup");
                    poc_event_t evt = { .type = POC_EVT_STATE_CHANGE,
                                        .state_change = { .state = POC_STATE_OFFLINE }};
                    poc_evt_push(&ctx->evt_queue, &evt);
                    atomic_store(&ctx->state, POC_STATE_OFFLINE);
                    atomic_store(&ctx->login_state, LOGIN_IDLE);
                }
            }

            /* UDP */
            if (fds[i].fd == ctx->udp_fd && (fds[i].revents & POLLIN)) {
                poc_udp_recv(ctx);
            }
        }

        /* Drain TX ring: encode + UDP send */
        if (atomic_load(&ctx->ptt_active))
            io_drain_tx(ctx);

        /* Timers */
        io_check_timers(ctx);

        /* GPS reporting */
        poc_gps_tick(ctx);
    }

    poc_log("io: thread exiting");
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

    ctx->codec = cfg->codec;
    ctx->heartbeat_ms = cfg->heartbeat_ms > 0 ? cfg->heartbeat_ms : HEARTBEAT_DEFAULT_MS;

    atomic_store(&ctx->state, POC_STATE_OFFLINE);
    atomic_store(&ctx->login_state, LOGIN_IDLE);
    atomic_store(&ctx->io_running, false);
    atomic_store(&ctx->ptt_active, false);
    atomic_store(&ctx->ptt_rx_active, false);
    ctx->tcp_fd = -1;
    ctx->udp_fd = -1;
    ctx->io_wakeup[0] = -1;
    ctx->io_wakeup[1] = -1;

    if (cb)
        ctx->cb = *cb;

    /* Init rings and event queue */
    poc_ring_init(&ctx->rx_ring, RX_RING_FRAMES);
    poc_ring_init(&ctx->tx_ring, TX_RING_FRAMES);
    poc_evt_init(&ctx->evt_queue);

    /* Init codec */
    poc_speex_init(&ctx->speex);

    /* Init encryption */
    poc_encrypt_init(&ctx->encrypt);

    /* Init FEC */
    poc_fec_init(&ctx->fec, cfg->fec_group_size);
    ctx->fec.enabled = cfg->enable_fec;

    /* Init GPS */
    ctx->gps_interval_ms = cfg->gps_interval_ms > 0 ? cfg->gps_interval_ms
                                                     : GPS_DEFAULT_INTERVAL_MS;
    atomic_store(&ctx->gps_valid, false);
    atomic_store(&ctx->gps_updated, false);

    poc_log("ctx: created for %s@%s:%u", ctx->account, ctx->server_host, ctx->server_port);
    return ctx;
}

void poc_destroy(poc_ctx_t *ctx)
{
    if (!ctx) return;
    poc_disconnect(ctx);
    poc_speex_destroy(&ctx->speex);
    poc_encrypt_destroy(&ctx->encrypt);
    poc_fec_destroy(&ctx->fec);
    poc_ring_destroy(&ctx->rx_ring);
    poc_ring_destroy(&ctx->tx_ring);
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

    /* Send login */
    uint8_t buf[256];
    int len = poc_build_login(ctx, buf, sizeof(buf));
    if (len < 0) {
        poc_tcp_close(ctx);
        return POC_ERR;
    }
    rc = poc_tcp_send_frame(ctx, buf, len);
    if (rc != POC_OK) {
        poc_tcp_close(ctx);
        return rc;
    }

    atomic_store(&ctx->login_state, LOGIN_SENT_LOGIN);
    ctx->login_sent_at = poc_mono_ms();

    /* Start I/O thread */
    atomic_store(&ctx->io_running, true);
    if (pthread_create(&ctx->io_thread, NULL, io_thread_fn, ctx) != 0) {
        atomic_store(&ctx->io_running, false);
        poc_tcp_close(ctx);
        poc_udp_close(ctx);
        return POC_ERR;
    }

    /* Push CONNECTING event for caller */
    poc_event_t evt = { .type = POC_EVT_STATE_CHANGE,
                        .state_change = { .state = POC_STATE_CONNECTING }};
    poc_evt_push(&ctx->evt_queue, &evt);

    poc_log("ctx: login sent, I/O thread running");
    return POC_OK;
}

int poc_disconnect(poc_ctx_t *ctx)
{
    if (!ctx) return POC_ERR;

    /* Stop I/O thread */
    if (atomic_load(&ctx->io_running)) {
        atomic_store(&ctx->io_running, false);
        io_wakeup(ctx);
        pthread_join(ctx->io_thread, NULL);
    }

    poc_tcp_close(ctx);
    poc_udp_close(ctx);

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
        case POC_EVT_FORCE_EXIT:
        case POC_EVT_GROUPS_UPDATED:
            break;
        }
    }

    /* Drain RX audio ring → fire audio callbacks */
    poc_ring_frame_t frame;
    while (poc_ring_pop(&ctx->rx_ring, &frame)) {
        if (ctx->cb.on_audio_frame) {
            poc_audio_frame_t af = {
                .samples = frame.samples,
                .n_samples = POC_AUDIO_FRAME_SAMPLES,
                .sample_rate = POC_AUDIO_RATE,
                .speaker_id = frame.speaker_id,
                .group_id = frame.group_id,
            };
            ctx->cb.on_audio_frame(ctx, &af, ctx->cb.userdata);
        }
    }

    return POC_OK;
}

/* ── Public API — these push into rings or send on I/O thread ──── */

int poc_enter_group(poc_ctx_t *ctx, uint32_t group_id)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;

    uint8_t buf[32];
    int len = poc_build_enter_group(ctx, group_id, buf, sizeof(buf));
    if (len < 0) return len;

    int rc = poc_tcp_send_frame(ctx, buf, len);
    if (rc == POC_OK)
        ctx->active_group_id = group_id;
    return rc;
}

int poc_leave_group(poc_ctx_t *ctx)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;

    uint8_t buf[16];
    int len = poc_build_leave_group(ctx, buf, sizeof(buf));
    if (len < 0) return len;

    int rc = poc_tcp_send_frame(ctx, buf, len);
    if (rc == POC_OK)
        ctx->active_group_id = 0;
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

    int rc = poc_tcp_send_frame(ctx, buf, len);
    if (rc == POC_OK)
        atomic_store(&ctx->ptt_active, true);
    return rc;
}

int poc_ptt_stop(poc_ctx_t *ctx)
{
    if (!ctx || !atomic_load(&ctx->ptt_active))
        return POC_ERR_STATE;

    uint8_t buf[16];
    int len = poc_build_end_ptt(ctx, buf, sizeof(buf));
    if (len < 0) return len;

    int rc = poc_tcp_send_frame(ctx, buf, len);
    atomic_store(&ctx->ptt_active, false);
    return rc;
}

/*
 * Push PCM into TX ring. I/O thread will encode + UDP send.
 * Non-blocking — drops frames if ring is full.
 */
int poc_ptt_send_audio(poc_ctx_t *ctx, const int16_t *pcm, int n_samples)
{
    if (!ctx || !atomic_load(&ctx->ptt_active))
        return POC_ERR_STATE;

    int offset = 0;
    while (offset + POC_AUDIO_FRAME_SAMPLES <= n_samples) {
        if (!poc_ring_push(&ctx->tx_ring, pcm + offset,
                           POC_AUDIO_FRAME_SAMPLES, 0, 0)) {
            poc_log("ctx: tx_ring full, dropping frame");
            break;
        }
        offset += POC_AUDIO_FRAME_SAMPLES;
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
    return poc_tcp_send_frame(ctx, buf, len);
}

int poc_send_user_msg(poc_ctx_t *ctx, uint32_t user_id, const char *msg)
{
    if (!ctx || !msg || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    uint8_t buf[512];
    int len = poc_build_send_user_msg(ctx, user_id, msg, buf, sizeof(buf));
    if (len < 0) return len;
    return poc_tcp_send_frame(ctx, buf, len);
}

int poc_call_user(poc_ctx_t *ctx, uint32_t user_id)
{
    if (!ctx || atomic_load(&ctx->state) != POC_STATE_ONLINE)
        return POC_ERR_STATE;
    /* Private call: StartPTT with target user ID */
    uint8_t buf[64];
    ctx->session_id++;
    buf[0] = ctx->session_id;
    poc_write32(buf + 1, ctx->user_id);
    buf[5] = CMD_START_PTT;
    buf[6] = 0;  /* Speex codec */
    poc_write16(buf + 7, 0x0000);
    poc_write32(buf + 9, user_id);
    int rc = poc_tcp_send_frame(ctx, buf, 13);
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
    return ctx ? ctx->group_count : 0;
}

int poc_get_groups(const poc_ctx_t *ctx, poc_group_t *out, int max)
{
    if (!ctx || !out) return 0;
    int n = ctx->group_count < max ? ctx->group_count : max;
    memcpy(out, ctx->groups, n * sizeof(poc_group_t));
    return n;
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
