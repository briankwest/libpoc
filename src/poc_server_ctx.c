/*
 * poc_server_ctx.c — Server context, I/O thread, state machine
 *
 * Handles: TCP listener, client accept, MS-frame deframing,
 * login challenge-response, heartbeat, group management,
 * PTT floor arbitration, UDP audio relay, message routing, SOS.
 */

#include "poc_server_internal.h"
#include "poc_proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>        /* TLS handshake only */
#include <sys/epoll.h>  /* I/O thread */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ── Helpers ────────────────────────────────────────────────────── */

static void srv_sha1_hex(const char *input, char *hex)
{
    unsigned char d[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)input, strlen(input), d);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) sprintf(hex + i * 2, "%02x", d[i]);
    hex[40] = '\0';
}

static int srv_send_frame_ssl(int fd, SSL *ssl, const uint8_t *payload, uint16_t len)
{
    int total = POC_MS_HDR_LEN + len;
    uint8_t *frame = malloc(total);
    if (!frame) return POC_ERR_NOMEM;
    frame[0] = POC_MS_MAGIC_0;
    frame[1] = POC_MS_MAGIC_1;
    poc_write16(frame + 2, len);
    memcpy(frame + POC_MS_HDR_LEN, payload, len);
    int sent = 0;
    while (sent < total) {
        int n;
        if (ssl) {
            n = SSL_write(ssl, frame + sent, total - sent);
            if (n <= 0) {
                int err = SSL_get_error(ssl, n);
                if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) continue;
                free(frame);
                return POC_ERR_NETWORK;
            }
        } else {
            n = send(fd, frame + sent, total - sent, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EAGAIN || errno == EINTR) continue;
                free(frame);
                return POC_ERR_NETWORK;
            }
        }
        sent += n;
    }
    free(frame);
    return POC_OK;
}

/* Convenience: send to a client */
static int srv_send_frame(srv_client_t *cl, const uint8_t *payload, uint16_t len)
{
    return srv_send_frame_ssl(cl->fd, cl->ssl, payload, len);
}

static void srv_broadcast_group(poc_server_t *srv, uint32_t group_id,
                                const uint8_t *payload, uint16_t len, int exclude_fd)
{
    for (int i = 0; i < srv->client_count; i++) {
        srv_client_t *c = &srv->clients[i];
        if (c->state == SRV_CLIENT_ONLINE && c->active_group == group_id && c->fd != exclude_fd)
            srv_send_frame(c, payload, len);
    }
}

static void srv_broadcast_all(poc_server_t *srv, const uint8_t *payload, uint16_t len, int exclude_fd)
{
    for (int i = 0; i < srv->client_count; i++)
        if (srv->clients[i].state == SRV_CLIENT_ONLINE && srv->clients[i].fd != exclude_fd)
            srv_send_frame(&srv->clients[i], payload, len);
}

static srv_user_t *srv_find_user(poc_server_t *srv, const char *account)
{
    for (int i = 0; i < srv->user_count; i++)
        if (strcmp(srv->users[i].account, account) == 0) return &srv->users[i];
    return NULL;
}

static srv_client_t *srv_find_client(poc_server_t *srv, uint32_t user_id)
{
    for (int i = 0; i < srv->client_count; i++)
        if (srv->clients[i].user_id == user_id && srv->clients[i].state == SRV_CLIENT_ONLINE)
            return &srv->clients[i];
    return NULL;
}

static int srv_find_group_idx(poc_server_t *srv, uint32_t gid)
{
    for (int i = 0; i < srv->group_count; i++)
        if (srv->groups[i].id == gid) return i;
    return -1;
}

static void srv_status_broadcast(poc_server_t *srv, uint32_t user_id, int status, int exclude_fd)
{
    uint8_t msg[8];
    msg[0] = 0; msg[1] = POC_NOTIFY_MOD_STATUS;
    poc_write32(msg + 2, user_id); msg[6] = (uint8_t)status;
    srv_broadcast_all(srv, msg, 7, exclude_fd);
}

static const char *srv_state_name(srv_client_state_t s)
{
    switch (s) {
    case SRV_CLIENT_NEW:        return "new";
    case SRV_CLIENT_CHALLENGED: return "authenticating";
    case SRV_CLIENT_ONLINE:     return "online";
    default:                    return "unknown";
    }
}

/* ── Client disconnect ──────────────────────────────────────────── */

static void srv_disconnect(poc_server_t *srv, int idx)
{
    srv_client_t *cl = &srv->clients[idx];
    poc_log_at(POC_LOG_INFO, "srv: %s (user %u) disconnected", cl->account, cl->user_id);

    if (cl->state == SRV_CLIENT_ONLINE) {
        srv_status_broadcast(srv, cl->user_id, 0, cl->fd);

        /* Fire on_group_leave if client was in a group */
        if (cl->active_group && srv->cb.on_group_leave)
            srv->cb.on_group_leave(srv, cl->user_id, cl->active_group, srv->cb.userdata);

        /* Clear private_call_target on any client that was in a call with us */
        if (cl->user_id) {
            for (int i = 0; i < srv->client_count; i++) {
                if (i != idx && srv->clients[i].private_call_target == cl->user_id)
                    srv->clients[i].private_call_target = 0;
            }
        }

        /* Release floor */
        for (int i = 0; i < srv->group_count; i++)
            if (srv->groups[i].floor_holder == idx) srv->groups[i].floor_holder = -1;

        /* Push disconnect event */
        poc_event_t evt = { .type = POC_EVT_USER_STATUS };
        evt.user_status.user_id = cl->user_id;
        evt.user_status.status = -1; /* disconnected */
        poc_evt_push(&srv->evt_queue, &evt);
    }

    if (cl->ssl) { SSL_shutdown(cl->ssl); SSL_free(cl->ssl); cl->ssl = NULL; }
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_DEL, cl->fd, NULL);
    close(cl->fd);
    srv->client_count--;
    if (idx < srv->client_count) {
        srv->clients[idx] = srv->clients[srv->client_count];
        /* Fix floor holder indices */
        for (int i = 0; i < srv->group_count; i++)
            if (srv->groups[i].floor_holder == srv->client_count)
                srv->groups[i].floor_holder = idx;
    }
}

/* ── Protocol handlers ──────────────────────────────────────────── */

static void srv_handle_login(poc_server_t *srv, srv_client_t *cl, const uint8_t *data, int len)
{
    if (len < 10) return;
    cl->session_id = data[0];
    const char *account = (const char *)(data + 10);

    snprintf(cl->account, sizeof(cl->account), "%s", account);
    srv_user_t *user = srv_find_user(srv, account);
    if (!user) {
        poc_log_at(POC_LOG_WARNING, "srv: login rejected — unknown account '%s'", account);
        uint8_t err[4] = { cl->session_id, POC_NOTIFY_RESPONSE, 0x06 };
        srv_send_frame(cl, err, 3);
        return;
    }

    cl->user_id = user->user_id;
    memcpy(cl->password_sha1, user->password_sha1, 41);
    cl->challenge_nonce = (uint32_t)random();
    cl->state = SRV_CLIENT_CHALLENGED;
    cl->login_time = poc_mono_ms();

    uint8_t resp[16];
    int off = 0;
    resp[off++] = cl->session_id;
    resp[off++] = POC_NOTIFY_CHALLENGE;
    poc_write32(resp + off, cl->user_id); off += 4;
    poc_write32(resp + off, cl->challenge_nonce); off += 4;
    resp[off++] = 0; /* privilege_ex */
    poc_write16(resp + off, 0); off += 2; /* key_type */
    resp[off++] = 0; /* gps_flag */

    srv_send_frame(cl, resp, off);
    poc_log_at(POC_LOG_INFO, "srv: %s: sent auth challenge (user %u)", account, cl->user_id);
}

static void srv_handle_validate(poc_server_t *srv, srv_client_t *cl, const uint8_t *data, int len)
{
    if (len < 26 || cl->state != SRV_CLIENT_CHALLENGED) {
        poc_log_at(POC_LOG_WARNING, "srv: %s: auth response rejected (expected %s, got %s)",
                   cl->account, srv_state_name(SRV_CLIENT_CHALLENGED), srv_state_name(cl->state));
        return;
    }
    uint8_t session = data[0];
    const uint8_t *client_hmac = data + 6;

    uint8_t nonce_buf[4];
    poc_write32(nonce_buf, cl->challenge_nonce);
    uint8_t expected[20];
    unsigned int hlen = 20;
    HMAC(EVP_sha1(), (const uint8_t *)cl->password_sha1, 40, nonce_buf, 4, expected, &hlen);

    if (memcmp(client_hmac, expected, 20) != 0) {
        poc_log_at(POC_LOG_WARNING, "srv: %s: authentication failed (bad password)", cl->account);
        uint8_t err[4] = { session, POC_NOTIFY_RESPONSE, 0x01 };
        srv_send_frame(cl, err, 3);
        return;
    }

    cl->state = SRV_CLIENT_ONLINE;
    cl->last_heartbeat = poc_mono_ms();
    /* Copy priority from user DB */
    for (int i = 0; i < srv->user_count; i++) {
        if (srv->users[i].user_id == cl->user_id) {
            cl->priority = srv->users[i].priority;
            break;
        }
    }
    poc_log_at(POC_LOG_INFO, "srv: %s authenticated — now online (user %u, priority %u)",
               cl->account, cl->user_id, cl->priority);

    /* Broadcast online status */
    srv_status_broadcast(srv, cl->user_id, 1, cl->fd);

    /* Build UserData: groups + user directory
     * Format: [session][cmd][group_count(2)][groups...][user_count(2)][users...]
     * Group: [gid(4)][nlen(1)][name(N)]
     * User:  [uid(4)][nlen(1)][name(N)][status(1)]
     */
    uint8_t resp[4096];
    int off = 0;
    resp[off++] = session;
    resp[off++] = POC_NOTIFY_USER_DATA;

    /* --- Groups --- */
    int gcount = 0;
    for (int i = 0; i < srv->group_count; i++) {
        srv_group_t *g = &srv->groups[i];
        if (g->member_count == 0) { gcount++; continue; }
        for (int j = 0; j < g->member_count; j++)
            if (g->members[j] == cl->user_id) { gcount++; break; }
    }
    poc_write16(resp + off, gcount); off += 2;

    for (int i = 0; i < srv->group_count; i++) {
        srv_group_t *g = &srv->groups[i];
        bool is_member = (g->member_count == 0);
        for (int j = 0; !is_member && j < g->member_count; j++)
            if (g->members[j] == cl->user_id) is_member = true;
        if (!is_member) continue;
        if (off + 5 + 64 > (int)sizeof(resp)) break;
        poc_write32(resp + off, g->id); off += 4;
        int nlen = strlen(g->name);
        resp[off++] = nlen;
        memcpy(resp + off, g->name, nlen); off += nlen;
    }

    /* --- User directory --- */
    poc_write16(resp + off, srv->user_count); off += 2;
    for (int i = 0; i < srv->user_count; i++) {
        srv_user_t *u = &srv->users[i];
        if (off + 6 + 64 > (int)sizeof(resp)) break;
        poc_write32(resp + off, u->user_id); off += 4;
        /* Send display name (full name) */
        const char *display = u->name[0] ? u->name : u->account;
        int nlen = strlen(display);
        resp[off++] = nlen;
        memcpy(resp + off, display, nlen); off += nlen;
        resp[off++] = poc_server_is_user_online(srv, u->user_id) ? 1 : 0;
    }

    srv_send_frame(cl, resp, off);
    poc_log("srv: sent user_data to %s: %d groups, %d users (%d bytes)",
            cl->account, gcount, srv->user_count, off);

    /* Push connect event */
    poc_event_t evt = { .type = POC_EVT_USER_STATUS,
                        .user_status = { .user_id = cl->user_id, .status = 1 }};
    poc_evt_push(&srv->evt_queue, &evt);
}

static void srv_handle_heartbeat(poc_server_t *srv, srv_client_t *cl)
{
    (void)srv;
    cl->last_heartbeat = poc_mono_ms();
    uint8_t resp[2] = { cl->session_id, POC_NOTIFY_HEARTBEAT };
    srv_send_frame(cl, resp, 2);
}

static void srv_handle_enter_group(poc_server_t *srv, srv_client_t *cl, const uint8_t *data, int len)
{
    if (len < 10) return;
    uint32_t gid = poc_read32(data + 6);
    cl->active_group = gid;
    poc_log_at(POC_LOG_INFO, "srv: %s joined group %u", cl->account, gid);

    uint8_t notify[12];
    int off = 0;
    notify[off++] = 0; notify[off++] = POC_NOTIFY_ENTER_GROUP;
    poc_write32(notify + off, cl->user_id); off += 4;
    poc_write32(notify + off, gid); off += 4;
    srv_broadcast_group(srv, gid, notify, off, cl->fd);

    if (srv->cb.on_group_enter)
        srv->cb.on_group_enter(srv, cl->user_id, gid, srv->cb.userdata);
}

static void srv_handle_start_ptt(poc_server_t *srv, srv_client_t *cl, int cl_idx,
                                 const uint8_t *data, int len)
{
    /* Record codec type from PTT start (byte 6) */
    if (len > 6)
        cl->codec_type = data[6];

    /* Check for private call: poc_call_user sends exactly 13 bytes with
     * target user ID at bytes 9-12. Group PTT sends 9+name_len bytes
     * with the account name at bytes 9+. When len==13, disambiguate by
     * checking if the 4-byte value is a known registered user. */
    uint32_t target_uid = 0;
    if (len == 13) {
        uint32_t maybe_uid = poc_read32(data + 9);
        /* Only treat as private call if it's a registered user */
        for (int i = 0; i < srv->user_count; i++) {
            if (srv->users[i].user_id == maybe_uid) {
                target_uid = maybe_uid;
                break;
            }
        }
    }

    if (target_uid != 0 && target_uid != cl->user_id) {
        /* ── Private call ── */
        srv_client_t *target = srv_find_client(srv, target_uid);
        if (!target) {
            poc_log_at(POC_LOG_WARNING, "srv: %s private call to %u — user not online",
                       cl->account, target_uid);
            uint8_t resp[4] = { cl->session_id, POC_NOTIFY_RESPONSE, 0x25 };
            srv_send_frame(cl, resp, 3);
            return;
        }

        /* Grant private call */
        cl->private_call_target = target_uid;
        uint8_t resp[4] = { cl->session_id, POC_NOTIFY_RESPONSE, 0 };
        srv_send_frame(cl, resp, 3);

        poc_log_at(POC_LOG_INFO, "srv: %s → private call to %s (uid %u)",
                   cl->account, target->account, target_uid);

        /* Look up display name */
        srv_user_t *caller_user = NULL;
        for (int i = 0; i < srv->user_count; i++)
            if (srv->users[i].user_id == cl->user_id) { caller_user = &srv->users[i]; break; }
        const char *display = (caller_user && caller_user->name[0]) ? caller_user->name : cl->account;

        /* Notify target user only */
        uint8_t notify[128];
        int off = 0;
        notify[off++] = 0; notify[off++] = POC_NOTIFY_START_PTT_PRI;
        poc_write32(notify + off, cl->user_id); off += 4;
        notify[off++] = 0;
        int nlen = strlen(display) + 1;
        memcpy(notify + off, display, nlen); off += nlen;
        srv_send_frame(target, notify, off);
        return;
    }

    /* ── Group PTT ── */
    if (cl->active_group == 0) return;
    int gidx = srv_find_group_idx(srv, cl->active_group);
    if (gidx < 0) return;

    /* Floor check with priority-based pre-emption:
     *   - Floor free → grant
     *   - Floor held by self → grant (re-key)
     *   - Floor held by lower-priority user → pre-empt and grant
     *   - Floor held by equal/higher-priority user → deny */
    bool grant = true;
    int old_holder = srv->groups[gidx].floor_holder;

    if (old_holder >= 0 && old_holder != cl_idx) {
        srv_client_t *holder = &srv->clients[old_holder];
        if (cl->priority > holder->priority) {
            /* Pre-empt: force-end the current holder's PTT */
            poc_log_at(POC_LOG_INFO, "srv: %s (pri %u) pre-empting %s (pri %u) on group %u",
                       cl->account, cl->priority, holder->account, holder->priority,
                       cl->active_group);

            /* Send END_PTT to old holder */
            uint8_t end_notify[8];
            int eoff = 0;
            end_notify[eoff++] = 0;
            end_notify[eoff++] = POC_NOTIFY_END_PTT_PRI;
            poc_write32(end_notify + eoff, holder->user_id); eoff += 4;
            srv_send_frame(holder, end_notify, eoff);
            srv_broadcast_group(srv, cl->active_group, end_notify, eoff, holder->fd);

            if (srv->cb.on_ptt_preempted)
                srv->cb.on_ptt_preempted(srv, holder->user_id, cl->user_id,
                                         cl->active_group, srv->cb.userdata);
            if (srv->cb.on_ptt_end)
                srv->cb.on_ptt_end(srv, holder->user_id, cl->active_group, srv->cb.userdata);
        } else {
            grant = false;
        }
    }

    /* Ask application callback (can still deny even if priority allows) */
    if (grant && srv->cb.on_ptt_request)
        grant = srv->cb.on_ptt_request(srv, cl->user_id, cl->active_group, srv->cb.userdata);

    /* Respond */
    uint8_t resp[4] = { cl->session_id, POC_NOTIFY_RESPONSE, grant ? 0 : 0x25 };
    srv_send_frame(cl, resp, 3);

    if (grant) {
        srv->groups[gidx].floor_holder = cl_idx;
        cl->last_audio_time = poc_mono_ms();  /* start floor timeout clock */
        poc_log_at(POC_LOG_INFO, "srv: %s granted PTT on group %u", cl->account, cl->active_group);

        /* Look up display name */
        srv_user_t *caller_user = NULL;
        for (int i = 0; i < srv->user_count; i++)
            if (srv->users[i].user_id == cl->user_id) { caller_user = &srv->users[i]; break; }
        const char *display = (caller_user && caller_user->name[0]) ? caller_user->name : cl->account;

        uint8_t notify[128];
        int off = 0;
        notify[off++] = 0; notify[off++] = POC_NOTIFY_START_PTT_PRI;
        poc_write32(notify + off, cl->user_id); off += 4;
        notify[off++] = 0;
        int nlen = strlen(display) + 1;
        memcpy(notify + off, display, nlen); off += nlen;
        srv_broadcast_group(srv, cl->active_group, notify, off, cl->fd);
    } else {
        poc_log_at(POC_LOG_DEBUG, "srv: %s PTT denied on group %u (floor busy)", cl->account, cl->active_group);
    }
}

static void srv_handle_end_ptt(poc_server_t *srv, srv_client_t *cl, int cl_idx)
{
    /* Private call end */
    if (cl->private_call_target != 0) {
        uint32_t target_uid = cl->private_call_target;
        cl->private_call_target = 0;
        poc_log_at(POC_LOG_INFO, "srv: %s ended private call to %u", cl->account, target_uid);

        srv_client_t *target = srv_find_client(srv, target_uid);
        if (target) {
            uint8_t notify[8];
            int off = 0;
            notify[off++] = 0; notify[off++] = POC_NOTIFY_END_PTT_PRI;
            poc_write32(notify + off, cl->user_id); off += 4;
            srv_send_frame(target, notify, off);
        }
        if (srv->cb.on_ptt_end)
            srv->cb.on_ptt_end(srv, cl->user_id, 0, srv->cb.userdata);
        return;
    }

    /* Group PTT end */
    if (cl->active_group == 0) return;
    int gidx = srv_find_group_idx(srv, cl->active_group);
    if (gidx >= 0 && srv->groups[gidx].floor_holder == cl_idx) {
        srv->groups[gidx].floor_holder = -1;
        poc_log_at(POC_LOG_INFO, "srv: %s released PTT on group %u", cl->account, cl->active_group);
    }

    uint8_t notify[8];
    int off = 0;
    notify[off++] = 0; notify[off++] = POC_NOTIFY_END_PTT_PRI;
    poc_write32(notify + off, cl->user_id); off += 4;
    srv_broadcast_group(srv, cl->active_group, notify, off, cl->fd);

    if (srv->cb.on_ptt_end)
        srv->cb.on_ptt_end(srv, cl->user_id, cl->active_group, srv->cb.userdata);
}

static void srv_handle_ext_data(poc_server_t *srv, srv_client_t *cl, const uint8_t *data, int len)
{
    if (len < 7) return;

    /* SOS check */
    uint8_t marker = data[6];
    if (marker == POC_SOS_MARKER || marker == POC_SOS_CANCEL_MARKER) {
        int alert_type = (len > 7) ? data[7] : 0;
        uint8_t relay[10];
        int off = 0;
        relay[off++] = 0; relay[off++] = POC_NOTIFY_EXT_DATA;
        poc_write32(relay + off, cl->user_id); off += 4;
        relay[off++] = marker;
        relay[off++] = (uint8_t)alert_type;
        srv_broadcast_all(srv, relay, off, cl->fd);

        if (marker == POC_SOS_MARKER) {
            poc_log_at(POC_LOG_WARNING, "srv: *** SOS ALERT from %s (user %u) ***", cl->account, cl->user_id);
            if (srv->cb.on_sos)
                srv->cb.on_sos(srv, cl->user_id, alert_type, srv->cb.userdata);
        } else {
            poc_log_at(POC_LOG_INFO, "srv: SOS CANCELLED by %s (user %u)", cl->account, cl->user_id);
            if (srv->cb.on_sos)
                srv->cb.on_sos(srv, cl->user_id, -1, srv->cb.userdata);
        }
        return;
    }

    /* Regular message / receipts / typing — all have target_id at data[6..9] */
    if (len < 10) return;
    uint32_t target_id = poc_read32(data + 6);

    /* Check for receipt/typing markers at data[10] */
    if (len >= 11) {
        uint8_t m = data[10];
        if (m == 0xFD || m == 0xFC || m == 0xFB) {
            bool is_typing = (m == 0xFB && len >= 12) ? data[11] != 0 : false;
            poc_log_at(POC_LOG_DEBUG, "srv: %s → %u: %s%s",
                       cl->account, target_id,
                       m == 0xFB ? "typing" : m == 0xFD ? "read receipt" : "delivery receipt",
                       (m == 0xFB && !is_typing) ? " (stopped)" : "");

            srv_client_t *target = srv_find_client(srv, target_id);
            if (target) {
                uint8_t relay[10];
                int off = 0;
                relay[off++] = 0; relay[off++] = POC_NOTIFY_EXT_DATA;
                poc_write32(relay + off, cl->user_id); off += 4;
                relay[off++] = m;
                if (m == 0xFB) relay[off++] = is_typing ? 1 : 0;
                srv_send_frame(target, relay, off);
            }
            return;
        }
    }

    /* Regular text message */
    const char *text = (const char *)(data + 10);
    int text_len = len - 10;

    poc_log_at(POC_LOG_INFO, "srv: %s -> %u: %.*s", cl->account, target_id, text_len, text);

    uint8_t relay[512];
    int off = 0;
    relay[off++] = 0; relay[off++] = POC_NOTIFY_EXT_DATA;
    poc_write32(relay + off, cl->user_id); off += 4;
    int tlen = strnlen(text, text_len) + 1;
    if (tlen + off < (int)sizeof(relay)) { memcpy(relay + off, text, tlen); off += tlen; }

    int gidx = srv_find_group_idx(srv, target_id);
    if (gidx >= 0) {
        srv_broadcast_group(srv, target_id, relay, off, -1); /* include sender for echo */
    } else {
        srv_client_t *target = srv_find_client(srv, target_id);
        if (target) {
            srv_send_frame(target, relay, off);
            /* Send delivery ACK to sender */
            uint8_t ack[4] = { cl->session_id, POC_NOTIFY_PKG_ACK, 0x00 };
            srv_send_frame(cl, ack, 3);
            /* Also send 0xFC delivery receipt with target user ID */
            uint8_t drecp[8];
            int doff = 0;
            drecp[doff++] = 0; drecp[doff++] = POC_NOTIFY_EXT_DATA;
            poc_write32(drecp + doff, target_id); doff += 4;
            drecp[doff++] = 0xFC;
            srv_send_frame(cl, drecp, doff);
        } else {
            /* Target not online — notify sender */
            poc_log_at(POC_LOG_INFO, "srv: user %u offline — notifying %s", target_id, cl->account);
            uint8_t nack[4] = { cl->session_id, POC_NOTIFY_RESPONSE, 0x25 }; /* 0x25 = target unavailable */
            srv_send_frame(cl, nack, 3);
        }
    }

    if (srv->cb.on_message)
        srv->cb.on_message(srv, cl->user_id, target_id, text, srv->cb.userdata);
}

static void srv_handle_force_exit(poc_server_t *srv, srv_client_t *cl, const uint8_t *data, int len)
{
    int off = 6;
    while (off + 4 <= len) {
        uint32_t uid = poc_read32(data + off); off += 4;
        for (int i = 0; i < srv->client_count; i++) {
            if (srv->clients[i].user_id == uid && srv->clients[i].state == SRV_CLIENT_ONLINE) {
                poc_log_at(POC_LOG_WARNING, "srv: %s stunned user %u — forced offline", cl->account, uid);
                uint8_t msg[4] = { 0, POC_NOTIFY_FORCE_EXIT };
                srv_send_frame(&srv->clients[i], msg, 2);
                srv_disconnect(srv, i);
                break;
            }
        }
    }
}

static void srv_handle_pull(poc_server_t *srv, srv_client_t *cl, const uint8_t *data, int len)
{
    int off = 6;
    while (off + 4 <= len) {
        uint32_t uid = poc_read32(data + off); off += 4;
        srv_client_t *t = srv_find_client(srv, uid);
        if (t) {
            t->active_group = cl->active_group;
            uint8_t notify[8];
            int noff = 0;
            notify[noff++] = 0; notify[noff++] = POC_NOTIFY_PULL_TO_GROUP;
            poc_write32(notify + noff, cl->active_group); noff += 4;
            srv_send_frame(t, notify, noff);
            poc_log_at(POC_LOG_INFO, "srv: %s pulled user %u into group %u", cl->account, uid, cl->active_group);
        }
    }
}

/* ── Message dispatch ───────────────────────────────────────────── */

static void srv_dispatch(poc_server_t *srv, int cl_idx, const uint8_t *data, int len)
{
    if (len < 6) return;
    srv_client_t *cl = &srv->clients[cl_idx];
    uint8_t cmd = data[5]; /* client→server format: cmd at offset 5 */

    /* Don't spam heartbeat every 30s — everything else is interesting */
    if (cmd != POC_CMD_HEARTBEAT)
        poc_log_at(POC_LOG_DEBUG, "srv: %s: %s (%s)",
                   cl->account[0] ? cl->account : "?",
                   poc_cmd_name(cmd), srv_state_name(cl->state));

    switch (cmd) {
    case POC_CMD_LOGIN:       srv_handle_login(srv, cl, data, len); break;
    case POC_CMD_VALIDATE:    srv_handle_validate(srv, cl, data, len); break;
    case POC_CMD_HEARTBEAT:   srv_handle_heartbeat(srv, cl); break;
    case POC_CMD_ENTER_GROUP: srv_handle_enter_group(srv, cl, data, len); break;
    case POC_CMD_LEAVE_GROUP:
        if (srv->cb.on_group_leave)
            srv->cb.on_group_leave(srv, cl->user_id, cl->active_group, srv->cb.userdata);
        cl->active_group = 0;
        break;
    case POC_CMD_START_PTT:
    case POC_CMD_START_PTT_ALT:
        srv_handle_start_ptt(srv, cl, cl_idx, data, len); break;
    case POC_CMD_END_PTT:
    case POC_CMD_END_PTT_ALT:
        srv_handle_end_ptt(srv, cl, cl_idx); break;
    case POC_CMD_EXT_DATA:    srv_handle_ext_data(srv, cl, data, len); break;
    case POC_CMD_FORCE_EXIT:  srv_handle_force_exit(srv, cl, data, len); break;
    case POC_CMD_PULL_TO_GROUP: srv_handle_pull(srv, cl, data, len); break;
    case POC_CMD_MOD_STATUS:
        if (len >= 7) srv_status_broadcast(srv, cl->user_id, data[6], cl->fd);
        break;
    case POC_CMD_REGISTER_PUSH_TOKEN: {
        /* [6] token_len, [7] bid_len, [8..] token, [..] bundle_id */
        if (len < 8) break;
        int token_len = data[6];
        int bid_len   = data[7];
        if (token_len <= 0 || token_len > 64) break;
        if (bid_len   <= 0 || bid_len   > 127) break;
        if (8 + token_len + bid_len > len) break;
        const uint8_t *token = data + 8;
        const uint8_t *bundle_raw = data + 8 + token_len;

        poc_event_t evt = { .type = POC_EVT_PUSH_TOKEN };
        evt.push_token.user_id   = cl->user_id;
        evt.push_token.token_len = (uint8_t)token_len;
        memcpy(evt.push_token.token, token, (size_t)token_len);
        int copy_len = bid_len < (int)sizeof(evt.push_token.bundle_id) - 1
                       ? bid_len : (int)sizeof(evt.push_token.bundle_id) - 1;
        memcpy(evt.push_token.bundle_id, bundle_raw, (size_t)copy_len);
        evt.push_token.bundle_id[copy_len] = '\0';
        poc_evt_push(&srv->evt_queue, &evt);

        poc_log_at(POC_LOG_INFO,
                   "srv: %s (uid %u) registered APNs push token (%d bytes, bundle=%s)",
                   cl->account, cl->user_id, token_len, evt.push_token.bundle_id);
        break;
    }

    /* Temp groups */
    case POC_CMD_INVITE_TMP:
        if (len >= 10) {
            poc_log_at(POC_LOG_INFO, "srv: %s inviting users to temp group", cl->account);
            int off = 6;
            while (off + 4 <= len) {
                uint32_t uid = poc_read32(data + off); off += 4;
                srv_client_t *t = srv_find_client(srv, uid);
                if (t) {
                    uint8_t notify[12];
                    int noff = 0;
                    notify[noff++] = 0; notify[noff++] = POC_NOTIFY_INVITE_TMP;
                    poc_write32(notify + noff, cl->active_group); noff += 4;
                    poc_write32(notify + noff, cl->user_id); noff += 4;
                    srv_send_frame(t, notify, noff);
                }
            }
        }
        break;
    case POC_CMD_ENTER_TMP:
        if (len >= 10) {
            uint32_t gid = poc_read32(data + 6);
            cl->active_group = gid;
            poc_log_at(POC_LOG_INFO, "srv: %s joined temp group %u", cl->account, gid);
        }
        break;
    case POC_CMD_REJECT_TMP:
        poc_log_at(POC_LOG_INFO, "srv: %s rejected temp group invite", cl->account);
        break;

    /* Voice messages */
    case POC_CMD_NOTE_INCOME:
    case POC_CMD_VOICE_INCOME:
    case POC_CMD_VOICE_MESSAGE:
        poc_log_at(POC_LOG_INFO, "srv: %s sent %s (%d bytes)", cl->account, poc_cmd_name(cmd), len);
        break;

    default:
        poc_log_at(POC_LOG_DEBUG, "srv: %s: unhandled command %s (0x%02x)", cl->account, poc_cmd_name(cmd), cmd);
        break;
    }
}

/* ── TCP deframe ────────────────────────────────────────────────── */

static int srv_tcp_recv(poc_server_t *srv, int cl_idx)
{
    srv_client_t *cl = &srv->clients[cl_idx];
    int space = SRV_RECV_BUF - cl->recv_len;
    if (space <= 0) { cl->recv_len = 0; return -1; }

    int n;
    if (cl->ssl) {
        n = SSL_read(cl->ssl, cl->recv_buf + cl->recv_len, space);
        if (n <= 0) {
            int err = SSL_get_error(cl->ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
            return -1;
        }
    } else {
        n = recv(cl->fd, cl->recv_buf + cl->recv_len, space, 0);
        if (n <= 0) return -1;
    }
    cl->recv_len += n;

    uint8_t *buf = cl->recv_buf;
    int remaining = cl->recv_len;
    while (remaining >= POC_MS_HDR_LEN + 1) {
        if (buf[0] != POC_MS_MAGIC_0 || buf[1] != POC_MS_MAGIC_1) { remaining = 0; break; }
        uint16_t plen = poc_read16(buf + 2);
        int ftotal = POC_MS_HDR_LEN + plen;
        if (remaining < ftotal) break;
        srv_dispatch(srv, cl_idx, buf + POC_MS_HDR_LEN, plen);
        buf += ftotal; remaining -= ftotal;
    }
    if (remaining > 0 && buf != cl->recv_buf) memmove(cl->recv_buf, buf, remaining);
    cl->recv_len = remaining;
    return 0;
}

/* ── UDP relay ──────────────────────────────────────────────────── */

static void srv_handle_udp(poc_server_t *srv)
{
    /* Drain every datagram available — a single epoll wakeup can have
     * accumulated many UDP packets, and recvfrom only returns one at
     * a time. Stopping after one packet (the previous behaviour) lost
     * audio when bursts arrived faster than the I/O thread looped. */
    uint8_t pkt[1500];
    struct sockaddr_in from;
    socklen_t flen;

    /* Per-event diagnostic counters. Logged at first 3 packets and
     * every 50th to confirm whether iOS is actually streaming and how
     * many of its packets the Opus decoder accepts. */
    static uint32_t recv_count = 0;
    static uint32_t no_sender = 0;
    static uint32_t no_group = 0;
    static uint32_t decode_ok = 0;
    static uint32_t decode_fail = 0;
    static uint32_t evt_full = 0;

    for (;;) {
        flen = sizeof(from);
        int n = recvfrom(srv->udp_fd, pkt, sizeof(pkt), 0,
                         (struct sockaddr *)&from, &flen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;  /* fully drained */
            poc_log_at(POC_LOG_WARNING, "srv: udp recv error: %s", strerror(errno));
            return;
        }
        if (n < POC_UDP_HDR_LEN) continue;

        recv_count++;
        uint32_t sender_id = poc_read32(pkt + 2);
        srv_client_t *sender = NULL;
        for (int i = 0; i < srv->client_count; i++) {
            if (srv->clients[i].user_id == sender_id &&
                srv->clients[i].state == SRV_CLIENT_ONLINE) {
                sender = &srv->clients[i];
                sender->udp_addr = from;
                sender->has_udp_addr = true;
                sender->last_audio_time = poc_mono_ms();
                break;
            }
        }
        if (!sender) {
            no_sender++;
            continue;
        }

        /* Private call: route only to the target user. */
        if (sender->private_call_target != 0) {
            for (int i = 0; i < srv->client_count; i++) {
                srv_client_t *c = &srv->clients[i];
                if (c->user_id == sender->private_call_target && c->has_udp_addr) {
                    sendto(srv->udp_fd, pkt, n, 0,
                           (struct sockaddr *)&c->udp_addr, sizeof(c->udp_addr));
                    break;
                }
            }
            continue;  /* no on_audio for private calls */
        }

        if (!sender->active_group) {
            no_group++;
            continue;
        }

        /* Relay the raw packet to other clients in the group. */
        for (int i = 0; i < srv->client_count; i++) {
            srv_client_t *c = &srv->clients[i];
            if (c == sender || c->state != SRV_CLIENT_ONLINE) continue;
            if (c->active_group != sender->active_group) continue;
            if (!c->has_udp_addr) continue;
            sendto(srv->udp_fd, pkt, n, 0,
                   (struct sockaddr *)&c->udp_addr, sizeof(c->udp_addr));
        }

        /* Decode for the on_audio callback (mod_poc bridges to RF). */
        if (srv->cb.on_audio && n > POC_UDP_HDR_LEN) {
            const uint8_t *encoded = pkt + POC_UDP_HDR_LEN;
            int enc_len = n - POC_UDP_HDR_LEN;
            int16_t pcm[POC_CODEC_MAX_FRAME_SAMPLES];
            int decoded = poc_codec_decode(srv->codec, encoded, enc_len,
                                           pcm, POC_CODEC_MAX_FRAME_SAMPLES);
            if (decoded > 0) {
                decode_ok++;
                poc_event_t evt = { .type = POC_EVT_AUDIO };
                evt.audio.speaker_id = sender_id;
                evt.audio.group_id   = sender->active_group;
                evt.audio.n_samples  = decoded;
                memcpy(evt.audio.pcm, pcm, (size_t)decoded * sizeof(int16_t));
                if (!poc_evt_push(&srv->evt_queue, &evt))
                    evt_full++;
            } else {
                decode_fail++;
            }
        }

        if (recv_count <= 3 || (recv_count % 50) == 0) {
            poc_log_at(POC_LOG_INFO,
                       "srv: udp pkt #%u from uid=%u len=%d "
                       "(decode ok=%u fail=%u, drops: no_sender=%u no_group=%u evt_full=%u)",
                       recv_count, sender_id, n,
                       decode_ok, decode_fail,
                       no_sender, no_group, evt_full);
        }
    }
}

/* ── I/O thread ─────────────────────────────────────────────────── */

static void *srv_io_thread(void *arg)
{
    poc_server_t *srv = (poc_server_t *)arg;
    poc_log_at(POC_LOG_INFO, "srv: I/O thread started");

    while (atomic_load(&srv->io_running)) {
        struct epoll_event events[SRV_EPOLL_BATCH];
        int n = epoll_wait(srv->epoll_fd, events, SRV_EPOLL_BATCH, 100);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (!atomic_load(&srv->io_running)) break;

        for (int e = 0; e < n; e++) {
            int fd = events[e].data.fd;
            uint32_t ev = events[e].events;

            /* Drain wakeup */
            if (fd == srv->wakeup[0]) {
                char tmp[64]; while (read(srv->wakeup[0], tmp, sizeof(tmp)) > 0);
                continue;
            }

            /* UDP audio */
            if (fd == srv->udp_fd) {
                srv_handle_udp(srv);
                continue;
            }

            /* Accept new client */
            if (fd == srv->listen_fd) {
                struct sockaddr_in ca;
                socklen_t cl = sizeof(ca);
                int cfd = accept(srv->listen_fd, (struct sockaddr *)&ca, &cl);
                if (cfd < 0) continue;

                /* Enforce soft limit if set */
                if (srv->max_clients > 0 && srv->client_count >= srv->max_clients) {
                    close(cfd);
                    continue;
                }

                int fl = fcntl(cfd, F_GETFL, 0);
                fcntl(cfd, F_SETFL, fl | O_NONBLOCK);

                /* TLS handshake if enabled */
                SSL *client_ssl = NULL;
                if (srv->tls_enabled && srv->ssl_ctx) {
                    client_ssl = SSL_new(srv->ssl_ctx);
                    SSL_set_fd(client_ssl, cfd);
                    int tls_ok = 0;
                    int last_err = 0, last_ret = 0;
                    /* ~5 s budget: 20 attempts × 250 ms poll */
                    for (int att = 0; att < 20; att++) {
                        int ret = SSL_accept(client_ssl);
                        if (ret == 1) { tls_ok = 1; break; }
                        int err = SSL_get_error(client_ssl, ret);
                        last_err = err; last_ret = ret;
                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                            struct pollfd tp = { .fd = cfd,
                                .events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN };
                            poll(&tp, 1, 250);
                            continue;
                        }
                        break;
                    }
                    if (!tls_ok) {
                        unsigned long e = ERR_peek_last_error();
                        char ebuf[256] = "";
                        if (e) ERR_error_string_n(e, ebuf, sizeof(ebuf));
                        poc_log_at(POC_LOG_WARNING,
                                   "srv: TLS handshake failed from %s "
                                   "(SSL_accept ret=%d err=%d errno=%d: %s)",
                                   inet_ntoa(ca.sin_addr),
                                   last_ret, last_err, errno,
                                   ebuf[0] ? ebuf : "no openssl error");
                        ERR_clear_error();
                        SSL_free(client_ssl);
                        close(cfd);
                        continue;
                    }
                }

                /* Grow clients array if needed */
                if (srv->client_count >= srv->client_cap) {
                    if (srv_grow((void **)&srv->clients, &srv->client_cap,
                                 sizeof(srv_client_t), SRV_DEFAULT_CLIENTS) < 0) {
                        poc_log_at(POC_LOG_ERROR, "srv: failed to grow clients array");
                        if (client_ssl) SSL_free(client_ssl);
                        close(cfd);
                        continue;
                    }
                }

                srv_client_t *c = &srv->clients[srv->client_count++];
                memset(c, 0, sizeof(*c));
                c->fd = cfd;
                c->ssl = client_ssl;
                c->state = SRV_CLIENT_NEW;

                /* Register with epoll */
                struct epoll_event cev = { .events = EPOLLIN, .data.fd = cfd };
                epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, cfd, &cev);

                poc_log_at(POC_LOG_INFO, "srv: new client connected from %s%s",
                           inet_ntoa(ca.sin_addr), client_ssl ? " (TLS)" : "");
                continue;
            }

            /* Client TCP — find client by fd */
            for (int i = 0; i < srv->client_count; i++) {
                if (srv->clients[i].fd != fd) continue;
                if (ev & (EPOLLERR | EPOLLHUP)) {
                    srv_disconnect(srv, i);
                } else if (ev & EPOLLIN) {
                    if (srv_tcp_recv(srv, i) < 0)
                        srv_disconnect(srv, i);
                }
                break;
            }
        }

        /* Stale client heartbeat timeout + PTT floor timeout */
        uint64_t now = poc_mono_ms();
        for (int i = 0; i < srv->client_count; i++) {
            srv_client_t *cl = &srv->clients[i];
            if (cl->state != SRV_CLIENT_ONLINE) continue;
            if (cl->last_heartbeat > 0 &&
                now - cl->last_heartbeat > SRV_HEARTBEAT_TIMEOUT_MS) {
                poc_log_at(POC_LOG_WARNING, "srv: %s (user %u) heartbeat timeout — disconnecting",
                           cl->account, cl->user_id);
                srv_disconnect(srv, i);
                i--;
                continue;
            }
        }
        /* Release floors held too long without audio */
        for (int g = 0; g < srv->group_count; g++) {
            int holder = srv->groups[g].floor_holder;
            if (holder < 0 || holder >= srv->client_count) continue;
            srv_client_t *cl = &srv->clients[holder];
            if (cl->last_audio_time > 0 &&
                now - cl->last_audio_time > SRV_PTT_FLOOR_TIMEOUT_MS) {
                poc_log_at(POC_LOG_WARNING, "srv: floor timeout on group %u — releasing %s",
                           srv->groups[g].id, cl->account);
                srv->groups[g].floor_holder = -1;
                /* Notify group */
                uint8_t notify[8] = {0};
                notify[1] = POC_NOTIFY_END_PTT_PRI;
                poc_write32(notify + 2, cl->user_id);
                srv_broadcast_group(srv, srv->groups[g].id, notify, 6, -1);
            }
        }
    }

    poc_log_at(POC_LOG_INFO, "srv: I/O thread exiting");
    return NULL;
}

/* ── Public API ─────────────────────────────────────────────────── */

poc_server_t *poc_server_create(const poc_server_config_t *cfg,
                                const poc_server_callbacks_t *cb)
{
    poc_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) return NULL;

    snprintf(srv->bind_addr, sizeof(srv->bind_addr), "%s",
             (cfg && cfg->bind_addr && cfg->bind_addr[0]) ? cfg->bind_addr : "0.0.0.0");
    srv->port = (cfg && cfg->port) ? cfg->port : 29999;
    srv->max_clients = (cfg && cfg->max_clients > 0) ? cfg->max_clients : 0; /* 0 = unlimited */

    srv->listen_fd = -1;
    srv->udp_fd = -1;
    srv->epoll_fd = -1;
    srv->wakeup[0] = srv->wakeup[1] = -1;
    atomic_store(&srv->io_running, false);
    poc_evt_init(&srv->evt_queue);

    /* Allocate initial dynamic arrays */
    srv->clients = calloc(SRV_DEFAULT_CLIENTS, sizeof(srv_client_t));
    srv->client_cap = srv->clients ? SRV_DEFAULT_CLIENTS : 0;
    srv->users = calloc(SRV_DEFAULT_USERS, sizeof(srv_user_t));
    srv->user_cap = srv->users ? SRV_DEFAULT_USERS : 0;
    srv->groups = calloc(SRV_DEFAULT_GROUPS, sizeof(srv_group_t));
    srv->group_cap = srv->groups ? SRV_DEFAULT_GROUPS : 0;

    if (!srv->clients || !srv->users || !srv->groups) {
        free(srv->clients); free(srv->users); free(srv->groups);
        free(srv);
        return NULL;
    }

    for (int i = 0; i < srv->group_cap; i++) srv->groups[i].floor_holder = -1;

    /* TLS config */
    srv->tls_enabled = (cfg && cfg->tls);
    if (cfg && cfg->tls_cert_path)
        snprintf(srv->tls_cert_path, sizeof(srv->tls_cert_path), "%s", cfg->tls_cert_path);
    if (cfg && cfg->tls_key_path)
        snprintf(srv->tls_key_path, sizeof(srv->tls_key_path), "%s", cfg->tls_key_path);

    /* Audio codec — Opus SWB, hardcoded (only supported codec) */
    srv->codec = poc_codec_create();
    if (!srv->codec) { free(srv); return NULL; }

    if (cb) srv->cb = *cb;
    return srv;
}

void poc_server_destroy(poc_server_t *srv)
{
    if (!srv) return;
    poc_server_stop(srv);
    poc_codec_destroy(srv->codec);
    if (srv->ssl_ctx) { SSL_CTX_free(srv->ssl_ctx); srv->ssl_ctx = NULL; }
    /* Free group member arrays */
    for (int i = 0; i < srv->group_count; i++)
        free(srv->groups[i].members);
    free(srv->clients);
    free(srv->users);
    free(srv->groups);
    if (srv->epoll_fd >= 0) close(srv->epoll_fd);
    free(srv);
}

int poc_server_add_user(poc_server_t *srv, const poc_server_user_t *user)
{
    if (!srv || !user) return POC_ERR;
    if (srv->user_count >= srv->user_cap) {
        if (srv_grow((void **)&srv->users, &srv->user_cap,
                     sizeof(srv_user_t), SRV_DEFAULT_USERS) < 0)
            return POC_ERR_NOMEM;
    }
    srv_user_t *u = &srv->users[srv->user_count++];
    snprintf(u->account, sizeof(u->account), "%s", user->account);
    snprintf(u->name, sizeof(u->name), "%s", user->name ? user->name : user->account);
    srv_sha1_hex(user->password, u->password_sha1);
    u->user_id = user->user_id;
    u->priority = user->priority;
    return POC_OK;
}

int poc_server_add_group(poc_server_t *srv, const poc_server_group_t *group)
{
    if (!srv || !group) return POC_ERR;
    if (srv->group_count >= srv->group_cap) {
        int old_cap = srv->group_cap;
        if (srv_grow((void **)&srv->groups, &srv->group_cap,
                     sizeof(srv_group_t), SRV_DEFAULT_GROUPS) < 0)
            return POC_ERR_NOMEM;
        /* Init floor_holder for new slots */
        for (int i = old_cap; i < srv->group_cap; i++)
            srv->groups[i].floor_holder = -1;
    }
    srv_group_t *g = &srv->groups[srv->group_count++];
    g->id = group->id;
    snprintf(g->name, sizeof(g->name), "%s", group->name);
    g->floor_holder = -1;
    g->members = NULL;
    g->member_count = 0;
    g->member_cap = 0;
    if (group->member_ids && group->member_count > 0) {
        g->members = malloc(group->member_count * sizeof(uint32_t));
        if (g->members) {
            memcpy(g->members, group->member_ids, group->member_count * sizeof(uint32_t));
            g->member_count = group->member_count;
            g->member_cap = group->member_count;
        }
    }
    return POC_OK;
}

int poc_server_remove_user(poc_server_t *srv, uint32_t user_id)
{
    if (!srv) return POC_ERR;
    for (int i = 0; i < srv->user_count; i++) {
        if (srv->users[i].user_id == user_id) {
            srv->users[i] = srv->users[--srv->user_count];
            return POC_OK;
        }
    }
    return POC_ERR;
}

int poc_server_remove_group(poc_server_t *srv, uint32_t group_id)
{
    if (!srv) return POC_ERR;
    for (int i = 0; i < srv->group_count; i++) {
        if (srv->groups[i].id == group_id) {
            free(srv->groups[i].members);
            srv->groups[i] = srv->groups[--srv->group_count];
            return POC_OK;
        }
    }
    return POC_ERR;
}

int poc_server_start(poc_server_t *srv)
{
    if (!srv) return POC_ERR;

    /* TLS context */
    if (srv->tls_enabled) {
        srv->ssl_ctx = SSL_CTX_new(TLS_server_method());
        if (!srv->ssl_ctx) {
            poc_log_at(POC_LOG_ERROR, "srv: failed to create TLS context");
            return POC_ERR;
        }
        SSL_CTX_set_min_proto_version(srv->ssl_ctx, TLS1_2_VERSION);
        if (SSL_CTX_use_certificate_chain_file(srv->ssl_ctx, srv->tls_cert_path) != 1) {
            unsigned long e = ERR_get_error();
            poc_log_at(POC_LOG_ERROR, "srv: failed to load TLS cert chain: %s (%s)",
                       srv->tls_cert_path, ERR_error_string(e, NULL));
            SSL_CTX_free(srv->ssl_ctx); srv->ssl_ctx = NULL;
            return POC_ERR;
        }
        if (SSL_CTX_use_PrivateKey_file(srv->ssl_ctx, srv->tls_key_path, SSL_FILETYPE_PEM) != 1) {
            unsigned long e = ERR_get_error();
            poc_log_at(POC_LOG_ERROR, "srv: failed to load TLS key: %s (%s)",
                       srv->tls_key_path, ERR_error_string(e, NULL));
            SSL_CTX_free(srv->ssl_ctx); srv->ssl_ctx = NULL;
            return POC_ERR;
        }
        if (SSL_CTX_check_private_key(srv->ssl_ctx) != 1) {
            unsigned long e = ERR_get_error();
            poc_log_at(POC_LOG_ERROR, "srv: TLS cert/key mismatch (%s)",
                       ERR_error_string(e, NULL));
            SSL_CTX_free(srv->ssl_ctx); srv->ssl_ctx = NULL;
            return POC_ERR;
        }
        poc_log_at(POC_LOG_INFO, "srv: TLS enabled (cert=%s)", srv->tls_cert_path);
    }

    /* TCP listener */
    srv->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(srv->port) };
    inet_pton(AF_INET, srv->bind_addr, &addr.sin_addr);
    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        poc_log_at(POC_LOG_ERROR, "srv: bind failed: %s", strerror(errno));
        close(srv->listen_fd); srv->listen_fd = -1;
        return POC_ERR_NETWORK;
    }
    listen(srv->listen_fd, 16);
    int fl = fcntl(srv->listen_fd, F_GETFL, 0);
    fcntl(srv->listen_fd, F_SETFL, fl | O_NONBLOCK);

    /* UDP */
    srv->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (bind(srv->udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        poc_log_at(POC_LOG_ERROR, "srv: udp bind failed: %s", strerror(errno));
        close(srv->listen_fd); srv->listen_fd = -1;
        close(srv->udp_fd); srv->udp_fd = -1;
        return POC_ERR_NETWORK;
    }
    fl = fcntl(srv->udp_fd, F_GETFL, 0);
    fcntl(srv->udp_fd, F_SETFL, fl | O_NONBLOCK);

    /* Wakeup pipe */
    if (pipe(srv->wakeup) < 0) {
        poc_log_at(POC_LOG_ERROR, "srv: pipe() failed: %s", strerror(errno));
        close(srv->listen_fd); srv->listen_fd = -1;
        close(srv->udp_fd); srv->udp_fd = -1;
        return POC_ERR;
    }
    fl = fcntl(srv->wakeup[0], F_GETFL, 0); fcntl(srv->wakeup[0], F_SETFL, fl | O_NONBLOCK);

    /* Create epoll and register initial fds */
    srv->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (srv->epoll_fd < 0) {
        poc_log_at(POC_LOG_ERROR, "srv: epoll_create1 failed: %s", strerror(errno));
        return POC_ERR;
    }
    struct epoll_event ev;
    ev.events = EPOLLIN; ev.data.fd = srv->wakeup[0];
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, srv->wakeup[0], &ev);
    ev.data.fd = srv->listen_fd;
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, srv->listen_fd, &ev);
    ev.data.fd = srv->udp_fd;
    epoll_ctl(srv->epoll_fd, EPOLL_CTL_ADD, srv->udp_fd, &ev);

    /* Start I/O thread */
    atomic_store(&srv->io_running, true);
    if (pthread_create(&srv->io_thread, NULL, srv_io_thread, srv) != 0) {
        atomic_store(&srv->io_running, false);
        return POC_ERR;
    }

    poc_log_at(POC_LOG_INFO, "srv: listening on %s:%d%s", srv->bind_addr, srv->port,
               srv->tls_enabled ? " (TLS)" : "");
    return POC_OK;
}

int poc_server_stop(poc_server_t *srv)
{
    if (!srv) return POC_ERR;
    if (atomic_load(&srv->io_running)) {
        atomic_store(&srv->io_running, false);
        char c = 1; if (srv->wakeup[1] >= 0) { if (write(srv->wakeup[1], &c, 1) < 0) {;} }
        pthread_join(srv->io_thread, NULL);
    }
    for (int i = 0; i < srv->client_count; i++) close(srv->clients[i].fd);
    srv->client_count = 0;
    if (srv->listen_fd >= 0) { close(srv->listen_fd); srv->listen_fd = -1; }
    if (srv->udp_fd >= 0) { close(srv->udp_fd); srv->udp_fd = -1; }
    if (srv->wakeup[0] >= 0) { close(srv->wakeup[0]); srv->wakeup[0] = -1; }
    if (srv->wakeup[1] >= 0) { close(srv->wakeup[1]); srv->wakeup[1] = -1; }
    if (srv->epoll_fd >= 0) { close(srv->epoll_fd); srv->epoll_fd = -1; }
    return POC_OK;
}

int poc_server_poll(poc_server_t *srv, int timeout_ms)
{
    (void)timeout_ms;
    if (!srv) return POC_ERR;

    poc_event_t evt;
    while (poc_evt_pop(&srv->evt_queue, &evt)) {
        switch (evt.type) {
        case POC_EVT_USER_STATUS:
            if (evt.user_status.status == 1 && srv->cb.on_client_connect) {
                /* Find account name for this user_id */
                const char *acct = "";
                for (int i = 0; i < srv->user_count; i++)
                    if (srv->users[i].user_id == evt.user_status.user_id)
                        { acct = srv->users[i].account; break; }
                srv->cb.on_client_connect(srv, evt.user_status.user_id, acct, srv->cb.userdata);
            } else if (evt.user_status.status <= 0 && srv->cb.on_client_disconnect) {
                const char *acct = "";
                for (int i = 0; i < srv->user_count; i++)
                    if (srv->users[i].user_id == evt.user_status.user_id)
                        { acct = srv->users[i].account; break; }
                srv->cb.on_client_disconnect(srv, evt.user_status.user_id, acct, srv->cb.userdata);
            }
            break;
        case POC_EVT_AUDIO:
            if (srv->cb.on_audio)
                srv->cb.on_audio(srv, evt.audio.speaker_id, evt.audio.group_id,
                                 evt.audio.pcm, evt.audio.n_samples, srv->cb.userdata);
            break;
        case POC_EVT_PUSH_TOKEN:
            if (srv->cb.on_push_token)
                srv->cb.on_push_token(srv, evt.push_token.user_id,
                                      evt.push_token.token,
                                      evt.push_token.token_len,
                                      evt.push_token.bundle_id,
                                      srv->cb.userdata);
            break;
        default:
            break;
        }
    }
    return POC_OK;
}

/* ── Audio injection + virtual PTT ─────────────────────────────── */

int poc_server_inject_audio(poc_server_t *srv, uint32_t group_id,
                            uint32_t virtual_user_id,
                            const int16_t *pcm, int n_samples)
{
    if (!srv || !pcm || n_samples <= 0) return POC_ERR;

    /* Encode PCM → codec */
    uint8_t encoded[POC_CODEC_MAX_ENCODED_SIZE];
    int enc_len = poc_codec_encode(srv->codec, pcm, n_samples,
                                   encoded, sizeof(encoded));
    if (enc_len <= 0) return POC_ERR;

    /* Build UDP packet: [seq(2)][sender(4)][pad(1)][type(1)][payload] */
    uint8_t pkt[POC_UDP_HDR_LEN + POC_CODEC_MAX_ENCODED_SIZE];
    poc_write16(pkt, srv->inject_seq++);
    poc_write32(pkt + 2, virtual_user_id);
    pkt[6] = 0;     /* pad */
    pkt[7] = 0x80;  /* content type: audio */
    memcpy(pkt + POC_UDP_HDR_LEN, encoded, enc_len);
    int pkt_len = POC_UDP_HDR_LEN + enc_len;

    /* Send to all clients in the group */
    int eligible = 0, sent = 0, no_udp = 0, wrong_group = 0, offline = 0;
    int send_errs = 0;
    /* Capture the first eligible client's address for the periodic log. */
    char first_dest[64] = "";
    int  first_port = 0;
    for (int i = 0; i < srv->client_count; i++) {
        srv_client_t *c = &srv->clients[i];
        if (c->state != SRV_CLIENT_ONLINE) { offline++; continue; }
        if (c->active_group != group_id)   { wrong_group++; continue; }
        eligible++;
        if (!c->has_udp_addr)              { no_udp++; continue; }
        if (!first_dest[0]) {
            inet_ntop(AF_INET, &c->udp_addr.sin_addr, first_dest, sizeof(first_dest));
            first_port = ntohs(c->udp_addr.sin_port);
        }
        ssize_t rc = sendto(srv->udp_fd, pkt, pkt_len, 0,
                            (struct sockaddr *)&c->udp_addr, sizeof(c->udp_addr));
        if (rc < 0) send_errs++;
        else sent++;
    }
    static int inject_count = 0;
    inject_count++;
    if (inject_count <= 3 || (inject_count % 50) == 0) {
        poc_log_at(POC_LOG_INFO,
                   "srv: inject_audio #%d gid=%u clients=%d eligible=%d sent=%d "
                   "no_udp=%d wrong_group=%d offline=%d send_errs=%d "
                   "enc_len=%d first_dest=%s:%d",
                   inject_count, group_id, srv->client_count,
                   eligible, sent, no_udp, wrong_group, offline, send_errs,
                   enc_len,
                   first_dest[0] ? first_dest : "-", first_port);
    }
    if (send_errs > 0) {
        poc_log_at(POC_LOG_WARNING,
                   "srv: inject_audio #%d sendto errors=%d errno=%d (%s)",
                   inject_count, send_errs, errno, strerror(errno));
    }
    return POC_OK;
}

int poc_server_start_ptt_for(poc_server_t *srv, uint32_t group_id,
                             uint32_t virtual_user_id, const char *name)
{
    if (!srv) return POC_ERR;
    uint8_t notify[64];
    int off = 0;
    notify[off++] = 0;
    notify[off++] = POC_NOTIFY_START_PTT_PRI;
    poc_write32(notify + off, virtual_user_id); off += 4;
    notify[off++] = 0; /* flags */
    if (name) {
        int nlen = strlen(name) + 1;
        if (nlen + off < (int)sizeof(notify)) {
            memcpy(notify + off, name, nlen);
            off += nlen;
        }
    }
    srv_broadcast_group(srv, group_id, notify, off, -1);

    /* Snapshot each in-group client's cached UDP address — this is
     * where audio will be sent to during the upcoming TX. If the
     * cached address is stale or missing, RX silently goes nowhere. */
    for (int i = 0; i < srv->client_count; i++) {
        srv_client_t *c = &srv->clients[i];
        if (c->state != SRV_CLIENT_ONLINE) continue;
        if (c->active_group != group_id) continue;
        if (c->has_udp_addr) {
            char addr[64];
            inet_ntop(AF_INET, &c->udp_addr.sin_addr, addr, sizeof(addr));
            uint64_t age_ms = poc_mono_ms() - c->last_audio_time;
            poc_log_at(POC_LOG_INFO,
                       "srv: ptt_start_for(gid=%u): client uid=%u udp=%s:%d "
                       "(last_inbound %llu ms ago)",
                       group_id, c->user_id, addr, ntohs(c->udp_addr.sin_port),
                       (unsigned long long)age_ms);
        } else {
            poc_log_at(POC_LOG_WARNING,
                       "srv: ptt_start_for(gid=%u): client uid=%u has NO udp_addr "
                       "— RX will not reach this client",
                       group_id, c->user_id);
        }
    }
    return POC_OK;
}

int poc_server_end_ptt_for(poc_server_t *srv, uint32_t group_id,
                           uint32_t virtual_user_id)
{
    if (!srv) return POC_ERR;
    uint8_t notify[8];
    int off = 0;
    notify[off++] = 0;
    notify[off++] = POC_NOTIFY_END_PTT_PRI;
    poc_write32(notify + off, virtual_user_id); off += 4;
    srv_broadcast_group(srv, group_id, notify, off, -1);
    return POC_OK;
}

/* ── Server-initiated actions ───────────────────────────────────── */

int poc_server_send_message(poc_server_t *srv, uint32_t from_id,
                            uint32_t target_id, const char *text)
{
    if (!srv || !text) return POC_ERR;
    uint8_t relay[512];
    int off = 0;
    relay[off++] = 0; relay[off++] = POC_NOTIFY_EXT_DATA;
    poc_write32(relay + off, from_id); off += 4;
    int tlen = strlen(text) + 1;
    if (tlen + off < (int)sizeof(relay)) { memcpy(relay + off, text, tlen); off += tlen; }

    int gidx = srv_find_group_idx(srv, target_id);
    if (gidx >= 0) { srv_broadcast_group(srv, target_id, relay, off, -1); return POC_OK; }
    srv_client_t *t = srv_find_client(srv, target_id);
    if (t) { srv_send_frame(t, relay, off); return POC_OK; }
    return POC_ERR;
}

int poc_server_broadcast(poc_server_t *srv, const char *text)
{
    if (!srv || !text) return POC_ERR;
    uint8_t relay[512];
    int off = 0;
    relay[off++] = 0; relay[off++] = POC_NOTIFY_EXT_DATA;
    poc_write32(relay + off, 0); off += 4;  /* from_id = 0 (server) */
    int tlen = strlen(text) + 1;
    if (tlen + off < (int)sizeof(relay)) { memcpy(relay + off, text, tlen); off += tlen; }
    srv_broadcast_all(srv, relay, off, -1);
    return POC_OK;
}

int poc_server_kick(poc_server_t *srv, uint32_t user_id)
{
    if (!srv) return POC_ERR;
    for (int i = 0; i < srv->client_count; i++) {
        if (srv->clients[i].user_id == user_id && srv->clients[i].state == SRV_CLIENT_ONLINE) {
            uint8_t msg[4] = { 0, POC_NOTIFY_FORCE_EXIT };
            srv_send_frame(&srv->clients[i], msg, 2);
            srv_disconnect(srv, i);
            return POC_OK;
        }
    }
    return POC_ERR;
}

int poc_server_pull_to_group(poc_server_t *srv, uint32_t user_id, uint32_t group_id)
{
    if (!srv) return POC_ERR;
    srv_client_t *t = srv_find_client(srv, user_id);
    if (!t) return POC_ERR;
    t->active_group = group_id;
    uint8_t notify[8];
    int off = 0;
    notify[off++] = 0; notify[off++] = POC_NOTIFY_PULL_TO_GROUP;
    poc_write32(notify + off, group_id); off += 4;
    srv_send_frame(t, notify, off);
    return POC_OK;
}

int poc_server_send_sos(poc_server_t *srv, uint32_t user_id, int alert_type)
{
    if (!srv) return POC_ERR;
    uint8_t relay[10];
    int off = 0;
    relay[off++] = 0; relay[off++] = POC_NOTIFY_EXT_DATA;
    poc_write32(relay + off, user_id); off += 4;
    relay[off++] = POC_SOS_MARKER;
    relay[off++] = (uint8_t)alert_type;
    srv_broadcast_all(srv, relay, off, -1);
    return POC_OK;
}

int poc_server_client_count(const poc_server_t *srv)
{
    if (!srv) return 0;
    int n = 0;
    for (int i = 0; i < srv->client_count; i++)
        if (srv->clients[i].state == SRV_CLIENT_ONLINE) n++;
    return n;
}

int poc_server_get_clients(const poc_server_t *srv, poc_user_t *out, int max)
{
    if (!srv || !out) return 0;
    int n = 0;
    for (int i = 0; i < srv->client_count && n < max; i++) {
        if (srv->clients[i].state == SRV_CLIENT_ONLINE) {
            out[n].id = srv->clients[i].user_id;
            snprintf(out[n].account, sizeof(out[n].account), "%s", srv->clients[i].account);
            out[n].status = 1;
            n++;
        }
    }
    return n;
}

bool poc_server_is_user_online(const poc_server_t *srv, uint32_t user_id)
{
    if (!srv) return false;
    for (int i = 0; i < srv->client_count; i++)
        if (srv->clients[i].user_id == user_id && srv->clients[i].state == SRV_CLIENT_ONLINE)
            return true;
    return false;
}
