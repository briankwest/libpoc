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
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

/* ── Helpers ────────────────────────────────────────────────────── */

static void srv_sha1_hex(const char *input, char *hex)
{
    unsigned char d[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)input, strlen(input), d);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) sprintf(hex + i * 2, "%02x", d[i]);
    hex[40] = '\0';
}

static int srv_send_frame(int fd, const uint8_t *payload, uint16_t len)
{
    uint8_t frame[POC_MS_HDR_LEN + 65535];
    frame[0] = POC_MS_MAGIC_0;
    frame[1] = POC_MS_MAGIC_1;
    poc_write16(frame + 2, len);
    memcpy(frame + POC_MS_HDR_LEN, payload, len);
    int total = POC_MS_HDR_LEN + len, sent = 0;
    while (sent < total) {
        int n = send(fd, frame + sent, total - sent, MSG_NOSIGNAL);
        if (n <= 0) return POC_ERR_NETWORK;
        sent += n;
    }
    return POC_OK;
}

static void srv_broadcast_group(poc_server_t *srv, uint32_t group_id,
                                const uint8_t *payload, uint16_t len, int exclude_fd)
{
    for (int i = 0; i < srv->client_count; i++) {
        srv_client_t *c = &srv->clients[i];
        if (c->state == SRV_CLIENT_ONLINE && c->active_group == group_id && c->fd != exclude_fd)
            srv_send_frame(c->fd, payload, len);
    }
}

static void srv_broadcast_all(poc_server_t *srv, const uint8_t *payload, uint16_t len, int exclude_fd)
{
    for (int i = 0; i < srv->client_count; i++)
        if (srv->clients[i].state == SRV_CLIENT_ONLINE && srv->clients[i].fd != exclude_fd)
            srv_send_frame(srv->clients[i].fd, payload, len);
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

/* ── Client disconnect ──────────────────────────────────────────── */

static void srv_disconnect(poc_server_t *srv, int idx)
{
    srv_client_t *cl = &srv->clients[idx];
    poc_log_at(POC_LOG_INFO, "srv: disconnect '%s' (user_id=%u)", cl->account, cl->user_id);

    if (cl->state == SRV_CLIENT_ONLINE) {
        srv_status_broadcast(srv, cl->user_id, 0, cl->fd);
        /* Release floor */
        for (int i = 0; i < srv->group_count; i++)
            if (srv->groups[i].floor_holder == idx) srv->groups[i].floor_holder = -1;
        /* Push disconnect event */
        poc_event_t evt = { .type = POC_EVT_USER_STATUS,
                            .user_status = { .user_id = cl->user_id, .status = 0 }};
        snprintf(evt.user_status.user_id ? (char[1]){0} : (char[1]){0}, 0, ""); /* just for the union */
        evt.user_status.user_id = cl->user_id;
        evt.user_status.status = -1; /* disconnected */
        poc_evt_push(&srv->evt_queue, &evt);
    }

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
        poc_log_at(POC_LOG_WARNING, "srv: unknown account '%s'", account);
        uint8_t err[4] = { cl->session_id, POC_NOTIFY_RESPONSE, 0x06 };
        srv_send_frame(cl->fd, err, 3);
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

    srv_send_frame(cl->fd, resp, off);
    poc_log_at(POC_LOG_INFO, "srv: challenged '%s' (user_id=%u)", account, cl->user_id);
}

static void srv_handle_validate(poc_server_t *srv, srv_client_t *cl, const uint8_t *data, int len)
{
    if (len < 26 || cl->state != SRV_CLIENT_CHALLENGED) {
        poc_log_at(POC_LOG_WARNING, "srv: validate rejected: len=%d state=%d (need len>=26 state=CHALLENGED)", len, cl->state);
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
        poc_log_at(POC_LOG_WARNING, "srv: HMAC mismatch for '%s'", cl->account);
        uint8_t err[4] = { session, POC_NOTIFY_RESPONSE, 0x01 };
        srv_send_frame(cl->fd, err, 3);
        return;
    }

    cl->state = SRV_CLIENT_ONLINE;
    cl->last_heartbeat = poc_mono_ms();
    poc_log_at(POC_LOG_INFO, "srv: '%s' authenticated (user_id=%u)", cl->account, cl->user_id);

    /* Broadcast online status */
    srv_status_broadcast(srv, cl->user_id, 1, cl->fd);

    /* Build UserData: [session][cmd][count(2)][gid(4)][nlen(1)][name(N)]... */
    uint8_t resp[512];
    int off = 0;
    resp[off++] = session;
    resp[off++] = POC_NOTIFY_USER_DATA;

    int gcount = 0;
    for (int i = 0; i < srv->group_count; i++) {
        srv_group_t *g = &srv->groups[i];
        if (g->member_count == 0) { gcount++; continue; } /* open group */
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
        poc_write32(resp + off, g->id); off += 4;
        int nlen = strlen(g->name);
        resp[off++] = nlen;
        memcpy(resp + off, g->name, nlen); off += nlen;
    }
    srv_send_frame(cl->fd, resp, off);

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
    srv_send_frame(cl->fd, resp, 2);
}

static void srv_handle_enter_group(poc_server_t *srv, srv_client_t *cl, const uint8_t *data, int len)
{
    if (len < 10) return;
    uint32_t gid = poc_read32(data + 6);
    cl->active_group = gid;
    poc_log_at(POC_LOG_INFO, "srv: '%s' entered group %u", cl->account, gid);

    uint8_t notify[12];
    int off = 0;
    notify[off++] = 0; notify[off++] = POC_NOTIFY_ENTER_GROUP;
    poc_write32(notify + off, cl->user_id); off += 4;
    poc_write32(notify + off, gid); off += 4;
    srv_broadcast_group(srv, gid, notify, off, cl->fd);

    poc_event_t evt = { .type = POC_EVT_GROUPS_UPDATED };
    poc_evt_push(&srv->evt_queue, &evt);
}

static void srv_handle_start_ptt(poc_server_t *srv, srv_client_t *cl, int cl_idx)
{
    if (cl->active_group == 0) return;
    int gidx = srv_find_group_idx(srv, cl->active_group);
    if (gidx < 0) return;

    /* Floor check */
    bool grant = true;
    if (srv->groups[gidx].floor_holder >= 0 && srv->groups[gidx].floor_holder != cl_idx)
        grant = false;

    /* Ask application callback */
    if (grant && srv->cb.on_ptt_request)
        grant = srv->cb.on_ptt_request(srv, cl->user_id, cl->active_group, srv->cb.userdata);

    /* Respond */
    uint8_t resp[4] = { cl->session_id, POC_NOTIFY_RESPONSE, grant ? 0 : 0x25 };
    srv_send_frame(cl->fd, resp, 3);

    if (grant) {
        srv->groups[gidx].floor_holder = cl_idx;
        poc_log_at(POC_LOG_INFO, "srv: '%s' granted PTT on group %u", cl->account, cl->active_group);

        uint8_t notify[64];
        int off = 0;
        notify[off++] = 0; notify[off++] = POC_NOTIFY_START_PTT_PRI;
        poc_write32(notify + off, cl->user_id); off += 4;
        notify[off++] = 0;
        int nlen = strlen(cl->account) + 1;
        memcpy(notify + off, cl->account, nlen); off += nlen;
        srv_broadcast_group(srv, cl->active_group, notify, off, cl->fd);
    } else {
        poc_log_at(POC_LOG_DEBUG, "srv: PTT denied for '%s' on group %u", cl->account, cl->active_group);
    }
}

static void srv_handle_end_ptt(poc_server_t *srv, srv_client_t *cl, int cl_idx)
{
    if (cl->active_group == 0) return;
    int gidx = srv_find_group_idx(srv, cl->active_group);
    if (gidx >= 0 && srv->groups[gidx].floor_holder == cl_idx) {
        srv->groups[gidx].floor_holder = -1;
        poc_log_at(POC_LOG_INFO, "srv: '%s' released PTT on group %u", cl->account, cl->active_group);
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
        if (marker == POC_SOS_MARKER) {
            poc_log_at(POC_LOG_WARNING, "srv: *** SOS from '%s' ***", cl->account);
            uint8_t relay[10];
            int off = 0;
            relay[off++] = 0; relay[off++] = POC_NOTIFY_EXT_DATA;
            poc_write32(relay + off, cl->user_id); off += 4;
            relay[off++] = POC_SOS_MARKER;
            relay[off++] = (uint8_t)alert_type;
            srv_broadcast_all(srv, relay, off, cl->fd);
            if (srv->cb.on_sos)
                srv->cb.on_sos(srv, cl->user_id, alert_type, srv->cb.userdata);
        }
        return;
    }

    /* Regular message */
    if (len < 10) return;
    uint32_t target_id = poc_read32(data + 6);
    const char *text = (const char *)(data + 10);
    int text_len = len - 10;

    poc_log_at(POC_LOG_INFO, "srv: msg '%s' -> %u: %.*s", cl->account, target_id, text_len, text);

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
            srv_send_frame(target->fd, relay, off);
        } else {
            /* Target not online — echo back to sender */
            srv_send_frame(cl->fd, relay, off);
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
                poc_log_at(POC_LOG_WARNING, "srv: user %u stunned by '%s'", uid, cl->account);
                uint8_t msg[4] = { 0, POC_NOTIFY_FORCE_EXIT };
                srv_send_frame(srv->clients[i].fd, msg, 2);
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
            srv_send_frame(t->fd, notify, noff);
            poc_log_at(POC_LOG_INFO, "srv: pulled user %u to group %u", uid, cl->active_group);
        }
    }
}

/* ── Message dispatch ───────────────────────────────────────────── */

static void srv_dispatch(poc_server_t *srv, int cl_idx, const uint8_t *data, int len)
{
    if (len < 6) return;
    srv_client_t *cl = &srv->clients[cl_idx];
    uint8_t cmd = data[5]; /* client→server format: cmd at offset 5 */
    poc_log_at(POC_LOG_DEBUG, "srv: dispatch cmd=0x%02x len=%d from '%s' state=%d",
               cmd, len, cl->account, cl->state);

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
        srv_handle_start_ptt(srv, cl, cl_idx); break;
    case POC_CMD_END_PTT:
    case POC_CMD_END_PTT_ALT:
        srv_handle_end_ptt(srv, cl, cl_idx); break;
    case POC_CMD_EXT_DATA:    srv_handle_ext_data(srv, cl, data, len); break;
    case POC_CMD_FORCE_EXIT:  srv_handle_force_exit(srv, cl, data, len); break;
    case POC_CMD_PULL_TO_GROUP: srv_handle_pull(srv, cl, data, len); break;
    case POC_CMD_MOD_STATUS:
        if (len >= 7) srv_status_broadcast(srv, cl->user_id, data[6], cl->fd);
        break;

    /* Temp groups */
    case POC_CMD_INVITE_TMP:
        if (len >= 10) {
            poc_log_at(POC_LOG_INFO, "srv: '%s' inviting users to temp group", cl->account);
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
                    srv_send_frame(t->fd, notify, noff);
                }
            }
        }
        break;
    case POC_CMD_ENTER_TMP:
        if (len >= 10) {
            uint32_t gid = poc_read32(data + 6);
            cl->active_group = gid;
            poc_log_at(POC_LOG_INFO, "srv: '%s' entered temp group %u", cl->account, gid);
        }
        break;
    case POC_CMD_REJECT_TMP:
        poc_log_at(POC_LOG_INFO, "srv: '%s' rejected temp group invite", cl->account);
        break;

    /* Voice messages */
    case POC_CMD_NOTE_INCOME:
    case POC_CMD_VOICE_INCOME:
    case POC_CMD_VOICE_MESSAGE:
        poc_log_at(POC_LOG_INFO, "srv: voice msg from '%s' cmd=0x%02x len=%d", cl->account, cmd, len);
        break;

    default:
        poc_log_at(POC_LOG_DEBUG, "srv: unhandled cmd=0x%02x from '%s'", cmd, cl->account);
        break;
    }
}

/* ── TCP deframe ────────────────────────────────────────────────── */

static int srv_tcp_recv(poc_server_t *srv, int cl_idx)
{
    srv_client_t *cl = &srv->clients[cl_idx];
    int space = SRV_RECV_BUF - cl->recv_len;
    if (space <= 0) { cl->recv_len = 0; return -1; }

    int n = recv(cl->fd, cl->recv_buf + cl->recv_len, space, 0);
    if (n <= 0) return -1;
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
    uint8_t pkt[1500];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    int n = recvfrom(srv->udp_fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&from, &flen);
    if (n < POC_UDP_HDR_LEN) return;

    uint32_t sender_id = poc_read32(pkt + 2);
    srv_client_t *sender = NULL;
    for (int i = 0; i < srv->client_count; i++) {
        if (srv->clients[i].user_id == sender_id && srv->clients[i].state == SRV_CLIENT_ONLINE) {
            sender = &srv->clients[i];
            sender->udp_addr = from;
            sender->has_udp_addr = true;
            break;
        }
    }
    if (!sender || !sender->active_group) return;

    for (int i = 0; i < srv->client_count; i++) {
        srv_client_t *c = &srv->clients[i];
        if (c == sender || c->state != SRV_CLIENT_ONLINE) continue;
        if (c->active_group != sender->active_group) continue;
        if (!c->has_udp_addr) continue;
        sendto(srv->udp_fd, pkt, n, 0, (struct sockaddr *)&c->udp_addr, sizeof(c->udp_addr));
    }
}

/* ── I/O thread ─────────────────────────────────────────────────── */

static void *srv_io_thread(void *arg)
{
    poc_server_t *srv = (poc_server_t *)arg;
    poc_log_at(POC_LOG_INFO, "srv: I/O thread started");

    while (atomic_load(&srv->io_running)) {
        struct pollfd fds[3 + SRV_MAX_CLIENTS];
        int nfds = 0;

        fds[nfds].fd = srv->wakeup[0]; fds[nfds].events = POLLIN; nfds++;
        fds[nfds].fd = srv->listen_fd; fds[nfds].events = POLLIN; nfds++;
        fds[nfds].fd = srv->udp_fd; fds[nfds].events = POLLIN; nfds++;

        for (int i = 0; i < srv->client_count; i++) {
            fds[nfds].fd = srv->clients[i].fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        int rc = poll(fds, nfds, 100);
        if (rc < 0) { if (errno == EINTR) continue; break; }
        if (!atomic_load(&srv->io_running)) break;

        /* Drain wakeup */
        if (fds[0].revents & POLLIN) {
            char tmp[64]; while (read(srv->wakeup[0], tmp, sizeof(tmp)) > 0);
        }

        /* Accept */
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in ca;
            socklen_t cl = sizeof(ca);
            int cfd = accept(srv->listen_fd, (struct sockaddr *)&ca, &cl);
            if (cfd >= 0 && srv->client_count < srv->max_clients) {
                int fl = fcntl(cfd, F_GETFL, 0);
                fcntl(cfd, F_SETFL, fl | O_NONBLOCK);
                srv_client_t *c = &srv->clients[srv->client_count++];
                memset(c, 0, sizeof(*c));
                c->fd = cfd;
                c->state = SRV_CLIENT_NEW;
                poc_log_at(POC_LOG_INFO, "srv: accept fd=%d", cfd);
            } else if (cfd >= 0) {
                close(cfd);
            }
        }

        /* UDP */
        if (fds[2].revents & POLLIN)
            srv_handle_udp(srv);

        /* Client TCP */
        for (int i = 0; i < srv->client_count; i++) {
            int pidx = 3 + i;
            if (pidx >= nfds) break;
            if (fds[pidx].revents & (POLLERR | POLLHUP)) { srv_disconnect(srv, i); i--; continue; }
            if (fds[pidx].revents & POLLIN) {
                if (srv_tcp_recv(srv, i) < 0) { srv_disconnect(srv, i); i--; }
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
    srv->max_clients = (cfg && cfg->max_clients > 0) ? cfg->max_clients : SRV_MAX_CLIENTS;
    if (srv->max_clients > SRV_MAX_CLIENTS) srv->max_clients = SRV_MAX_CLIENTS;

    srv->listen_fd = -1;
    srv->udp_fd = -1;
    srv->wakeup[0] = srv->wakeup[1] = -1;
    atomic_store(&srv->io_running, false);
    poc_evt_init(&srv->evt_queue);

    for (int i = 0; i < SRV_MAX_GROUPS; i++) srv->groups[i].floor_holder = -1;

    if (cb) srv->cb = *cb;
    return srv;
}

void poc_server_destroy(poc_server_t *srv)
{
    if (!srv) return;
    poc_server_stop(srv);
    free(srv);
}

int poc_server_add_user(poc_server_t *srv, const poc_server_user_t *user)
{
    if (!srv || !user || srv->user_count >= SRV_MAX_USERS) return POC_ERR;
    srv_user_t *u = &srv->users[srv->user_count++];
    snprintf(u->account, sizeof(u->account), "%s", user->account);
    srv_sha1_hex(user->password, u->password_sha1);
    u->user_id = user->user_id;
    return POC_OK;
}

int poc_server_add_group(poc_server_t *srv, const poc_server_group_t *group)
{
    if (!srv || !group || srv->group_count >= SRV_MAX_GROUPS) return POC_ERR;
    srv_group_t *g = &srv->groups[srv->group_count++];
    g->id = group->id;
    snprintf(g->name, sizeof(g->name), "%s", group->name);
    g->floor_holder = -1;
    int n = group->member_count < SRV_MAX_GROUP_MEM ? group->member_count : SRV_MAX_GROUP_MEM;
    for (int i = 0; i < n; i++) g->members[i] = group->member_ids[i];
    g->member_count = n;
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
            srv->groups[i] = srv->groups[--srv->group_count];
            return POC_OK;
        }
    }
    return POC_ERR;
}

int poc_server_start(poc_server_t *srv)
{
    if (!srv) return POC_ERR;

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
    pipe(srv->wakeup);
    fl = fcntl(srv->wakeup[0], F_GETFL, 0); fcntl(srv->wakeup[0], F_SETFL, fl | O_NONBLOCK);

    /* Start I/O thread */
    atomic_store(&srv->io_running, true);
    if (pthread_create(&srv->io_thread, NULL, srv_io_thread, srv) != 0) {
        atomic_store(&srv->io_running, false);
        return POC_ERR;
    }

    poc_log_at(POC_LOG_INFO, "srv: listening on %s:%d", srv->bind_addr, srv->port);
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
        default:
            break;
        }
    }
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
    if (t) { srv_send_frame(t->fd, relay, off); return POC_OK; }
    return POC_ERR;
}

int poc_server_broadcast(poc_server_t *srv, const char *text)
{
    return poc_server_send_message(srv, 0, 0, text);
}

int poc_server_kick(poc_server_t *srv, uint32_t user_id)
{
    if (!srv) return POC_ERR;
    for (int i = 0; i < srv->client_count; i++) {
        if (srv->clients[i].user_id == user_id && srv->clients[i].state == SRV_CLIENT_ONLINE) {
            uint8_t msg[4] = { 0, POC_NOTIFY_FORCE_EXIT };
            srv_send_frame(srv->clients[i].fd, msg, 2);
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
    srv_send_frame(t->fd, notify, off);
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
