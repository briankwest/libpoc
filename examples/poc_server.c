/*
 * poc_server.c — Minimal PoC protocol server
 *
 * Implements the server side of the MS-framed PoC protocol:
 *   - TCP listener on port 29999
 *   - Login with HMAC-SHA1 challenge-response
 *   - Group membership and PTT floor arbitration
 *   - UDP audio relay between group members
 *   - Text message routing
 *
 * Single-process, single-thread, poll()-based event loop.
 * Config from INI file: users, groups, bind address.
 *
 * Usage: poc_server [config.ini]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "linenoise.h"
#include "poc_proto.h"


/* ── Limits ─────────────────────────────────────────────────────── */

#define MAX_CLIENTS      64
#define MAX_USERS        64
#define MAX_GROUPS       32
#define MAX_GROUP_MEMBERS 32
#define MAX_ACCOUNT_LEN  32
#define MAX_PASSWORD_LEN 64
#define MAX_GROUP_NAME   64
#define TCP_BUF_SIZE     (64 * 1024)

/* ── Data types ─────────────────────────────────────────────────── */

typedef struct {
    char    account[MAX_ACCOUNT_LEN];
    char    password[MAX_PASSWORD_LEN];
    char    password_sha1[41];
    uint32_t user_id;
} user_def_t;

typedef struct {
    uint32_t id;
    char     name[MAX_GROUP_NAME];
    char     members[MAX_GROUP_MEMBERS][MAX_ACCOUNT_LEN];
    int      member_count;
} group_def_t;

typedef enum {
    CLIENT_NEW,
    CLIENT_CHALLENGED,
    CLIENT_ONLINE,
} client_state_t;

typedef struct {
    int             fd;
    client_state_t  state;
    uint32_t        user_id;
    char            account[MAX_ACCOUNT_LEN];
    uint8_t         session_id;
    uint32_t        challenge_nonce;
    uint32_t        active_group;
    struct sockaddr_in udp_addr;
    bool            has_udp_addr;

    /* TCP recv buffer */
    uint8_t         recv_buf[TCP_BUF_SIZE];
    int             recv_len;
} client_t;

typedef struct {
    char     bind_addr[64];
    uint16_t port;
    int      max_clients;

    user_def_t  users[MAX_USERS];
    int         user_count;
    uint32_t    next_user_id;

    group_def_t groups[MAX_GROUPS];
    int         group_count;

    int         listen_fd;
    int         udp_fd;
    client_t    clients[MAX_CLIENTS];
    int         client_count;

    /* PTT floor: group_id -> client index (-1 = free) */
    int         floor_holder[MAX_GROUPS];
} server_t;

static volatile int g_running = 1;
static int g_log_level = 2; /* 0=ERR, 1=WRN, 2=INF, 3=DBG */
static struct linenoiseState *g_srv_ls = NULL;
static void handle_sig(int s) { (void)s; g_running = 0; }

/* ── Helpers ────────────────────────────────────────────────────── */

static void sha1_hex(const char *input, char *hex_out)
{
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)input, strlen(input), digest);
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        sprintf(hex_out + i * 2, "%02x", digest[i]);
    hex_out[40] = '\0';
}

static void hmac_sha1(const uint8_t *key, int key_len,
                      const uint8_t *data, int data_len,
                      uint8_t *digest)
{
    unsigned int out_len = SHA_DIGEST_LENGTH;
    HMAC(EVP_sha1(), key, key_len, data, data_len, digest, &out_len);
}

static uint16_t rd16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }
static uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void wr16(uint8_t *p, uint16_t v) { p[0] = v>>8; p[1] = v; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = v>>24; p[1] = v>>16; p[2] = v>>8; p[3] = v; }

static void slog_at(int level, const char *fmt, ...)
{
    if (level > g_log_level) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    static const char *tags[] = {"ERR", "WRN", "INF", "DBG"};
    const char *tag = (level >= 0 && level <= 3) ? tags[level] : "???";
    if (g_srv_ls) linenoiseHide(g_srv_ls);
    fprintf(stderr, "[srv %02d:%02d:%02d.%03ld %s] ",
            tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000, tag);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    if (g_srv_ls) linenoiseShow(g_srv_ls);
}

/* Convenience macros */
#define slog_err(...)  slog_at(0, __VA_ARGS__)
#define slog_warn(...) slog_at(1, __VA_ARGS__)
#define slog(...)      slog_at(2, __VA_ARGS__)
#define slog_dbg(...)  slog_at(3, __VA_ARGS__)

/* ── INI parser ─────────────────────────────────────────────────── */

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        *end-- = '\0';
    return s;
}

static int load_config(server_t *srv, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }

    char line[512], section[64] = "";
    srv->next_user_id = 1000;

    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        if (!*s || *s == ';' || *s == '#') continue;

        if (*s == '[') {
            char *e = strchr(s, ']');
            if (e) { *e = '\0'; snprintf(section, sizeof(section), "%s", s + 1); }
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(s);
        char *val = trim(eq + 1);

        if (strcmp(section, "server") == 0) {
            if (strcmp(key, "bind") == 0) snprintf(srv->bind_addr, sizeof(srv->bind_addr), "%s", val);
            else if (strcmp(key, "port") == 0) srv->port = atoi(val);
            else if (strcmp(key, "max_clients") == 0) srv->max_clients = atoi(val);
        }
        else if (strcmp(section, "users") == 0) {
            if (srv->user_count < MAX_USERS) {
                user_def_t *u = &srv->users[srv->user_count];
                snprintf(u->account, sizeof(u->account), "%s", key);
                snprintf(u->password, sizeof(u->password), "%s", val);
                sha1_hex(val, u->password_sha1);
                u->user_id = srv->next_user_id++;
                srv->user_count++;
            }
        }
        else if (strcmp(section, "groups") == 0) {
            if (srv->group_count < MAX_GROUPS) {
                group_def_t *g = &srv->groups[srv->group_count];
                g->id = atoi(key);

                /* Parse "name : member1, member2, ..." */
                char *colon = strchr(val, ':');
                if (colon) {
                    *colon = '\0';
                    snprintf(g->name, sizeof(g->name), "%s", trim(val));
                    char *members = trim(colon + 1);
                    char *tok = strtok(members, ",");
                    while (tok && g->member_count < MAX_GROUP_MEMBERS) {
                        snprintf(g->members[g->member_count], MAX_ACCOUNT_LEN, "%s", trim(tok));
                        g->member_count++;
                        tok = strtok(NULL, ",");
                    }
                } else {
                    snprintf(g->name, sizeof(g->name), "%s", val);
                }
                srv->group_count++;
            }
        }
    }
    fclose(f);

    if (!srv->port) srv->port = 29999;
    if (!srv->bind_addr[0]) strcpy(srv->bind_addr, "0.0.0.0");
    if (!srv->max_clients) srv->max_clients = MAX_CLIENTS;

    slog("config: %d users, %d groups, bind %s:%d",
         srv->user_count, srv->group_count, srv->bind_addr, srv->port);
    return 0;
}

/* ── User/group lookup ──────────────────────────────────────────── */

static user_def_t *find_user(server_t *srv, const char *account)
{
    for (int i = 0; i < srv->user_count; i++)
        if (strcmp(srv->users[i].account, account) == 0)
            return &srv->users[i];
    return NULL;
}

static int find_group_idx(server_t *srv, uint32_t group_id)
{
    for (int i = 0; i < srv->group_count; i++)
        if (srv->groups[i].id == group_id)
            return i;
    return -1;
}

static client_t *find_client_by_user_id(server_t *srv, uint32_t user_id)
{
    for (int i = 0; i < srv->client_count; i++)
        if (srv->clients[i].user_id == user_id && srv->clients[i].state == CLIENT_ONLINE)
            return &srv->clients[i];
    return NULL;
}

/* ── TCP send helpers ───────────────────────────────────────────── */

static int tcp_send_frame(int fd, const uint8_t *payload, uint16_t len)
{
    uint8_t hdr[POC_MS_HDR_LEN];
    hdr[0] = POC_MS_MAGIC_0;
    hdr[1] = POC_MS_MAGIC_1;
    wr16(hdr + 2, len);

    uint8_t frame[POC_MS_HDR_LEN + 65535];
    memcpy(frame, hdr, POC_MS_HDR_LEN);
    memcpy(frame + POC_MS_HDR_LEN, payload, len);

    int total = POC_MS_HDR_LEN + len;
    int sent = 0;
    while (sent < total) {
        int n = send(fd, frame + sent, total - sent, MSG_NOSIGNAL);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

/* Send frame to all online clients in a group except `exclude_fd` */
static void broadcast_user_status(server_t *srv, uint32_t user_id,
                                  int status, int exclude_fd);
static void disconnect_client(server_t *srv, int idx);

static void broadcast_group(server_t *srv, uint32_t group_id,
                            const uint8_t *payload, uint16_t len, int exclude_fd)
{
    for (int i = 0; i < srv->client_count; i++) {
        client_t *c = &srv->clients[i];
        if (c->state == CLIENT_ONLINE && c->active_group == group_id && c->fd != exclude_fd)
            tcp_send_frame(c->fd, payload, len);
    }
}

/* ── Protocol handlers ──────────────────────────────────────────── */

static void handle_login(server_t *srv, client_t *cl, const uint8_t *data, int len)
{
    if (len < 10) { slog("login: too short"); return; }

    uint8_t session = data[0];
    /* data[1..4] = user_id (0xFFFFFFFF for initial login) */
    /* data[5] = cmd (0x01) */
    /* data[6..9] = version */
    const char *account = (const char *)(data + 10);

    cl->session_id = session;
    snprintf(cl->account, sizeof(cl->account), "%s", account);

    user_def_t *user = find_user(srv, account);
    if (!user) {
        slog_err("login: unknown account '%s'", account);
        /* Send login error */
        uint8_t err[4] = {0, POC_CMD_LOGIN, 0x06};
        tcp_send_frame(cl->fd, err, 3);
        return;
    }

    cl->user_id = user->user_id;

    /* Generate challenge */
    cl->challenge_nonce = (uint32_t)random();
    cl->state = CLIENT_CHALLENGED;

    /* Build challenge response:
     * [0]    session_id
     * [1]    POC_NOTIFY_CHALLENGE (0x07)
     * [2-5]  user_id (big-endian)
     * [6-9]  nonce (big-endian)
     * [10]   privilege_ex
     * [11-12] key_type (0 = no encryption)
     * [13]   gps_flag
     */
    uint8_t resp[32];
    int off = 0;
    resp[off++] = session;
    resp[off++] = POC_NOTIFY_CHALLENGE;
    wr32(resp + off, cl->user_id); off += 4;
    wr32(resp + off, cl->challenge_nonce); off += 4;
    resp[off++] = 0;     /* privilege_ex */
    wr16(resp + off, 0); off += 2; /* key_type: no encryption */
    resp[off++] = 0;     /* gps_flag */

    tcp_send_frame(cl->fd, resp, off);
    slog("login: challenged '%s' (user_id=%u, nonce=0x%08x)",
         account, cl->user_id, cl->challenge_nonce);
}

static void handle_validate(server_t *srv, client_t *cl, const uint8_t *data, int len)
{
    if (len < 26 || cl->state != CLIENT_CHALLENGED) {
        slog_err("validate: bad state or short message");
        return;
    }

    uint8_t session = data[0];
    /* data[1..4] = user_id */
    /* data[5] = POC_CMD_VALIDATE (0x04) */
    const uint8_t *client_hmac = data + 6; /* 20 bytes */

    user_def_t *user = find_user(srv, cl->account);
    if (!user) { slog_err("validate: user gone"); return; }

    /* Compute expected HMAC: HMAC-SHA1(sha1_hex_password, nonce) */
    uint8_t nonce_buf[4];
    wr32(nonce_buf, cl->challenge_nonce);
    uint8_t expected[20];
    hmac_sha1((const uint8_t *)user->password_sha1, 40, nonce_buf, 4, expected);

    if (memcmp(client_hmac, expected, 20) != 0) {
        slog_err("validate: HMAC mismatch for '%s'", cl->account);
        /* Send validate error */
        uint8_t err[4] = {session, POC_CMD_LOGIN, 0x01};
        tcp_send_frame(cl->fd, err, 3);
        return;
    }

    cl->state = CLIENT_ONLINE;
    slog("validate: '%s' authenticated (user_id=%u)", cl->account, cl->user_id);

    /* Broadcast online status to other clients */
    broadcast_user_status(srv, cl->user_id, 1, cl->fd);

    /* Build UserData response (minimal: just enough for poc_cli to go ONLINE)
     * [0]    session_id
     * [1]    POC_NOTIFY_USER_DATA (0x0B)
     * [2..]  group list data (simplified)
     */
    uint8_t resp[512];
    int off = 0;
    resp[off++] = session;
    resp[off++] = POC_NOTIFY_USER_DATA;

    /* Encode groups this user belongs to */
    int group_count = 0;
    for (int i = 0; i < srv->group_count; i++) {
        group_def_t *g = &srv->groups[i];
        for (int j = 0; j < g->member_count; j++) {
            if (strcmp(g->members[j], cl->account) == 0) {
                group_count++;
                break;
            }
        }
    }

    /* Simple group list encoding: count + (id, name_len, name)... */
    wr16(resp + off, group_count); off += 2;
    for (int i = 0; i < srv->group_count; i++) {
        group_def_t *g = &srv->groups[i];
        bool is_member = false;
        for (int j = 0; j < g->member_count; j++)
            if (strcmp(g->members[j], cl->account) == 0) { is_member = true; break; }
        if (!is_member) continue;

        wr32(resp + off, g->id); off += 4;
        int nlen = strlen(g->name);
        resp[off++] = nlen;
        memcpy(resp + off, g->name, nlen); off += nlen;
    }

    tcp_send_frame(cl->fd, resp, off);
}

static void handle_heartbeat(server_t *srv, client_t *cl, const uint8_t *data, int len)
{
    (void)srv; (void)data; (void)len;
    /* Send heartbeat ack in server→client format: [session][cmd] */
    uint8_t resp[2];
    resp[0] = cl->session_id;
    resp[1] = POC_CMD_HEARTBEAT;
    tcp_send_frame(cl->fd, resp, 2);
}

static void handle_enter_group(server_t *srv, client_t *cl, const uint8_t *data, int len)
{
    if (len < 10) return;
    uint32_t group_id = rd32(data + 6);
    cl->active_group = group_id;
    slog("group: '%s' entered group %u", cl->account, group_id);

    /* Notify other group members that this user joined */
    uint8_t notify[32];
    int off = 0;
    notify[off++] = 0;
    notify[off++] = POC_CMD_ENTER_GROUP;
    wr32(notify + off, cl->user_id); off += 4;
    wr32(notify + off, group_id); off += 4;
    broadcast_group(srv, group_id, notify, off, cl->fd);
}

static void handle_start_ptt(server_t *srv, client_t *cl, const uint8_t *data __attribute__((unused)), int len __attribute__((unused)))
{
    if (cl->active_group == 0) {
        slog("ptt: '%s' not in a group", cl->account);
        return;
    }

    int gidx = find_group_idx(srv, cl->active_group);
    if (gidx < 0) return;

    /* Check floor */
    if (srv->floor_holder[gidx] >= 0 && srv->floor_holder[gidx] != (int)(cl - srv->clients)) {
        slog_dbg("ptt: floor busy for group %u, denying '%s'", cl->active_group, cl->account);
        /* Send PTT denied (response with non-zero) */
        uint8_t resp[8];
        resp[0] = cl->session_id;
        resp[1] = POC_CMD_LOGIN; /* 0x01 = response */
        resp[2] = 1; /* denied */
        tcp_send_frame(cl->fd, resp, 3);
        return;
    }

    srv->floor_holder[gidx] = (int)(cl - srv->clients);
    slog("ptt: '%s' granted floor on group %u", cl->account, cl->active_group);

    /* Send grant to requester */
    uint8_t grant[8];
    grant[0] = cl->session_id;
    grant[1] = POC_CMD_LOGIN; /* 0x01 = response */
    grant[2] = 0; /* granted */
    tcp_send_frame(cl->fd, grant, 3);

    /* Notify group: PTT start
     * [0] session, [1] POC_CMD_START_PTT, [2-5] speaker_id, [6] flags */
    uint8_t notify[32];
    int off = 0;
    notify[off++] = 0;
    notify[off++] = POC_CMD_START_PTT;
    wr32(notify + off, cl->user_id); off += 4;
    notify[off++] = 0; /* flags */
    /* Add speaker name */
    int nlen = strlen(cl->account);
    memcpy(notify + off, cl->account, nlen + 1); off += nlen + 1;
    broadcast_group(srv, cl->active_group, notify, off, cl->fd);
}

static void handle_end_ptt(server_t *srv, client_t *cl, const uint8_t *data __attribute__((unused)), int len __attribute__((unused)))
{
    if (cl->active_group == 0) return;

    int gidx = find_group_idx(srv, cl->active_group);
    if (gidx < 0) return;

    if (srv->floor_holder[gidx] == (int)(cl - srv->clients)) {
        srv->floor_holder[gidx] = -1;
        slog("ptt: '%s' released floor on group %u", cl->account, cl->active_group);
    }

    /* Notify group: PTT end */
    uint8_t notify[16];
    int off = 0;
    notify[off++] = 0;
    notify[off++] = POC_CMD_END_PTT;
    wr32(notify + off, cl->user_id); off += 4;
    broadcast_group(srv, cl->active_group, notify, off, cl->fd);
}

static void handle_ext_data(server_t *srv, client_t *cl, const uint8_t *data, int len)
{
    if (len < 7) return;

    /* Check for SOS marker (0xFF at byte 6) or cancel (0xFE) */
    uint8_t marker = data[6];
    if (marker == 0xFF || marker == 0xFE) {
        int alert_type = (len > 7) ? data[7] : 0;
        const char *alert_names[] = {"SOS", "ManDown", "Fall", "CallAlarm"};
        const char *aname = (alert_type < 4) ? alert_names[alert_type] : "unknown";

        if (marker == 0xFF) {
            slog("*** SOS from '%s' (user %u): %s ***", cl->account, cl->user_id, aname);
            /* Broadcast SOS to all online clients */
            uint8_t relay[16];
            int off = 0;
            relay[off++] = 0;
            relay[off++] = POC_CMD_EXT_DATA;
            wr32(relay + off, cl->user_id); off += 4;
            relay[off++] = POC_SOS_MARKER;
            relay[off++] = (uint8_t)alert_type;
            for (int i = 0; i < srv->client_count; i++)
                if (srv->clients[i].state == CLIENT_ONLINE && srv->clients[i].fd != cl->fd)
                    tcp_send_frame(srv->clients[i].fd, relay, off);
        } else {
            slog("SOS cancel from '%s' (user %u)", cl->account, cl->user_id);
        }
        return;
    }

    /* Regular message: need target_id + text */
    if (len < 10) return;
    uint32_t target_id = rd32(data + 6);
    const char *text = (const char *)(data + 10);

    slog("msg: '%s' -> %u: %s", cl->account, target_id, text);

    /* Build server→client format message:
     * [0] session, [1] POC_CMD_EXT_DATA, [2-5] sender_id, [6..] text */
    int text_len = strlen(text) + 1;
    uint8_t relay[512];
    int off = 0;
    relay[off++] = 0;
    relay[off++] = POC_CMD_EXT_DATA;
    wr32(relay + off, cl->user_id); off += 4;
    if (text_len + off < (int)sizeof(relay)) {
        memcpy(relay + off, text, text_len);
        off += text_len;
    }

    int gidx = find_group_idx(srv, target_id);
    if (gidx >= 0) {
        broadcast_group(srv, target_id, relay, off, cl->fd);
    } else {
        client_t *target = find_client_by_user_id(srv, target_id);
        if (target)
            tcp_send_frame(target->fd, relay, off);
        else
            slog_warn("msg: target user %u not online", target_id);
    }
}

/* ── User status broadcast ──────────────────────────────────────── */

static void broadcast_user_status(server_t *srv, uint32_t user_id,
                                  int status, int exclude_fd)
{
    /* Send [session=0][cmd=0x25][user_id(4)][status(1)] to all online clients */
    uint8_t msg[8];
    msg[0] = 0;
    msg[1] = POC_NOTIFY_MOD_STATUS; /* POC_CMD_MOD_STATUS */
    wr32(msg + 2, user_id);
    msg[6] = (uint8_t)status;

    for (int i = 0; i < srv->client_count; i++) {
        client_t *c = &srv->clients[i];
        if (c->state == CLIENT_ONLINE && c->fd != exclude_fd)
            tcp_send_frame(c->fd, msg, 7);
    }
    slog("status: user %u -> %s", user_id, status ? "online" : "offline");
}

/* ── Message dispatch ───────────────────────────────────────────── */

static void handle_message(server_t *srv, client_t *cl, const uint8_t *data, int len)
{
    if (len < 6) return;
    /* Wire format: [0]=session [1-4]=user_id [5]=cmd [6..]=payload */
    uint8_t cmd = data[5];

    switch (cmd) {
    case POC_CMD_LOGIN:
        handle_login(srv, cl, data, len);
        break;
    case POC_CMD_VALIDATE:
        handle_validate(srv, cl, data, len);
        break;
    case POC_CMD_HEARTBEAT:
        handle_heartbeat(srv, cl, data, len);
        break;
    case POC_CMD_ENTER_GROUP:
        handle_enter_group(srv, cl, data, len);
        break;
    case POC_CMD_LEAVE_GROUP: /* 0x17 — also serves as leave group */
        cl->active_group = 0;
        slog("group: '%s' left group", cl->account);
        break;
    case POC_CMD_START_PTT:
    case POC_CMD_START_PTT_ALT:
        handle_start_ptt(srv, cl, data, len);
        break;
    case POC_CMD_END_PTT:
    case POC_CMD_END_PTT_ALT:
        handle_end_ptt(srv, cl, data, len);
        break;
    case POC_CMD_EXT_DATA:
        handle_ext_data(srv, cl, data, len);
        break;

    /* ── Temp groups ── */
    case POC_CMD_INVITE_TMP:
        if (len >= 10) {
            slog("tmp_group: '%s' inviting users", cl->account);
            /* Forward invite to all target users listed in payload */
            int off = 6;
            while (off + 4 <= len) {
                uint32_t uid = rd32(data + off); off += 4;
                client_t *target = find_client_by_user_id(srv, uid);
                if (target) {
                    uint8_t notify[16];
                    int noff = 0;
                    notify[noff++] = 0;
                    notify[noff++] = POC_NOTIFY_INVITE_TMP; /* POC_CMD_INVITE_TMP */
                    wr32(notify + noff, cl->active_group); noff += 4;
                    wr32(notify + noff, cl->user_id); noff += 4;
                    tcp_send_frame(target->fd, notify, noff);
                    slog("tmp_group: invited user %u", uid);
                }
            }
        }
        break;

    case POC_CMD_ENTER_TMP:
        if (len >= 10) {
            uint32_t gid = rd32(data + 6);
            cl->active_group = gid;
            slog("tmp_group: '%s' entered temp group %u", cl->account, gid);
        }
        break;

    /* POC_CMD_LEAVE_GROUP == CMD_LEAVE_GROUP (0x17), handled above */

    case POC_CMD_REJECT_TMP:
        slog("tmp_group: '%s' rejected invite", cl->account);
        break;

    /* ── Dispatcher: pull to group ── */
    case POC_CMD_PULL_TO_GROUP:
        if (len >= 10) {
            int off = 6;
            while (off + 4 <= len) {
                uint32_t uid = rd32(data + off); off += 4;
                client_t *target = find_client_by_user_id(srv, uid);
                if (target) {
                    target->active_group = cl->active_group;
                    uint8_t notify[8];
                    int noff = 0;
                    notify[noff++] = 0;
                    notify[noff++] = 0x4D; /* POC_CMD_PULL_TO_GROUP */
                    wr32(notify + noff, cl->active_group); noff += 4;
                    tcp_send_frame(target->fd, notify, noff);
                    slog("pull: user %u pulled to group %u by '%s'", uid, cl->active_group, cl->account);
                }
            }
        }
        break;

    /* ── Dispatcher: force exit ── */
    case POC_CMD_FORCE_EXIT:
        if (len >= 10) {
            int off = 6;
            while (off + 4 <= len) {
                uint32_t uid = rd32(data + off); off += 4;
                for (int i = 0; i < srv->client_count; i++) {
                    if (srv->clients[i].user_id == uid && srv->clients[i].state == CLIENT_ONLINE) {
                        slog("force_exit: user %u stunned by '%s'", uid, cl->account);
                        uint8_t fmsg[4] = {0, POC_NOTIFY_FORCE_EXIT};
                        tcp_send_frame(srv->clients[i].fd, fmsg, 2);
                        disconnect_client(srv, i);
                        break;
                    }
                }
            }
        }
        break;

    /* ── User status update ── */
    case POC_CMD_MOD_STATUS:
        if (len >= 7) {
            int status = data[6];
            slog("status: '%s' set status to %d", cl->account, status);
            broadcast_user_status(srv, cl->user_id, status, cl->fd);
        }
        break;

    /* ── Voice messages (store-and-forward stub) ── */
    case POC_CMD_NOTE_INCOME:
    case POC_CMD_VOICE_INCOME:
    case POC_CMD_VOICE_MESSAGE:
        slog("voice_msg: from '%s' cmd=0x%02x len=%d (forwarding not implemented)", cl->account, cmd, len);
        break;

    default:
        slog_dbg("unhandled cmd=0x%02x from '%s' len=%d", cmd, cl->account, len);
        break;
    }
}

/* ── TCP recv + deframe ─────────────────────────────────────────── */

static int tcp_recv_deframe(server_t *srv, client_t *cl)
{
    int space = TCP_BUF_SIZE - cl->recv_len;
    if (space <= 0) { cl->recv_len = 0; return -1; }

    int n = recv(cl->fd, cl->recv_buf + cl->recv_len, space, 0);
    if (n <= 0) return -1;
    cl->recv_len += n;

    /* Deframe MS packets */
    uint8_t *buf = cl->recv_buf;
    int remaining = cl->recv_len;

    while (remaining >= POC_MS_HDR_LEN + 1) {
        if (buf[0] != POC_MS_MAGIC_0 || buf[1] != POC_MS_MAGIC_1) {
            slog_err("bad magic from '%s', resetting", cl->account);
            remaining = 0;
            break;
        }

        uint16_t plen = rd16(buf + 2);
        int frame_total = POC_MS_HDR_LEN + plen;
        if (remaining < frame_total) break;

        handle_message(srv, cl, buf + POC_MS_HDR_LEN, plen);

        buf += frame_total;
        remaining -= frame_total;
    }

    if (remaining > 0 && buf != cl->recv_buf)
        memmove(cl->recv_buf, buf, remaining);
    cl->recv_len = remaining;

    return 0;
}

/* ── Client disconnect ──────────────────────────────────────────── */

static void disconnect_client(server_t *srv, int idx)
{
    client_t *cl = &srv->clients[idx];
    slog("disconnect: '%s' (fd=%d)", cl->account, cl->fd);

    /* Broadcast offline status */
    if (cl->state == CLIENT_ONLINE && cl->user_id)
        broadcast_user_status(srv, cl->user_id, 0, cl->fd);

    /* Release any held floor */
    for (int i = 0; i < srv->group_count; i++) {
        if (srv->floor_holder[i] == idx)
            srv->floor_holder[i] = -1;
    }

    /* Notify group members */
    if (cl->active_group) {
        uint8_t notify[16];
        int off = 0;
        notify[off++] = 0;
        notify[off++] = POC_CMD_END_PTT;
        wr32(notify + off, cl->user_id); off += 4;
        broadcast_group(srv, cl->active_group, notify, off, cl->fd);
    }

    close(cl->fd);

    /* Compact array */
    srv->client_count--;
    if (idx < srv->client_count)
        srv->clients[idx] = srv->clients[srv->client_count];

    /* Fix floor_holder indices */
    for (int i = 0; i < srv->group_count; i++) {
        if (srv->floor_holder[i] == srv->client_count)
            srv->floor_holder[i] = idx;
    }
}

/* ── UDP relay ──────────────────────────────────────────────────── */

static void handle_udp(server_t *srv)
{
    uint8_t pkt[1500];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    int n = recvfrom(srv->udp_fd, pkt, sizeof(pkt), 0,
                     (struct sockaddr *)&from, &fromlen);
    if (n < POC_UDP_HDR_LEN) return;

    uint32_t sender_id = rd32(pkt + 2);

    /* Find sender client and record their UDP address */
    client_t *sender = NULL;
    for (int i = 0; i < srv->client_count; i++) {
        if (srv->clients[i].user_id == sender_id && srv->clients[i].state == CLIENT_ONLINE) {
            sender = &srv->clients[i];
            sender->udp_addr = from;
            sender->has_udp_addr = true;
            break;
        }
    }

    if (!sender || !sender->active_group) return;

    /* Relay to all other group members with UDP addresses */
    for (int i = 0; i < srv->client_count; i++) {
        client_t *c = &srv->clients[i];
        if (c == sender) continue;
        if (c->state != CLIENT_ONLINE) continue;
        if (c->active_group != sender->active_group) continue;
        if (!c->has_udp_addr) continue;

        sendto(srv->udp_fd, pkt, n, 0,
               (struct sockaddr *)&c->udp_addr, sizeof(c->udp_addr));
    }
}

/* ── Main ───────────────────────────────────────────────────────── */

/* Forward declarations for console commands */
static void srv_completion(const char *buf, linenoiseCompletions *lc);
static void srv_process_line(server_t *srv, const char *line);

int main(int argc, char **argv)
{
    const char *config_path = NULL;

    /* Parse flags */
    int opt;
    while ((opt = getopt(argc, argv, "vq")) != -1) {
        switch (opt) {
        case 'v': g_log_level = 3; break;
        case 'q': g_log_level = 0; break;
        }
    }
    config_path = (optind < argc) ? argv[optind] : "poc_server.conf.ini";

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);
    signal(SIGPIPE, SIG_IGN);
    srandom(time(NULL));

    server_t srv;
    memset(&srv, 0, sizeof(srv));
    for (int i = 0; i < MAX_GROUPS; i++) srv.floor_holder[i] = -1;

    if (load_config(&srv, config_path) < 0)
        return 1;

    /* TCP listener */
    srv.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(srv.listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(srv.port),
    };
    inet_pton(AF_INET, srv.bind_addr, &addr.sin_addr);

    if (bind(srv.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv.listen_fd, 16);

    int flags = fcntl(srv.listen_fd, F_GETFL, 0);
    fcntl(srv.listen_fd, F_SETFL, flags | O_NONBLOCK);

    /* UDP socket */
    srv.udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (bind(srv.udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("udp bind"); return 1;
    }
    flags = fcntl(srv.udp_fd, F_GETFL, 0);
    fcntl(srv.udp_fd, F_SETFL, flags | O_NONBLOCK);

    slog("listening on %s:%d (tcp+udp)", srv.bind_addr, srv.port);

    /* Setup console — multiplexed (non-blocking) linenoise */
    linenoiseSetCompletionCallback(srv_completion);
    linenoiseHistorySetMaxLen(50);

    /* Make stdin non-blocking so linenoiseEditFeed never blocks the poll loop */
    int stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, stdin_flags | O_NONBLOCK);

    printf("Type 'help' for server commands.\n");

    char lnbuf[512];
    struct linenoiseState srv_ls;
    g_srv_ls = &srv_ls;
    linenoiseEditStart(&srv_ls, STDIN_FILENO, STDOUT_FILENO,
                       lnbuf, sizeof(lnbuf), "srv> ");

    /* Poll loop */
    while (g_running) {
        struct pollfd fds[3 + MAX_CLIENTS];
        int nfds = 0;

        /* stdin for console */
        fds[nfds].fd = STDIN_FILENO;
        fds[nfds].events = POLLIN;
        nfds++;

        fds[nfds].fd = srv.listen_fd;
        fds[nfds].events = POLLIN;
        nfds++;

        fds[nfds].fd = srv.udp_fd;
        fds[nfds].events = POLLIN;
        nfds++;

        for (int i = 0; i < srv.client_count; i++) {
            fds[nfds].fd = srv.clients[i].fd;
            fds[nfds].events = POLLIN;
            nfds++;
        }

        int rc = poll(fds, nfds, 100);
        if (rc < 0) { if (errno == EINTR) continue; break; }

        /* Console input */
        if (fds[0].revents & POLLIN) {
            char *line = linenoiseEditFeed(&srv_ls);
            if (line == linenoiseEditMore) goto skip_console;
            linenoiseEditStop(&srv_ls);
            if (line) {
                if (line[0]) {
                    linenoiseHistoryAdd(line);
                    srv_process_line(&srv, line);
                }
                linenoiseFree(line);
            } else {
                g_running = 0;  /* EOF / Ctrl-D */
            }
            if (g_running)
                linenoiseEditStart(&srv_ls, STDIN_FILENO, STDOUT_FILENO,
                                   lnbuf, sizeof(lnbuf), "srv> ");
        }
        skip_console:

        /* Accept new clients */
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in caddr;
            socklen_t clen = sizeof(caddr);
            int cfd = accept(srv.listen_fd, (struct sockaddr *)&caddr, &clen);
            if (cfd >= 0 && srv.client_count < srv.max_clients) {
                flags = fcntl(cfd, F_GETFL, 0);
                fcntl(cfd, F_SETFL, flags | O_NONBLOCK);

                client_t *cl = &srv.clients[srv.client_count++];
                memset(cl, 0, sizeof(*cl));
                cl->fd = cfd;
                cl->state = CLIENT_NEW;

                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &caddr.sin_addr, ip, sizeof(ip));
                slog("accept: fd=%d from %s:%d", cfd, ip, ntohs(caddr.sin_port));
            } else if (cfd >= 0) {
                close(cfd);
                slog_warn("accept: max clients reached, rejecting");
            }
        }

        /* UDP */
        if (fds[2].revents & POLLIN)
            handle_udp(&srv);

        /* Client TCP data */
        for (int i = 0; i < srv.client_count; i++) {
            int pidx = 3 + i;
            if (pidx >= nfds) break;

            if (fds[pidx].revents & (POLLERR | POLLHUP)) {
                disconnect_client(&srv, i);
                i--;
                continue;
            }
            if (fds[pidx].revents & POLLIN) {
                if (tcp_recv_deframe(&srv, &srv.clients[i]) < 0) {
                    disconnect_client(&srv, i);
                    i--;
                }
            }
        }
    }

    linenoiseEditStop(&srv_ls);
    g_srv_ls = NULL;

    slog("shutting down");
    for (int i = 0; i < srv.client_count; i++)
        close(srv.clients[i].fd);
    close(srv.listen_fd);
    close(srv.udp_fd);

    return 0;
}

/* ── Server console commands ────────────────────────────────────── */

static const char *srv_commands[] = {
    "clients", "groups", "users", "kick", "broadcast", "msg",
    "pull", "stun", "sos", "status", "shutdown", "help", NULL
};

static void srv_completion(const char *buf, linenoiseCompletions *lc)
{
    size_t len = strlen(buf);
    for (int i = 0; srv_commands[i]; i++)
        if (strncmp(buf, srv_commands[i], len) == 0)
            linenoiseAddCompletion(lc, srv_commands[i]);
}

static void srv_cmd_clients(server_t *srv)
{
    printf("Connected clients (%d):\n", srv->client_count);
    for (int i = 0; i < srv->client_count; i++) {
        client_t *c = &srv->clients[i];
        const char *state = c->state == CLIENT_ONLINE ? "online" :
                           c->state == CLIENT_CHALLENGED ? "auth" : "new";
        printf("  [%d] fd=%d account='%s' user_id=%u state=%s group=%u\n",
               i, c->fd, c->account, c->user_id, state, c->active_group);
    }
}

static void srv_cmd_groups(server_t *srv)
{
    printf("Groups (%d):\n", srv->group_count);
    for (int i = 0; i < srv->group_count; i++) {
        group_def_t *g = &srv->groups[i];
        int online = 0;
        for (int j = 0; j < srv->client_count; j++)
            if (srv->clients[j].state == CLIENT_ONLINE &&
                srv->clients[j].active_group == g->id) online++;
        const char *floor = "free";
        if (srv->floor_holder[i] >= 0 && srv->floor_holder[i] < srv->client_count)
            floor = srv->clients[srv->floor_holder[i]].account;
        printf("  [%u] %s — %d members, %d online, floor: %s\n",
               g->id, g->name, g->member_count, online, floor);
    }
}

static void srv_cmd_users(server_t *srv)
{
    printf("Registered users (%d):\n", srv->user_count);
    for (int i = 0; i < srv->user_count; i++) {
        user_def_t *u = &srv->users[i];
        bool online = false;
        for (int j = 0; j < srv->client_count; j++)
            if (srv->clients[j].user_id == u->user_id &&
                srv->clients[j].state == CLIENT_ONLINE) { online = true; break; }
        printf("  [%u] %s %s\n", u->user_id, u->account, online ? "(online)" : "");
    }
}

static void srv_cmd_kick(server_t *srv, const char *args)
{
    if (!args || !*args) { printf("Usage: kick <user_id or account>\n"); return; }

    /* Find by user_id or account name */
    uint32_t uid = atoi(args);
    int idx = -1;
    for (int i = 0; i < srv->client_count; i++) {
        if ((uid > 0 && srv->clients[i].user_id == uid) ||
            strcmp(srv->clients[i].account, args) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) { printf("Client '%s' not found. Use 'clients' to list.\n", args); return; }

    printf("Kicking '%s' (user_id=%u)...\n", srv->clients[idx].account, srv->clients[idx].user_id);
    uint8_t msg[4] = {0, POC_NOTIFY_FORCE_EXIT}; /* POC_CMD_FORCE_EXIT */
    tcp_send_frame(srv->clients[idx].fd, msg, 2);
    disconnect_client(srv, idx);
}

static void srv_cmd_broadcast(server_t *srv, const char *args)
{
    if (!args || !*args) {
        printf("Usage: broadcast <message>\n");
        return;
    }
    /* Send message to ALL online clients */
    uint8_t msg[512];
    int off = 0;
    msg[off++] = 0;
    msg[off++] = 0x43; /* POC_CMD_EXT_DATA */
    wr32(msg + off, 0); off += 4; /* from server (user_id=0) */
    int tlen = strlen(args) + 1;
    if (tlen + off < (int)sizeof(msg)) {
        memcpy(msg + off, args, tlen);
        off += tlen;
    }
    for (int i = 0; i < srv->client_count; i++)
        if (srv->clients[i].state == CLIENT_ONLINE)
            tcp_send_frame(srv->clients[i].fd, msg, off);
    printf("Broadcast sent to %d clients.\n", srv->client_count);
}

static void srv_cmd_help(void)
{
    printf("Server commands:\n");
    printf("  clients              List connected clients\n");
    printf("  groups               List groups with status\n");
    printf("  users                List registered users\n");
    printf("  kick <id|account>    Disconnect a client by user_id or name\n");
    printf("  broadcast <msg>      Send message to all clients\n");
    printf("  msg <uid|gid> <text> Send message to user or group\n");
    printf("  pull <uid> <gid>     Force user into a group\n");
    printf("  stun <uid>           Force-exit a user\n");
    printf("  sos <uid>            Trigger SOS for a user\n");
    printf("  status               Show server stats\n");
    printf("  shutdown             Stop the server\n");
    printf("  help                 Show this help\n");
}

static void srv_cmd_msg(server_t *srv, const char *args)
{
    uint32_t target = 0;
    char text[256] = "";
    if (sscanf(args, "%u %255[^\n]", &target, text) < 2)
        { printf("Usage: msg <user_id|group_id> <text>\n"); return; }

    uint8_t relay[512];
    int off = 0;
    relay[off++] = 0;
    relay[off++] = POC_NOTIFY_EXT_DATA; /* POC_CMD_EXT_DATA */
    wr32(relay + off, 0); off += 4; /* from server */
    int tlen = strlen(text) + 1;
    memcpy(relay + off, text, tlen); off += tlen;

    int gidx = find_group_idx(srv, target);
    if (gidx >= 0) {
        broadcast_group(srv, target, relay, off, -1);
        printf("Message sent to group %u.\n", target);
    } else {
        client_t *t = find_client_by_user_id(srv, target);
        if (t) { tcp_send_frame(t->fd, relay, off); printf("Message sent to user %u.\n", target); }
        else printf("Target %u not found.\n", target);
    }
}

static void srv_cmd_pull(server_t *srv, const char *args)
{
    uint32_t uid = 0, gid = 0;
    if (sscanf(args, "%u %u", &uid, &gid) < 2)
        { printf("Usage: pull <user_id> <group_id>\n"); return; }
    client_t *t = find_client_by_user_id(srv, uid);
    if (!t) { printf("User %u not online.\n", uid); return; }
    t->active_group = gid;
    uint8_t notify[8] = {0, POC_NOTIFY_PULL_TO_GROUP};
    wr32(notify + 2, gid);
    tcp_send_frame(t->fd, notify, 6);
    printf("Pulled user %u to group %u.\n", uid, gid);
}

static void srv_cmd_stun(server_t *srv, const char *args)
{
    uint32_t uid = atoi(args);
    if (uid == 0) { printf("Usage: stun <user_id>\n"); return; }
    for (int i = 0; i < srv->client_count; i++) {
        if (srv->clients[i].user_id == uid && srv->clients[i].state == CLIENT_ONLINE) {
            uint8_t msg[4] = {0, POC_NOTIFY_FORCE_EXIT};
            tcp_send_frame(srv->clients[i].fd, msg, 2);
            printf("Stunned user %u.\n", uid);
            disconnect_client(srv, i);
            return;
        }
    }
    printf("User %u not online.\n", uid);
}

static void srv_cmd_status(server_t *srv)
{
    int online = 0;
    for (int i = 0; i < srv->client_count; i++)
        if (srv->clients[i].state == CLIENT_ONLINE) online++;
    printf("Server status:\n");
    printf("  Registered users: %d\n", srv->user_count);
    printf("  Groups:           %d\n", srv->group_count);
    printf("  Connected:        %d (%d online)\n", srv->client_count, online);
}

static void srv_cmd_sos(server_t *srv, const char *args)
{
    uint32_t uid = atoi(args);
    if (uid == 0) { printf("Usage: sos <user_id>\n"); return; }
    uint8_t relay[16];
    int off = 0;
    relay[off++] = 0;
    relay[off++] = POC_NOTIFY_EXT_DATA;
    wr32(relay + off, uid); off += 4;
    relay[off++] = POC_SOS_MARKER;
    relay[off++] = 0; /* SOS type */
    for (int i = 0; i < srv->client_count; i++)
        if (srv->clients[i].state == CLIENT_ONLINE)
            tcp_send_frame(srv->clients[i].fd, relay, off);
    printf("SOS broadcast for user %u.\n", uid);
}

static void srv_process_line(server_t *srv, const char *line)
{
    if (strcmp(line, "clients") == 0) srv_cmd_clients(srv);
    else if (strcmp(line, "groups") == 0) srv_cmd_groups(srv);
    else if (strcmp(line, "users") == 0) srv_cmd_users(srv);
    else if (strncmp(line, "kick ", 5) == 0) srv_cmd_kick(srv, line + 5);
    else if (strncmp(line, "broadcast ", 10) == 0) srv_cmd_broadcast(srv, line + 10);
    else if (strncmp(line, "msg ", 4) == 0) srv_cmd_msg(srv, line + 4);
    else if (strncmp(line, "pull ", 5) == 0) srv_cmd_pull(srv, line + 5);
    else if (strncmp(line, "stun ", 5) == 0) srv_cmd_stun(srv, line + 5);
    else if (strncmp(line, "sos ", 4) == 0) srv_cmd_sos(srv, line + 4);
    else if (strcmp(line, "status") == 0) srv_cmd_status(srv);
    else if (strcmp(line, "shutdown") == 0 || strcmp(line, "quit") == 0) g_running = 0;
    else if (strcmp(line, "help") == 0 || strcmp(line, "?") == 0) srv_cmd_help();
    else printf("Unknown command. Type 'help' for a list.\n");
}
