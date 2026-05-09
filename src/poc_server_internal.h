/*
 * poc_server_internal.h — Server-side internal types
 *
 * All client/user/group arrays are dynamically allocated and grown
 * on demand. Default initial capacities can be overridden.
 */

#ifndef POC_SERVER_INTERNAL_H
#define POC_SERVER_INTERNAL_H

#include "poc_server.h"
#include "poc_internal.h"
#include <pthread.h>
#include <openssl/ssl.h>
#include <sys/epoll.h>

/* Default initial capacities (grown dynamically as needed) */
#define SRV_DEFAULT_CLIENTS   64
#define SRV_DEFAULT_USERS     64
#define SRV_DEFAULT_GROUPS    16
#define SRV_DEFAULT_MEMBERS   16

#define SRV_RECV_BUF             (64 * 1024)
#define SRV_LOGIN_TIMEOUT_MS     7000
#define SRV_HEARTBEAT_TIMEOUT_MS 90000   /* 90s — 3x the default 30s interval */
#define SRV_PTT_FLOOR_TIMEOUT_MS 60000   /* 60s max floor hold without audio */
#define SRV_EPOLL_BATCH          64      /* max events per epoll_wait call */

/* Per-group replay ring for late joiners (e.g. iOS PT clients waking
 * via APNs while the radio is mid-transmission). Holds the most
 * recent UDP audio packets pushed via poc_server_inject_audio so the
 * first UDP punch from a freshly-reconnected client triggers a
 * catch-up burst before live audio resumes. */
#define SRV_REPLAY_DEPTH         100     /* 100 × 20 ms = 2.0 s */
#define SRV_REPLAY_PKT_MAX       256     /* 8 B header + Opus SWB enc */
#define SRV_REPLAY_FRESH_MS      500     /* skip replay if last write older */

typedef enum {
    SRV_CLIENT_NEW,
    SRV_CLIENT_CHALLENGED,
    SRV_CLIENT_ONLINE,
} srv_client_state_t;

typedef struct {
    int                 fd;
    srv_client_state_t  state;
    uint32_t            user_id;
    char                account[32];
    char                password_sha1[41];
    uint8_t             session_id;
    uint32_t            challenge_nonce;
    uint32_t            active_group;
    uint32_t            priority;             /* copied from user DB on login */
    uint32_t            private_call_target;  /* non-zero = in private call to this user */
    struct sockaddr_in  udp_addr;
    bool                has_udp_addr;
    uint64_t            last_heartbeat;
    uint64_t            last_audio_time;     /* last UDP audio from this client */
    int                 codec_type;          /* POC_CODEC_* from PTT start */
    uint64_t            login_time;

    uint8_t             recv_buf[SRV_RECV_BUF];
    int                 recv_len;

    /* TLS */
    SSL                *ssl;
} srv_client_t;

typedef struct {
    char     account[32];
    char     name[64];
    char     password_sha1[41];
    uint32_t user_id;
    uint32_t priority;       /* PTT floor priority (higher = more priority) */
} srv_user_t;

typedef struct {
    uint32_t  id;
    char      name[64];
    uint32_t *members;       /* dynamically allocated member ID array */
    int       member_count;
    int       member_cap;    /* allocated capacity */
    int       floor_holder;  /* client index, -1 = free */

    /* Replay ring — protected by replay_mu. Written from any thread
     * that calls poc_server_inject_audio (kerchunk audio thread in
     * mod_poc); read from the I/O thread when a UDP punch arrives. */
    pthread_mutex_t replay_mu;
    uint8_t   replay_pkt[SRV_REPLAY_DEPTH][SRV_REPLAY_PKT_MAX];
    uint16_t  replay_len[SRV_REPLAY_DEPTH];
    int       replay_head;            /* next slot to write */
    int       replay_count;           /* 0..SRV_REPLAY_DEPTH */
    int64_t   replay_last_write_ms;   /* poc_mono_ms() of last push */
} srv_group_t;

struct poc_server {
    /* Config */
    char                bind_addr[64];
    uint16_t            port;
    int                 max_clients;  /* soft limit (0 = unlimited growth) */

    /* Users (dynamically allocated) */
    srv_user_t         *users;
    int                 user_count;
    int                 user_cap;

    /* Groups (dynamically allocated) */
    srv_group_t        *groups;
    int                 group_count;
    int                 group_cap;

    /* Clients (dynamically allocated) */
    srv_client_t       *clients;
    int                 client_count;
    int                 client_cap;

    /* Sockets */
    int                 listen_fd;
    int                 udp_fd;
    int                 epoll_fd;     /* epoll instance for I/O thread */

    /* TLS */
    SSL_CTX            *ssl_ctx;
    bool                tls_enabled;
    char                tls_cert_path[256];
    char                tls_key_path[256];

    /* Audio codec (I/O thread — decode incoming, encode injected) */
    poc_codec_t        *codec;
    uint16_t            inject_seq;  /* UDP sequence for injected audio */

    /* I/O thread */
    pthread_t           io_thread;
    _Atomic bool        io_running;
    int                 wakeup[2]; /* pipe */

    /* Event queue (I/O → main thread) */
    poc_evt_queue_t     evt_queue;

    /* Callbacks */
    poc_server_callbacks_t cb;
};

/* Grow a dynamic array. Returns 0 on success, -1 on alloc failure. */
static inline int srv_grow(void **arr, int *cap, int elem_size, int min_cap)
{
    int new_cap = *cap ? *cap * 2 : min_cap;
    if (new_cap < min_cap) new_cap = min_cap;
    void *p = realloc(*arr, (size_t)new_cap * elem_size);
    if (!p) return -1;
    /* Zero new slots */
    memset((char *)p + (size_t)(*cap) * elem_size, 0,
           (size_t)(new_cap - *cap) * elem_size);
    *arr = p;
    *cap = new_cap;
    return 0;
}

#endif /* POC_SERVER_INTERNAL_H */
