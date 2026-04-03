/*
 * poc_server_internal.h — Server-side internal types
 */

#ifndef POC_SERVER_INTERNAL_H
#define POC_SERVER_INTERNAL_H

#include "poc_server.h"
#include "poc_internal.h"
#include <pthread.h>

#define SRV_MAX_CLIENTS   64
#define SRV_MAX_USERS     64
#define SRV_MAX_GROUPS    32
#define SRV_MAX_GROUP_MEM 32
#define SRV_RECV_BUF      (64 * 1024)
#define SRV_LOGIN_TIMEOUT_MS 7000

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
    struct sockaddr_in  udp_addr;
    bool                has_udp_addr;
    uint64_t            last_heartbeat;
    uint64_t            login_time;

    uint8_t             recv_buf[SRV_RECV_BUF];
    int                 recv_len;
} srv_client_t;

typedef struct {
    char     account[32];
    char     password_sha1[41];
    uint32_t user_id;
} srv_user_t;

typedef struct {
    uint32_t id;
    char     name[64];
    uint32_t members[SRV_MAX_GROUP_MEM];
    int      member_count;
    int      floor_holder;  /* client index, -1 = free */
} srv_group_t;

struct poc_server {
    /* Config */
    char                bind_addr[64];
    uint16_t            port;
    int                 max_clients;

    /* Users and groups */
    srv_user_t          users[SRV_MAX_USERS];
    int                 user_count;
    srv_group_t         groups[SRV_MAX_GROUPS];
    int                 group_count;

    /* Clients */
    srv_client_t        clients[SRV_MAX_CLIENTS];
    int                 client_count;

    /* Sockets */
    int                 listen_fd;
    int                 udp_fd;

    /* I/O thread */
    pthread_t           io_thread;
    _Atomic bool        io_running;
    int                 wakeup[2]; /* pipe */

    /* Event queue (I/O → main thread) */
    poc_evt_queue_t     evt_queue;

    /* Callbacks */
    poc_server_callbacks_t cb;
};

#endif /* POC_SERVER_INTERNAL_H */
