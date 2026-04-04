/*
 * poc_server.h — PoC protocol server API
 *
 * Server-side state machine that handles TCP/UDP listener, client
 * authentication, group membership, PTT floor arbitration, audio
 * relay, and message routing. The application provides callbacks
 * and user/group configuration; the library handles the protocol.
 */

#ifndef POC_SERVER_H
#define POC_SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include "poc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque server context ──────────────────────────────────────── */

typedef struct poc_server poc_server_t;

/* ── Configuration ──────────────────────────────────────────────── */

typedef struct {
    const char *bind_addr;       /* NULL or "" = "0.0.0.0" */
    uint16_t    port;            /* 0 = default 29999 */
    int         max_clients;     /* 0 = default 64 */

    /* TLS — wraps TCP signaling in TLS; UDP audio stays cleartext */
    bool        tls;             /* enable TLS */
    const char *tls_cert_path;   /* server certificate PEM */
    const char *tls_key_path;    /* server private key PEM */
} poc_server_config_t;

/* User credentials — add before or after start */
typedef struct {
    const char *account;
    const char *password;        /* raw — library SHA1-hashes internally */
    uint32_t    user_id;
} poc_server_user_t;

/* Group definition — add before or after start */
typedef struct {
    uint32_t    id;
    const char *name;
    const uint32_t *member_ids;  /* allowed user IDs (NULL = open group) */
    int         member_count;    /* 0 = open to all */
} poc_server_group_t;

/* ── Callbacks ──────────────────────────────────────────────────── */

typedef struct {
    /* Client lifecycle */
    void (*on_client_connect)(poc_server_t *srv, uint32_t user_id,
                              const char *account, void *ud);
    void (*on_client_disconnect)(poc_server_t *srv, uint32_t user_id,
                                 const char *account, void *ud);

    /* PTT floor — return true to grant, false to deny.
     * If NULL, library auto-grants (first-come-first-served). */
    bool (*on_ptt_request)(poc_server_t *srv, uint32_t user_id,
                           uint32_t group_id, void *ud);
    void (*on_ptt_end)(poc_server_t *srv, uint32_t user_id,
                       uint32_t group_id, void *ud);

    /* Messages */
    void (*on_message)(poc_server_t *srv, uint32_t from_id,
                       uint32_t target_id, const char *text, void *ud);
    void (*on_sos)(poc_server_t *srv, uint32_t user_id,
                   int alert_type, void *ud);

    /* Group changes */
    void (*on_group_enter)(poc_server_t *srv, uint32_t user_id,
                           uint32_t group_id, void *ud);
    void (*on_group_leave)(poc_server_t *srv, uint32_t user_id,
                           uint32_t group_id, void *ud);

    /* Audio — fires when a client sends voice (decoded 8kHz PCM).
     * Called from the main thread in poc_server_poll(). */
    void (*on_audio)(poc_server_t *srv, uint32_t speaker_id,
                     uint32_t group_id, const int16_t *pcm,
                     int n_samples, void *ud);

    void *userdata;
} poc_server_callbacks_t;

/* ── Lifecycle ──────────────────────────────────────────────────── */

poc_server_t *poc_server_create(const poc_server_config_t *cfg,
                                const poc_server_callbacks_t *cb);
void          poc_server_destroy(poc_server_t *srv);

/* ── User and group management ──────────────────────────────────── */

int  poc_server_add_user(poc_server_t *srv, const poc_server_user_t *user);
int  poc_server_add_group(poc_server_t *srv, const poc_server_group_t *group);
int  poc_server_remove_user(poc_server_t *srv, uint32_t user_id);
int  poc_server_remove_group(poc_server_t *srv, uint32_t group_id);

/* ── Start/stop ─────────────────────────────────────────────────── */

int  poc_server_start(poc_server_t *srv);
int  poc_server_stop(poc_server_t *srv);

/* ── Poll events (call from main thread to fire callbacks) ──────── */

int  poc_server_poll(poc_server_t *srv, int timeout_ms);

/* ── Server-initiated actions ───────────────────────────────────── */

int  poc_server_send_message(poc_server_t *srv, uint32_t from_id,
                             uint32_t target_id, const char *text);
int  poc_server_broadcast(poc_server_t *srv, const char *text);
int  poc_server_kick(poc_server_t *srv, uint32_t user_id);
int  poc_server_pull_to_group(poc_server_t *srv, uint32_t user_id,
                              uint32_t group_id);
int  poc_server_send_sos(poc_server_t *srv, uint32_t user_id,
                         int alert_type);

/* ── Audio injection (for bridging external audio into PoC) ────── */

int  poc_server_inject_audio(poc_server_t *srv, uint32_t group_id,
                             uint32_t virtual_user_id,
                             const int16_t *pcm, int n_samples);

/* Virtual PTT — send start/end notifications as a virtual user.
 * Use with inject_audio to bridge external audio sources. */
int  poc_server_start_ptt_for(poc_server_t *srv, uint32_t group_id,
                              uint32_t virtual_user_id, const char *name);
int  poc_server_end_ptt_for(poc_server_t *srv, uint32_t group_id,
                            uint32_t virtual_user_id);

/* ── Query state ────────────────────────────────────────────────── */

int  poc_server_client_count(const poc_server_t *srv);
int  poc_server_get_clients(const poc_server_t *srv,
                            poc_user_t *out, int max);
bool poc_server_is_user_online(const poc_server_t *srv, uint32_t user_id);

#ifdef __cplusplus
}
#endif

#endif /* POC_SERVER_H */
