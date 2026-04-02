/*
 * poc.h — PoC (Push-to-Talk over Cellular) protocol library
 *
 * Implements the signaling and audio transport protocol used by
 * common PoC radios (Retevis, TYT, etc.) for group and private PTT.
 */

#ifndef POC_H
#define POC_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque context ─────────────────────────────────────────────── */

typedef struct poc_ctx poc_ctx_t;

/* ── Status codes ───────────────────────────────────────────────── */

#define POC_OK            0
#define POC_ERR          -1
#define POC_ERR_AUTH     -2
#define POC_ERR_TIMEOUT  -3
#define POC_ERR_NETWORK  -4
#define POC_ERR_STATE    -5
#define POC_ERR_NOMEM    -6

/* ── Connection state ───────────────────────────────────────────── */

typedef enum {
    POC_STATE_OFFLINE    = 0,
    POC_STATE_CONNECTING = 1,
    POC_STATE_ONLINE     = 2,
    POC_STATE_LOGOUT     = 3
} poc_state_t;

/* ── Audio codec ────────────────────────────────────────────────── */

#define POC_CODEC_SPEEX   0

#define POC_AUDIO_RATE       8000   /* Hz */
#define POC_AUDIO_FRAME_MS   20
#define POC_AUDIO_FRAME_SAMPLES 160 /* 20ms @ 8kHz */

/* ── Configuration ──────────────────────────────────────────────── */

typedef struct {
    const char *server_host;
    uint16_t    server_port;     /* default 29999 */
    const char *account;
    const char *password;        /* raw — library hashes with SHA1 */
    const char *imei;            /* may be NULL */
    const char *iccid;           /* may be NULL */
    int         codec;           /* POC_CODEC_SPEEX */
    int         heartbeat_ms;    /* 0 = default (30000) */
    bool        enable_fec;      /* audio forward error correction */
    int         fec_group_size;  /* FEC group size (0 = default 3) */
    int         gps_interval_ms; /* GPS report interval (0 = default 60000) */
} poc_config_t;

/* ── Data types ─────────────────────────────────────────────────── */

typedef struct {
    uint32_t id;
    char     name[64];
    int      user_count;
    bool     is_active;
    bool     is_tmp;
} poc_group_t;

typedef struct {
    uint32_t id;
    char     account[32];
    char     name[64];
    int      status;
    uint32_t privilege;
} poc_user_t;

typedef struct {
    const int16_t *samples;
    int            n_samples;     /* always 160 */
    int            sample_rate;   /* always 8000 */
    uint32_t       speaker_id;
    uint32_t       group_id;
} poc_audio_frame_t;

/* ── Callbacks ──────────────────────────────────────────────────── */

typedef struct {
    void (*on_state_change)(poc_ctx_t *ctx, poc_state_t state, void *ud);
    void (*on_login_error)(poc_ctx_t *ctx, int code, const char *msg, void *ud);
    void (*on_groups_updated)(poc_ctx_t *ctx, const poc_group_t *groups, int count, void *ud);
    void (*on_ptt_start)(poc_ctx_t *ctx, uint32_t speaker_id, const char *name,
                         uint32_t group_id, void *ud);
    void (*on_ptt_end)(poc_ctx_t *ctx, uint32_t speaker_id, uint32_t group_id, void *ud);
    void (*on_audio_frame)(poc_ctx_t *ctx, const poc_audio_frame_t *frame, void *ud);
    void (*on_ptt_granted)(poc_ctx_t *ctx, bool granted, void *ud);
    void (*on_message)(poc_ctx_t *ctx, uint32_t from_id, const char *text, void *ud);
    void *userdata;
} poc_callbacks_t;

/* ── Lifecycle ──────────────────────────────────────────────────── */

poc_ctx_t  *poc_create(const poc_config_t *cfg, const poc_callbacks_t *cb);
void        poc_destroy(poc_ctx_t *ctx);

/* ── Connection ─────────────────────────────────────────────────── */

int  poc_connect(poc_ctx_t *ctx);
int  poc_disconnect(poc_ctx_t *ctx);
int  poc_poll(poc_ctx_t *ctx, int timeout_ms);

/* ── Group ──────────────────────────────────────────────────────── */

int  poc_enter_group(poc_ctx_t *ctx, uint32_t group_id);
int  poc_leave_group(poc_ctx_t *ctx);

/* ── PTT ────────────────────────────────────────────────────────── */

int  poc_ptt_start(poc_ctx_t *ctx);
int  poc_ptt_stop(poc_ctx_t *ctx);
int  poc_ptt_send_audio(poc_ctx_t *ctx, const int16_t *pcm, int n_samples);

/* ── GPS ────────────────────────────────────────────────────────── */

int  poc_set_gps(poc_ctx_t *ctx, float lat, float lng);

/* ── Messaging ──────────────────────────────────────────────────── */

int  poc_send_group_msg(poc_ctx_t *ctx, uint32_t group_id, const char *msg);
int  poc_send_user_msg(poc_ctx_t *ctx, uint32_t user_id, const char *msg);

/* ── Private call ───────────────────────────────────────────────── */

int  poc_call_user(poc_ctx_t *ctx, uint32_t user_id);
int  poc_call_end(poc_ctx_t *ctx);

/* ── Encryption ─────────────────────────────────────────────────── */

bool poc_is_encrypted(const poc_ctx_t *ctx);

/* ── Info ───────────────────────────────────────────────────────── */

poc_state_t  poc_get_state(const poc_ctx_t *ctx);
uint32_t     poc_get_user_id(const poc_ctx_t *ctx);
const char  *poc_get_account(const poc_ctx_t *ctx);
int          poc_get_group_count(const poc_ctx_t *ctx);
int          poc_get_groups(const poc_ctx_t *ctx, poc_group_t *out, int max);

#ifdef __cplusplus
}
#endif

#endif /* POC_H */
