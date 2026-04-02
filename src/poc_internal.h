/*
 * poc_internal.h — Private types and constants
 *
 * Threading model:
 *   - I/O thread: runs TCP/UDP poll loop, decodes audio, pushes into rings
 *   - Caller thread: calls poc_poll() to drain rings/events and fire callbacks
 *   - TX path: caller pushes PCM into tx_ring, I/O thread encodes and sends
 */

#ifndef POC_INTERNAL_H
#define POC_INTERNAL_H

#include "poc.h"
#include "poc_ring.h"
#include "poc_events.h"
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <speex/speex.h>

/* ── TCP Frame ("MS" framing) ───────────────────────────────────── */

#define MS_MAGIC_0      0x4D   /* 'M' */
#define MS_MAGIC_1      0x53   /* 'S' */
#define MS_HDR_LEN      4      /* 2 magic + 2 length */
#define MS_MAX_PAYLOAD   65535

#define TCP_RECV_BUF_SZ  (128 * 1024)

/* ── Command types (MS-frame payload byte at offset 1) ──────────── */

#define CMD_LOGIN                0x01
#define CMD_VALIDATE             0x04
#define CMD_HEARTBEAT            0x06
#define CMD_CHALLENGE            0x07
#define CMD_NOTIFY_USER_DATA     0x0B
#define CMD_NOTIFY_START_PTT     0x0D
#define CMD_NOTIFY_END_PTT       0x0F
#define CMD_NOTIFY_ENTER_GROUP   0x11
#define CMD_NOTIFY_INVITE_TMP    0x13
#define CMD_NOTIFY_ENTER_TMP     0x15
#define CMD_NOTIFY_LEAVE_TMP     0x17
#define CMD_NOTIFY_REJECT_TMP    0x19
#define CMD_NOTIFY_PKG_ACK       0x1D
#define CMD_NOTIFY_MOD_NAME      0x1F
#define CMD_NOTIFY_MOD_DEF_GRP   0x21
#define CMD_NOTIFY_MOD_STATUS    0x25
#define CMD_NOTIFY_MOD_PRIV      0x27
#define CMD_NOTIFY_MOD_PRIORITY  0x29
#define CMD_NOTIFY_REMOVE_USER   0x2B
#define CMD_FORCE_EXIT           0x2D
#define CMD_NOTIFY_ADD_GROUP     0x33
#define CMD_NOTIFY_DEL_GROUP     0x35
#define CMD_NOTIFY_GRP_MOD_NAME  0x37
#define CMD_NOTIFY_GRP_MOD_MSTR  0x39
#define CMD_NOTIFY_GRP_ADD_USER  0x3B
#define CMD_NOTIFY_GRP_DEL_USER  0x3D
#define CMD_NOTIFY_EXT_DATA      0x43
#define CMD_PULL_TO_GROUP        0x4D
#define CMD_START_PTT            0x5D
#define CMD_END_PTT              0x5E
#define CMD_START_PTT_ALT        0x66
#define CMD_END_PTT_ALT          0x67
#define CMD_NOTE_INCOME          0x70
#define CMD_VOICE_INCOME         0x72
#define CMD_VOICE_MESSAGE        0x73
#define CMD_RECV_CONTENT         0x80
#define CMD_RECV_MCAST           0x84

/* ── UDP packet header ──────────────────────────────────────────── */

#define UDP_HDR_LEN       8    /* 2 seq + 4 sender + 1 pad + 1 type */
#define UDP_MAX_PKT       1400
#define UDP_DEDUP_SLOTS   8

/* ── Speex codec constants ──────────────────────────────────────── */

#define SPEEX_FRAME_PCM   320   /* bytes (160 samples * 2) */
#define SPEEX_FRAME_ENC   20    /* bytes encoded (mode 4, narrowband) */

/* ── Timeouts ───────────────────────────────────────────────────── */

#define LOGIN_TIMEOUT_MS      7000
#define VALIDATE_TIMEOUT_MS   5000
#define HEARTBEAT_DEFAULT_MS  30000
#define RECONNECT_INIT_MS     2000    /* first retry after 2s */
#define RECONNECT_MAX_MS      512000  /* give up after 512s */
#define MAX_LOGIN_RETRIES     5

/* ── Ring buffer sizing ─────────────────────────────────────────── */

#define RX_RING_FRAMES    64   /* ~1.28s jitter buffer (64 * 20ms) */
#define TX_RING_FRAMES    64   /* ~1.28s TX buffer */

/* ── Encryption ─────────────────────────────────────────────────── */

#define POC_KEY_TYPE_AES  0x02
#define POC_KEY_TYPE_SM4  0x06
#define POC_ENCRYPT_KEY_LEN 32   /* max key length (AES-256) */
#define POC_MAX_GROUP_KEYS  32   /* max per-group keys */

/* ── FEC ────────────────────────────────────────────────────────── */

#define POC_FEC_DEFAULT_GROUP 3  /* 3 data frames + 1 parity */
#define POC_FEC_MAX_GROUP     8
#define POC_FEC_MAX_FRAME    64  /* max encoded frame size */

/* ── GPS ────────────────────────────────────────────────────────── */

#define GPS_DEFAULT_INTERVAL_MS  60000  /* 60 seconds */

/* ── Protocol version ───────────────────────────────────────────── */

#define POC_PROTOCOL_VER  0x000A0102  /* 10.1.2 */

/* ── Login state machine ────────────────────────────────────────── */

typedef enum {
    LOGIN_IDLE,
    LOGIN_CONNECTING,
    LOGIN_SENT_LOGIN,
    LOGIN_SENT_VALIDATE,
    LOGIN_ONLINE,
    LOGIN_FAILED
} login_state_t;

/* ── Speex codec state ──────────────────────────────────────────── */

typedef struct {
    void       *enc_state;
    void       *dec_state;
    SpeexBits   enc_bits;
    SpeexBits   dec_bits;
    int         frame_size;  /* samples per frame (160) */
} poc_speex_t;

/* ── Encryption state ───────────────────────────────────────────── */

typedef struct {
    uint32_t group_id;
    uint8_t  key_type;
    uint8_t  key[POC_ENCRYPT_KEY_LEN];
    int      key_len;
    bool     valid;
} poc_group_key_t;

typedef struct {
    bool             enabled;
    uint8_t          key_type;       /* session-level key type */
    uint8_t          key[POC_ENCRYPT_KEY_LEN];
    int              key_len;
    poc_group_key_t  group_keys[POC_MAX_GROUP_KEYS];
} poc_encrypt_t;

/* ── FEC state ──────────────────────────────────────────────────── */

typedef struct {
    bool    enabled;
    int     group_size;

    /* Encoder */
    int     enc_count;
    uint8_t parity[POC_FEC_MAX_FRAME];
    int     parity_len;

    /* Decoder */
    uint8_t dec_frames[POC_FEC_MAX_GROUP][POC_FEC_MAX_FRAME];
    int     dec_frame_len[POC_FEC_MAX_GROUP];
    uint8_t dec_parity[POC_FEC_MAX_FRAME];
    int     dec_parity_len;
    bool    dec_has_parity;
    uint32_t dec_received;  /* bitmask */
} poc_fec_t;

/* ── Group storage ──────────────────────────────────────────────── */

#define MAX_GROUPS  64

/* ── Context ────────────────────────────────────────────────────── */

struct poc_ctx {
    /* Config (copies, owned) */
    char        server_host[256];
    uint16_t    server_port;
    char        account[32];
    char        password_sha1[41]; /* hex SHA1 of password */
    char        imei[20];
    char        iccid[33];
    int         codec;
    int         heartbeat_ms;

    /* State (written by I/O thread, read by both) */
    _Atomic poc_state_t  state;
    _Atomic login_state_t login_state;
    uint8_t         session_id;     /* I/O thread only */
    uint32_t        user_id;        /* I/O thread only after challenge */
    uint32_t        challenge_nonce;
    uint32_t        privilege;
    int             login_retries;

    /* TCP (I/O thread only) */
    int             tcp_fd;
    uint8_t         tcp_recv_buf[TCP_RECV_BUF_SZ];
    int             tcp_recv_len;

    /* UDP (I/O thread only) */
    int             udp_fd;
    struct sockaddr_in udp_server;
    uint16_t        udp_seq;
    uint16_t        udp_dedup[UDP_DEDUP_SLOTS];
    int             udp_dedup_idx;

    /* Timers (I/O thread only, monotonic ms) */
    uint64_t        last_heartbeat;
    uint64_t        login_sent_at;
    uint64_t        last_activity;

    /* PTT state (I/O thread writes, caller reads via events) */
    _Atomic bool    ptt_active;        /* we are transmitting */
    _Atomic bool    ptt_rx_active;     /* someone else is talking */
    uint32_t        ptt_speaker_id;
    char            ptt_speaker_name[64];

    /* Groups (I/O thread only for now) */
    poc_group_t     groups[MAX_GROUPS];
    int             group_count;
    uint32_t        active_group_id;

    /* Audio codec (I/O thread only — NOT thread-safe) */
    poc_speex_t     speex;

    /* Encryption (I/O thread only) */
    poc_encrypt_t   encrypt;

    /* FEC (I/O thread only) */
    poc_fec_t       fec;

    /* GPS (written by caller, read by I/O thread) */
    float           gps_lat;
    float           gps_lng;
    _Atomic bool    gps_valid;
    _Atomic bool    gps_updated;
    uint64_t        last_gps_send;
    int             gps_interval_ms;

    /* ── Lock-free queues (I/O thread ↔ caller) ──── */
    poc_ring_t      rx_ring;     /* decoded PCM: I/O → caller */
    poc_ring_t      tx_ring;     /* raw PCM:     caller → I/O */
    poc_evt_queue_t evt_queue;   /* signaling:   I/O → caller */

    /* ── Reconnect (I/O thread only) ─────────────────── */
    uint64_t        reconnect_at;       /* when to try next (mono ms) */
    int             reconnect_delay_ms; /* current backoff: 2000..512000 */
    bool            reconnect_active;   /* true = in backoff loop */

    /* ── I/O thread ─────────────────────────────────── */
    pthread_t       io_thread;
    _Atomic bool    io_running;   /* false = signal thread to stop */
    int             io_wakeup[2]; /* pipe: write to [1] to wake poll */

    /* Callbacks (fired from caller's thread in poc_poll) */
    poc_callbacks_t cb;
};

/* ── Internal functions ─────────────────────────────────────────── */

/* poc_util.c */
uint64_t    poc_mono_ms(void);
uint16_t    poc_read16(const uint8_t *p);
uint32_t    poc_read32(const uint8_t *p);
void        poc_write16(uint8_t *p, uint16_t v);
void        poc_write32(uint8_t *p, uint32_t v);
void        poc_log(const char *fmt, ...);

/* poc_crypto.c */
void        poc_sha1(const char *input, char *hex_out);
void        poc_hmac_sha1(const uint8_t *key, int key_len,
                          const uint8_t *data, int data_len,
                          uint8_t *digest);

/* poc_tcp.c */
int         poc_tcp_connect(poc_ctx_t *ctx);
void        poc_tcp_close(poc_ctx_t *ctx);
int         poc_tcp_send_frame(poc_ctx_t *ctx, const uint8_t *payload, uint16_t len);
int         poc_tcp_recv(poc_ctx_t *ctx);

/* poc_udp.c */
int         poc_udp_open(poc_ctx_t *ctx);
void        poc_udp_close(poc_ctx_t *ctx);
int         poc_udp_send(poc_ctx_t *ctx, const uint8_t *data, int len);
int         poc_udp_recv(poc_ctx_t *ctx);

/* poc_msg_build.c */
int         poc_build_login(poc_ctx_t *ctx, uint8_t *buf, int buflen);
int         poc_build_validate(poc_ctx_t *ctx, uint8_t *buf, int buflen);
int         poc_build_heartbeat(poc_ctx_t *ctx, uint8_t *buf, int buflen);
int         poc_build_enter_group(poc_ctx_t *ctx, uint32_t group_id,
                                  uint8_t *buf, int buflen);
int         poc_build_leave_group(poc_ctx_t *ctx, uint8_t *buf, int buflen);
int         poc_build_start_ptt(poc_ctx_t *ctx, uint8_t *buf, int buflen);
int         poc_build_end_ptt(poc_ctx_t *ctx, uint8_t *buf, int buflen);

/* poc_msg_parse.c */
int         poc_parse_message(poc_ctx_t *ctx, const uint8_t *data, int len);

/* poc_codec.c */
int         poc_speex_init(poc_speex_t *s);
void        poc_speex_destroy(poc_speex_t *s);
int         poc_speex_encode(poc_speex_t *s, const int16_t *pcm, uint8_t *out);
int         poc_speex_decode(poc_speex_t *s, const uint8_t *in, int in_len, int16_t *pcm);

/* poc_encrypt.c */
void        poc_encrypt_init(poc_encrypt_t *enc);
void        poc_encrypt_destroy(poc_encrypt_t *enc);
void        poc_encrypt_set_key(poc_encrypt_t *enc, uint8_t key_type,
                                const uint8_t *key, int key_len);
void        poc_encrypt_set_group_key(poc_encrypt_t *enc, uint32_t group_id,
                                      uint8_t key_type, const uint8_t *key, int key_len);
int         poc_encrypt_audio(poc_encrypt_t *enc, uint32_t group_id,
                              const uint8_t *in, int in_len,
                              uint8_t *out, int out_max);
int         poc_decrypt_audio(poc_encrypt_t *enc, uint32_t group_id,
                              const uint8_t *in, int in_len,
                              uint8_t *out, int out_max);

/* poc_gps.c */
int         poc_build_gps_heartbeat(poc_ctx_t *ctx, uint8_t *buf, int buflen);
int         poc_build_gps_aprs(poc_ctx_t *ctx, char *buf, int buflen);
int         poc_gps_update(poc_ctx_t *ctx, float lat, float lng);
void        poc_gps_tick(poc_ctx_t *ctx);

/* poc_fec.c */
void        poc_fec_init(poc_fec_t *fec, int group_size);
void        poc_fec_destroy(poc_fec_t *fec);
int         poc_fec_encode(poc_fec_t *fec, const uint8_t *in, int in_len,
                           uint8_t *out1, uint8_t *out2, int out_max);
int         poc_fec_decode(poc_fec_t *fec, const uint8_t *in, int in_len,
                           int seq_in_group, uint8_t *out, int out_max);

/* poc_msg_build.c — additional builders */
int         poc_build_send_user_msg(poc_ctx_t *ctx, uint32_t user_id,
                                    const char *text, uint8_t *buf, int buflen);
int         poc_build_send_group_msg(poc_ctx_t *ctx, uint32_t group_id,
                                     const char *text, uint8_t *buf, int buflen);

#endif /* POC_INTERNAL_H */
