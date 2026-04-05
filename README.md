# libpoc

C library for **PoC** (Push-to-Talk over Cellular) radio protocol. Implements the binary signaling and audio transport used by common LTE PoC radios (Retevis, TYT, etc.) for group and private push-to-talk over cellular networks.

Connects to a PoC server, authenticates via HMAC-SHA1 challenge-response, joins talk groups, and handles bidirectional half-duplex PTT voice with multi-codec support (Speex, G.711, Opus) over UDP. Includes a server-side API for building custom PoC servers with priority-based PTT floor arbitration. Designed for embedding into repeater controllers, dispatch consoles, and radio gateways.

C11/POSIX, callback-driven, threaded I/O. Dependencies: libspeex, OpenSSL, pthreads. Optional: libopus.

## Table of Contents

- [Features](#features)
- [Building](#building)
- [Quick Start](#quick-start)
  - [Client Example](#client-example)
  - [Server Example](#server-example)
- [Audio Codecs](#audio-codecs)
- [API Reference](#api-reference)
  - [Configuration](#configuration)
  - [Lifecycle](#lifecycle)
  - [Connection](#connection)
  - [Groups](#groups)
  - [PTT Voice](#ptt-voice)
  - [Private Calls](#private-calls)
  - [Temp Groups](#temp-groups)
  - [Monitor (Listen-Only)](#monitor-listen-only)
  - [Dispatcher Control](#dispatcher-control)
  - [GPS](#gps)
  - [Messaging](#messaging)
  - [SOS / Emergency](#sos--emergency)
  - [Voice Messages](#voice-messages)
  - [Encryption](#encryption)
  - [Codec Availability](#codec-availability)
  - [Logging](#logging)
  - [State and Info](#state-and-info)
  - [Callbacks](#callbacks)
  - [Data Types](#data-types)
  - [Error Codes](#error-codes)
- [Server API](#server-api)
  - [Server Configuration](#server-configuration)
  - [Server Lifecycle](#server-lifecycle)
  - [User and Group Management](#user-and-group-management)
  - [Server Start/Stop](#server-startstop)
  - [Server Poll](#server-poll)
  - [Server-Initiated Actions](#server-initiated-actions)
  - [Audio Injection](#audio-injection)
  - [Virtual PTT](#virtual-ptt)
  - [Server Query](#server-query)
  - [Server Callbacks](#server-callbacks)
- [PTT Floor Control](#ptt-floor-control)
- [Threading Model](#threading-model)
- [Audio Flow](#audio-flow)
- [State Machines](#state-machines)
  - [Client Connection State](#client-connection-state)
  - [Client PTT State](#client-ptt-state)
  - [Server Client Lifecycle](#server-client-lifecycle)
  - [Server PTT Floor State](#server-ptt-floor-state-per-group)
  - [Server Group Membership](#server-group-membership)
- [Forward Error Correction](#forward-error-correction)
- [Protocol Overview](#protocol-overview)
- [Test Suite](#test-suite)
- [Example Programs](#example-programs)
- [Project Structure](#project-structure)
- [License](#license)

## Features

- **TCP Signaling** -- Custom MS-framed binary protocol on port 29999 with login, heartbeat, group management, and PTT floor control
- **HMAC-SHA1 Authentication** -- SHA1 password hashing with server challenge-response handshake
- **UDP Voice Transport** -- Real-time audio with sequence numbering and duplicate suppression
- **Multi-Codec Support** -- Pluggable codec abstraction with 10 codec modes: Speex NB/WB/UWB, G.711 u-law/A-law, Opus NB/WB/SWB/FB/32K
- **AES Audio Encryption** -- AES-128/192/256-ECB per-group and per-session keys, parsed from server challenge and user data
- **GPS Position Reporting** -- Periodic position heartbeats over the signaling channel
- **Audio FEC** -- XOR-based forward error correction on both TX and RX paths with configurable group size
- **Text Messaging** -- Group and private text messages with delivery/read receipts and typing indicators
- **Private Calls** -- Direct user-to-user voice calls with automatic state cleanup on disconnect
- **Temp Groups** -- Create, invite, accept, and reject ad-hoc temporary groups
- **SOS / Emergency** -- SOS, man-down, fall detection, and call alarm alerts
- **Server API** -- Full-featured server-side library for building custom PoC servers with TCP/UDP listener, client authentication, group membership, PTT floor arbitration, audio relay, and message routing
- **Priority-Based PTT Pre-emption** -- Higher-priority users can override the current speaker; the server enforces floor priority and fires pre-emption callbacks
- **Floor Timeout** -- Server auto-releases floor after 60s without audio; stale clients reaped after 90s heartbeat timeout
- **Audio Level Metering** -- `on_audio_level` callback fires per frame with RMS level in dBFS for squelch/VOX/UI
- **TLS Signaling** -- Optional TLS wrapping for TCP signaling (UDP audio stays cleartext)
- **Configurable Buffers** -- Configurable TX/RX ring buffer sizes for high-latency or low-latency operation
- **Threaded I/O** -- Dedicated I/O thread with lock-free SPSC ring buffers for zero-copy audio handoff
- **Non-blocking API** -- `poc_poll()` drains event and audio queues from any thread without blocking

## Building

```bash
bash autogen.sh   # generate configure (requires autoconf, automake, libtool)
./configure
make               # builds libpoc.so, libpoc.a, poc_cli, poc_server, and test binaries
make check         # runs 232 unit tests + 15 integration tests
make install       # installs library, headers, and pkg-config file
```

### Dependencies

| Library | Package | Required | Purpose |
|---------|---------|----------|---------|
| libspeex | `libspeex-dev` | Yes | Speex NB/WB/UWB audio codecs |
| OpenSSL | `libssl-dev` | Yes | SHA1, HMAC-SHA1, AES encryption, TLS |
| pthreads | libc | Yes | I/O thread |
| libopus | `libopus-dev` | No | Opus audio codecs (auto-detected by configure) |

When libopus is not installed, `./configure` prints `have_opus=no` and the Opus codec modes (`POC_CODEC_OPUS_*`) gracefully return `false` from `poc_codec_available()`. All other codecs remain fully functional.

### Debian Packages

```bash
dpkg-buildpackage -us -uc -b
```

Produces `libpoc0` (shared library), `libpoc-dev` (headers + pkg-config), and debug symbol packages.

### Using in Your Project

```bash
pkg-config --cflags --libs poc
```

```c
#include <libpoc/poc.h>
#include <libpoc/poc_server.h>  /* for server API */
```

## Quick Start

### Client Example

Complete minimal program that connects, joins a group, and prints incoming PTT audio:

```c
#include <libpoc/poc.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

static volatile int running = 1;
static void handle_sig(int s) { (void)s; running = 0; }

static void on_state(poc_ctx_t *ctx, poc_state_t state, void *ud) {
    if (state == POC_STATE_ONLINE) {
        printf("Online! Entering group...\n");
        poc_enter_group(ctx, *(uint32_t *)ud);
    }
}

static void on_ptt_start(poc_ctx_t *ctx, uint32_t speaker,
                         const char *name, uint32_t gid, void *ud) {
    (void)ctx; (void)ud;
    printf("PTT start: %s (user %u) on group %u\n", name, speaker, gid);
}

static void on_ptt_end(poc_ctx_t *ctx, uint32_t speaker,
                       uint32_t gid, void *ud) {
    (void)ctx; (void)ud;
    printf("PTT end: user %u on group %u\n", speaker, gid);
}

static void on_audio(poc_ctx_t *ctx, const poc_audio_frame_t *f, void *ud) {
    (void)ctx; (void)ud;
    printf("Audio: %d samples from user %u\n", f->n_samples, f->speaker_id);
    /* Write f->samples to your audio output here */
}

int main(void) {
    signal(SIGINT, handle_sig);
    uint32_t group_id = 100;

    poc_config_t cfg = {
        .server_host  = "server.example.com",
        .server_port  = 29999,
        .account      = "12345678",
        .password     = "mypassword",
    };

    poc_callbacks_t cb = {
        .on_state_change = on_state,
        .on_ptt_start    = on_ptt_start,
        .on_ptt_end      = on_ptt_end,
        .on_audio_frame  = on_audio,
        .userdata        = &group_id,
    };

    poc_ctx_t *ctx = poc_create(&cfg, &cb);
    poc_connect(ctx);

    while (running)
        poc_poll(ctx, 50);

    poc_destroy(ctx);
    return 0;
}
```

Compile:
```bash
gcc -o my_poc my_poc.c $(pkg-config --cflags --libs poc)
```

### Server Example

Minimal server that accepts two users and relays PTT audio between them:

```c
#include <libpoc/poc.h>
#include <libpoc/poc_server.h>
#include <stdio.h>
#include <signal.h>

static volatile int running = 1;
static void handle_sig(int s) { (void)s; running = 0; }

static void on_connect(poc_server_t *srv, uint32_t uid,
                       const char *acct, void *ud) {
    (void)srv; (void)ud;
    printf("Connected: %s (user %u)\n", acct, uid);
}

static void on_preempted(poc_server_t *srv, uint32_t old_uid,
                         uint32_t new_uid, uint32_t gid, void *ud) {
    (void)srv; (void)ud;
    printf("PTT pre-empted: user %u took floor from %u on group %u\n",
           new_uid, old_uid, gid);
}

int main(void) {
    signal(SIGINT, handle_sig);

    poc_server_config_t cfg = { .port = 29999 };
    poc_server_callbacks_t cb = {
        .on_client_connect = on_connect,
        .on_ptt_preempted  = on_preempted,
    };

    poc_server_t *srv = poc_server_create(&cfg, &cb);

    /* Add users with PTT priority (higher = more priority) */
    poc_server_add_user(srv, &(poc_server_user_t){
        .account = "dispatch", .password = "secret",
        .name = "Dispatch", .user_id = 1000, .priority = 10 });
    poc_server_add_user(srv, &(poc_server_user_t){
        .account = "field01", .password = "secret",
        .name = "Field Unit 1", .user_id = 2000, .priority = 0 });

    poc_server_add_group(srv, &(poc_server_group_t){
        .id = 100, .name = "Operations" });

    poc_server_start(srv);
    printf("Server running on port 29999\n");

    while (running)
        poc_server_poll(srv, 50);

    poc_server_destroy(srv);
    return 0;
}
```

## Audio Codecs

libpoc uses a pluggable codec abstraction layer (`poc_codec_t` vtable in `src/poc_codec.h`). Each codec implements encode/decode/destroy via function pointers, and all codecs use a uniform 20ms frame size.

### Supported Codecs

| Enum | Value | Sample Rate | Frame Samples | Encoded Size | Dependency |
|------|-------|-------------|---------------|--------------|------------|
| `POC_CODEC_SPEEX_NB` | 0 | 8000 Hz | 160 | ~20 bytes | libspeex |
| `POC_CODEC_SPEEX_WB` | 1 | 16000 Hz | 320 | ~46 bytes | libspeex |
| `POC_CODEC_SPEEX_UWB` | 2 | 32000 Hz | 640 | ~70 bytes | libspeex |
| `POC_CODEC_PCMU` | 3 | 8000 Hz | 160 | 160 bytes | built-in |
| `POC_CODEC_PCMA` | 4 | 8000 Hz | 160 | 160 bytes | built-in |
| `POC_CODEC_OPUS_NB` | 5 | 8000 Hz | 160 | variable | libopus |
| `POC_CODEC_OPUS_WB` | 6 | 16000 Hz | 320 | variable | libopus |
| `POC_CODEC_OPUS_SWB` | 7 | 24000 Hz | 480 | variable | libopus |
| `POC_CODEC_OPUS_FB` | 8 | 48000 Hz | 960 | variable | libopus |
| `POC_CODEC_OPUS_32K` | 9 | 32000 Hz | 640 | variable | libopus |

`POC_CODEC_SPEEX` is a backward-compatible alias for `POC_CODEC_SPEEX_NB` (value 0).

All codecs produce 20ms frames. The frame sample count varies with sample rate: `sample_rate * 20 / 1000`.

- **Speex** codecs produce fixed-size compressed output using quality 4.
- **G.711** codecs use 1:1 byte mapping (mu-law or A-law), zero compression latency.
- **Opus** codecs use VBR (variable bitrate), producing different output sizes for silence vs. active speech. Opus 32K resamples to 48kHz internally.

### Runtime Availability

```c
bool poc_codec_available(int codec_type);
```

Query at runtime whether a codec is available. Speex and G.711 codecs are always available. Opus codecs return `true` only when libpoc was compiled with libopus support (`HAVE_OPUS`).

### Codec Abstraction

The internal `poc_codec_t` struct provides a vtable interface:

```c
struct poc_codec {
    int  (*encode)(poc_codec_t *c, const int16_t *pcm, int n_samples,
                   uint8_t *out, int out_max);
    int  (*decode)(poc_codec_t *c, const uint8_t *in, int in_len,
                   int16_t *pcm, int pcm_max);
    void (*destroy)(poc_codec_t *c);

    int  sample_rate;       /* Hz: 8000, 16000, 24000, 32000, 48000 */
    int  frame_samples;     /* samples per frame */
    int  frame_ms;          /* ms per frame (always 20) */
    int  max_encoded_size;  /* worst-case encoded bytes per frame */
    int  codec_type;        /* POC_CODEC_* enum value */
};
```

Codec instances are created with `poc_codec_create(int codec_type)` and destroyed with `poc_codec_destroy()`. The library manages codec lifecycle internally -- callers select a codec via the `poc_config_t.codec` field.

## API Reference

All client functions are declared in `<libpoc/poc.h>`. The library uses an opaque context (`poc_ctx_t`).

### Configuration

```c
typedef struct {
    const char *server_host;     /* Server hostname or IP address */
    uint16_t    server_port;     /* Server port (default: 29999) */
    const char *account;         /* Account ID string */
    const char *password;        /* Raw password (library SHA1-hashes internally) */
    const char *imei;            /* Device IMEI (optional, may be NULL) */
    const char *iccid;           /* SIM ICCID (optional, may be NULL) */
    int         codec;           /* POC_CODEC_* enum (default: POC_CODEC_SPEEX_NB) */
    int         heartbeat_ms;    /* Heartbeat interval in ms (0 = default 30000) */
    bool        enable_fec;      /* Enable audio forward error correction */
    int         fec_group_size;  /* FEC group size: N data + 1 parity (0 = default 3) */
    int         gps_interval_ms; /* GPS report interval in ms (0 = default 60000) */
    int         rx_ring_frames;  /* RX ring capacity (0 = default 64) */
    int         tx_ring_frames;  /* TX ring capacity (0 = default 64) */
    bool        tls;             /* Enable TLS for TCP signaling */
    const char *tls_ca_path;     /* CA cert file (NULL = system default) */
    bool        tls_verify;      /* Verify server certificate (default true) */
} poc_config_t;
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `server_host` | Yes | -- | Server hostname or IP |
| `server_port` | No | 29999 | TCP/UDP port |
| `account` | Yes | -- | Account ID for authentication |
| `password` | Yes | -- | Plaintext password (SHA1 hashed internally) |
| `imei` | No | NULL | Device IMEI sent during login |
| `iccid` | No | NULL | SIM ICCID sent during login |
| `codec` | No | `POC_CODEC_SPEEX_NB` | Audio codec selection (see [Audio Codecs](#audio-codecs)) |
| `heartbeat_ms` | No | 30000 | Keepalive interval (ms) |
| `enable_fec` | No | false | Enable audio FEC |
| `fec_group_size` | No | 3 | FEC data frames per parity frame |
| `gps_interval_ms` | No | 60000 | GPS report interval (ms) |
| `rx_ring_frames` | No | 64 | RX audio ring capacity (~1.28s at 64 frames) |
| `tx_ring_frames` | No | 64 | TX audio ring capacity (~1.28s at 64 frames) |
| `tls` | No | false | Enable TLS for TCP signaling |
| `tls_ca_path` | No | NULL | CA certificate path (NULL = system default) |
| `tls_verify` | No | true | Verify server certificate |

### Lifecycle

#### `poc_create`

```c
poc_ctx_t *poc_create(const poc_config_t *cfg, const poc_callbacks_t *cb);
```

Create a new PoC context. Copies all config strings internally. Initializes the selected audio codec, ring buffers, and event queues. Does not connect.

**Parameters:**
- `cfg` -- Server and codec configuration. `server_host`, `account`, and `password` are required.
- `cb` -- Callback struct. All callback pointers are optional (NULL = not called). The `userdata` field is passed to every callback.

**Returns:** Opaque context pointer, or NULL on error.

#### `poc_destroy`

```c
void poc_destroy(poc_ctx_t *ctx);
```

Disconnect (if connected), stop I/O thread, free all resources. Safe to call with NULL. After this call, `ctx` is invalid.

### Connection

#### `poc_connect`

```c
int poc_connect(poc_ctx_t *ctx);
```

Resolve the server hostname, establish a TCP connection (optionally wrapped in TLS), send the login message, open a UDP socket for audio, and start the I/O thread. The login handshake (challenge-response) completes asynchronously -- use the `on_state_change` callback to detect when `POC_STATE_ONLINE` is reached.

**Returns:** `POC_OK` on successful connection initiation, or an error code if the TCP connection fails immediately. Login failures are reported via `on_login_error`.

#### `poc_disconnect`

```c
int poc_disconnect(poc_ctx_t *ctx);
```

Stop the I/O thread, close TCP and UDP sockets, flush all ring buffers, and transition to `POC_STATE_OFFLINE`. Fires `on_state_change(POC_STATE_OFFLINE)` on the next `poc_poll()`.

#### `poc_poll`

```c
int poc_poll(poc_ctx_t *ctx, int timeout_ms);
```

Drain the event queue and audio ring buffer, firing callbacks for each pending item. This is the **only** function that fires callbacks. Call it regularly from your main or audio thread.

**Parameters:**
- `timeout_ms` -- Currently ignored (always non-blocking). Reserved for future use.

**Returns:** `POC_OK`, or `POC_ERR_STATE` if context is NULL.

**Important:** Callbacks fire synchronously inside `poc_poll()`. Keep callback handlers fast -- long-running work will block audio delivery.

### Groups

#### `poc_enter_group`

```c
int poc_enter_group(poc_ctx_t *ctx, uint32_t group_id);
```

Join a talk group. After entering, incoming PTT audio from this group will be delivered via `on_audio_frame`. Only one group can be active at a time.

**Returns:** `POC_OK` or `POC_ERR_STATE` if not online.

#### `poc_leave_group`

```c
int poc_leave_group(poc_ctx_t *ctx);
```

Leave the current group. Stops receiving audio and PTT notifications for this group.

#### `poc_get_group_count`

```c
int poc_get_group_count(const poc_ctx_t *ctx);
```

**Returns:** Number of groups available to this account (populated after login).

#### `poc_get_groups`

```c
int poc_get_groups(const poc_ctx_t *ctx, poc_group_t *out, int max);
```

Copy up to `max` group descriptors into the caller-provided array.

**Returns:** Number of groups actually copied.

### PTT Voice

#### `poc_ptt_start`

```c
int poc_ptt_start(poc_ctx_t *ctx);
```

Request the PTT floor (permission to transmit) from the server. The result is delivered via `on_ptt_granted(true/false)`. If granted, begin sending audio with `poc_ptt_send_audio`.

**Returns:** `POC_OK` or `POC_ERR_STATE` if not online.

#### `poc_ptt_stop`

```c
int poc_ptt_stop(poc_ctx_t *ctx);
```

Release the PTT floor and stop transmitting. Any remaining audio in the TX ring is drained by the I/O thread before the release message is sent.

#### `poc_ptt_send_audio`

```c
int poc_ptt_send_audio(poc_ctx_t *ctx, const int16_t *pcm, int n_samples);
```

Push PCM audio into the TX ring buffer. The I/O thread encodes with the configured codec, optionally encrypts and FEC-wraps, then sends via UDP.

**Parameters:**
- `pcm` -- 16-bit signed PCM samples at the codec's sample rate.
- `n_samples` -- Number of samples. Must be a multiple of the codec's frame size (e.g., 160 for 8kHz codecs, 320 for 16kHz). Partial frames at the end are silently discarded.

Audio is queued, not sent synchronously. If the TX ring is full (~1.28s backlog), excess frames are dropped with a log message.

**Returns:** `POC_OK` or `POC_ERR_STATE` if not currently transmitting.

### Private Calls

#### `poc_call_user`

```c
int poc_call_user(poc_ctx_t *ctx, uint32_t user_id);
```

Initiate a private (one-to-one) voice call to a specific user. After calling this, use `poc_ptt_send_audio` to send voice, same as group PTT.

#### `poc_call_end`

```c
int poc_call_end(poc_ctx_t *ctx);
```

End the current private call. Equivalent to `poc_ptt_stop`.

### Temp Groups

#### `poc_invite_tmp_group`

```c
int poc_invite_tmp_group(poc_ctx_t *ctx, const uint32_t *user_ids, int count);
```

Create a temporary (ad-hoc) group and invite the specified users.

#### `poc_accept_tmp_group`

```c
int poc_accept_tmp_group(poc_ctx_t *ctx, uint32_t group_id);
```

Accept an invitation to a temporary group. The invitation is delivered via the `on_tmp_group_invite` callback.

#### `poc_reject_tmp_group`

```c
int poc_reject_tmp_group(poc_ctx_t *ctx, uint32_t group_id);
```

Reject an invitation to a temporary group.

### Monitor (Listen-Only)

#### `poc_monitor_group` / `poc_unmonitor_group`

```c
int poc_monitor_group(poc_ctx_t *ctx, uint32_t group_id);
int poc_unmonitor_group(poc_ctx_t *ctx, uint32_t group_id);
```

Add or remove a group from the listen-only monitor set. Monitored groups deliver audio via `on_audio_frame` but the user does not appear as an active member.

### Dispatcher Control

#### `poc_pull_users_to_group`

```c
int poc_pull_users_to_group(poc_ctx_t *ctx, const uint32_t *user_ids, int count);
```

Force one or more users into the current active group. Requires dispatcher privilege.

#### `poc_force_user_exit`

```c
int poc_force_user_exit(poc_ctx_t *ctx, const uint32_t *user_ids, int count);
```

Force one or more users to disconnect. Requires dispatcher privilege.

### GPS

#### `poc_set_gps`

```c
int poc_set_gps(poc_ctx_t *ctx, float lat, float lng);
```

Set the device's GPS position. The position is sent to the server automatically at the interval configured by `gps_interval_ms`. The I/O thread handles the timing -- just call this whenever you have a new fix.

**Parameters:**
- `lat` -- Latitude in decimal degrees (positive = North).
- `lng` -- Longitude in decimal degrees (positive = East).

### Messaging

#### `poc_send_group_msg`

```c
int poc_send_group_msg(poc_ctx_t *ctx, uint32_t group_id, const char *msg);
```

Send a text message to all members of a group.

#### `poc_send_user_msg`

```c
int poc_send_user_msg(poc_ctx_t *ctx, uint32_t user_id, const char *msg);
```

Send a private text message to a specific user.

Both return `POC_OK` or `POC_ERR_STATE` if not online. Incoming messages are delivered via `on_message`.

#### `poc_send_read_receipt`

```c
int poc_send_read_receipt(poc_ctx_t *ctx, uint32_t to_user_id);
```

Send a read receipt to a user. Delivery and read receipts are received via the `on_msg_delivered` and `on_msg_read` callbacks.

#### `poc_send_typing`

```c
int poc_send_typing(poc_ctx_t *ctx, uint32_t to_user_id, bool typing);
```

Send a typing indicator to a user. Incoming typing indicators arrive via the `on_typing` callback.

### SOS / Emergency

```c
#define POC_ALERT_SOS         0
#define POC_ALERT_MANDOWN     1
#define POC_ALERT_FALL        2
#define POC_ALERT_CALL_ALARM  3
```

#### `poc_send_sos`

```c
int poc_send_sos(poc_ctx_t *ctx, int alert_type);
```

Send an emergency alert. The `alert_type` selects the alert class (SOS, man-down, fall detection, or call alarm).

#### `poc_cancel_sos`

```c
int poc_cancel_sos(poc_ctx_t *ctx);
```

Cancel an active SOS alert.

### Voice Messages

#### `poc_request_voice_message`

```c
int poc_request_voice_message(poc_ctx_t *ctx, uint64_t note_id);
```

Request playback of a stored voice message by its note ID. Incoming voice message notifications are delivered via the `on_voice_message` callback.

### Encryption

Audio encryption is configured per-group by the server during the login handshake. The library handles encrypt/decrypt transparently in the I/O thread -- no caller action needed.

#### `poc_is_encrypted`

```c
bool poc_is_encrypted(const poc_ctx_t *ctx);
```

**Returns:** true if audio encryption is active for the current session.

Supported ciphers (selected by server):
- **AES-128/192/256-ECB** (type 0x02)
- **SM4-ECB** (type 0x06, Chinese national standard)

Per-group keys are delivered in the login response. Session-level keys are used for private calls.

### Codec Availability

```c
bool poc_codec_available(int codec_type);
```

**Returns:** true if the specified codec type is available at runtime. See [Audio Codecs](#audio-codecs) for details.

### Logging

```c
typedef void (*poc_log_fn)(int level, const char *msg, void *userdata);

void poc_set_log_callback(poc_log_fn fn, void *userdata);
void poc_set_log_level(int level);
```

| Level | Constant | Description |
|-------|----------|-------------|
| 0 | `POC_LOG_ERROR` | Errors only |
| 1 | `POC_LOG_WARNING` | Warnings and errors |
| 2 | `POC_LOG_INFO` | Informational messages |
| 3 | `POC_LOG_DEBUG` | Verbose debug output |

Set a custom log callback to integrate with your application's logging. Set the log level to filter output. The default log level is `POC_LOG_INFO`.

### State and Info

#### `poc_get_state`

```c
poc_state_t poc_get_state(const poc_ctx_t *ctx);
```

**Returns:** Current connection state. Thread-safe (uses atomic read).

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | `POC_STATE_OFFLINE` | Not connected |
| 1 | `POC_STATE_CONNECTING` | TCP connected, login in progress |
| 2 | `POC_STATE_ONLINE` | Authenticated, ready for PTT |
| 3 | `POC_STATE_LOGOUT` | Logging out |

#### `poc_get_user_id`

```c
uint32_t poc_get_user_id(const poc_ctx_t *ctx);
```

**Returns:** Server-assigned user ID (set after successful login), or 0 if not logged in.

#### `poc_get_account`

```c
const char *poc_get_account(const poc_ctx_t *ctx);
```

**Returns:** The account string passed at creation, or `""` if ctx is NULL.

#### `poc_get_user_count` / `poc_get_users`

```c
int poc_get_user_count(const poc_ctx_t *ctx);
int poc_get_users(const poc_ctx_t *ctx, poc_user_t *out, int max);
```

Query the list of users received from the server during login.

#### `poc_set_status`

```c
int poc_set_status(poc_ctx_t *ctx, int status);
```

Set the user's presence status. Predefined status constants:

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | `POC_STATUS_OFFLINE` | Offline |
| 1 | `POC_STATUS_ONLINE` | Online |
| 2 | `POC_STATUS_AWAY` | Away |
| 3 | `POC_STATUS_BUSY` | Busy |
| 4 | `POC_STATUS_LUNCH` | Lunch |
| 5 | `POC_STATUS_DND` | Do not disturb |

### Callbacks

```c
typedef struct {
    void (*on_state_change)(poc_ctx_t *ctx, poc_state_t state, void *ud);
    void (*on_login_error)(poc_ctx_t *ctx, int code, const char *msg, void *ud);
    void (*on_groups_updated)(poc_ctx_t *ctx, const poc_group_t *groups,
                              int count, void *ud);
    void (*on_ptt_start)(poc_ctx_t *ctx, uint32_t speaker_id, const char *name,
                         uint32_t group_id, void *ud);
    void (*on_ptt_end)(poc_ctx_t *ctx, uint32_t speaker_id,
                       uint32_t group_id, void *ud);
    void (*on_audio_frame)(poc_ctx_t *ctx, const poc_audio_frame_t *frame,
                           void *ud);
    void (*on_ptt_granted)(poc_ctx_t *ctx, bool granted, void *ud);
    void (*on_message)(poc_ctx_t *ctx, uint32_t from_id, const char *text,
                       void *ud);
    void (*on_user_status)(poc_ctx_t *ctx, uint32_t user_id, int status,
                           void *ud);
    void (*on_tmp_group_invite)(poc_ctx_t *ctx, uint32_t group_id,
                                uint32_t inviter_id, void *ud);
    void (*on_pull_to_group)(poc_ctx_t *ctx, uint32_t group_id, void *ud);
    void (*on_voice_message)(poc_ctx_t *ctx, uint32_t from_id, uint64_t note_id,
                             const char *description, void *ud);
    void (*on_sos)(poc_ctx_t *ctx, uint32_t user_id, int alert_type, void *ud);
    void (*on_msg_delivered)(poc_ctx_t *ctx, uint32_t user_id, void *ud);
    void (*on_msg_read)(poc_ctx_t *ctx, uint32_t user_id, void *ud);
    void (*on_typing)(poc_ctx_t *ctx, uint32_t user_id, bool typing, void *ud);
    void (*on_audio_level)(poc_ctx_t *ctx, uint32_t speaker_id,
                           float rms_db, void *ud);
    void *userdata;
} poc_callbacks_t;
```

All callbacks are optional (NULL = not called). All fire from the thread calling `poc_poll()`.

| Callback | When | Key Parameters |
|----------|------|----------------|
| `on_state_change` | Connection state transitions | `state`: new `poc_state_t` value |
| `on_login_error` | Authentication or login timeout | `code`: error code, `msg`: description |
| `on_groups_updated` | Group list received or changed | `groups`: array, `count`: length |
| `on_ptt_start` | Someone begins talking | `speaker_id`, `name`, `group_id` |
| `on_ptt_end` | Speaker releases floor | `speaker_id`, `group_id` |
| `on_audio_frame` | Decoded audio frame ready | `frame->samples`: PCM at codec sample rate |
| `on_ptt_granted` | Floor request result | `granted`: true if you may transmit |
| `on_message` | Text message received | `from_id`: sender, `text`: message body |
| `on_user_status` | User presence changed | `user_id`, `status`: new status value |
| `on_tmp_group_invite` | Temp group invitation received | `group_id`, `inviter_id` |
| `on_pull_to_group` | Forced into a group by dispatcher | `group_id` |
| `on_voice_message` | Voice message notification | `from_id`, `note_id`, `description` |
| `on_sos` | Emergency alert received | `user_id`, `alert_type` |
| `on_msg_delivered` | Message delivery confirmation | `user_id` |
| `on_msg_read` | Message read receipt | `user_id` |
| `on_typing` | Typing indicator | `user_id`, `typing`: true/false |
| `on_audio_level` | RX audio level per frame | `speaker_id`, `rms_db`: level in dBFS (0.0 = full scale, -96.0 = silence) |

### Data Types

#### `poc_group_t`

```c
typedef struct {
    uint32_t id;           /* Group ID */
    char     name[64];     /* Display name */
    int      user_count;   /* Number of members */
    bool     is_active;    /* Currently active group */
    bool     is_tmp;       /* Temporary (ad-hoc) group */
} poc_group_t;
```

#### `poc_user_t`

```c
typedef struct {
    uint32_t id;           /* User ID */
    char     account[32];  /* Account string */
    char     name[64];     /* Display name */
    int      status;       /* 0 = offline, 1 = online, ... */
    uint32_t privilege;    /* Permission bitmask */
} poc_user_t;
```

#### `poc_audio_frame_t`

```c
typedef struct {
    const int16_t *samples;    /* PCM sample buffer */
    int            n_samples;  /* Codec-dependent (160, 320, 480, 640, 960) */
    int            sample_rate;/* Codec-dependent (8000, 16000, 24000, 32000, 48000) */
    uint32_t       speaker_id; /* User ID of the speaker */
    uint32_t       group_id;   /* Group this audio belongs to */
} poc_audio_frame_t;
```

The `samples` pointer is valid only for the duration of the `on_audio_frame` callback. Copy the data if you need it later. Frame size and sample rate depend on the active codec -- use the struct fields at runtime rather than hardcoded values.

### Error Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `POC_OK` | Success |
| -1 | `POC_ERR` | General error |
| -2 | `POC_ERR_AUTH` | Authentication failed |
| -3 | `POC_ERR_TIMEOUT` | Operation timed out |
| -4 | `POC_ERR_NETWORK` | Network error (connection lost, DNS failure) |
| -5 | `POC_ERR_STATE` | Invalid state (e.g., PTT while offline) |
| -6 | `POC_ERR_NOMEM` | Memory allocation failed |

All functions that return `int` use these codes. `POC_OK` (0) is success, negative values are errors.

## Server API

The server API is declared in `<libpoc/poc_server.h>`. It provides a complete PoC protocol server: TCP/UDP listener, client authentication, group membership, PTT floor arbitration with priority-based pre-emption, audio relay, and message routing.

The application provides user/group configuration and callbacks; the library handles all protocol details. The server uses the same I/O thread architecture as the client, with an event queue drained by `poc_server_poll()`.

### Server Configuration

```c
typedef struct {
    const char *bind_addr;       /* NULL or "" = "0.0.0.0" */
    uint16_t    port;            /* 0 = default 29999 */
    int         max_clients;     /* 0 = default 64 */
    bool        tls;             /* Enable TLS */
    const char *tls_cert_path;   /* Server certificate PEM */
    const char *tls_key_path;    /* Server private key PEM */
} poc_server_config_t;
```

| Field | Default | Description |
|-------|---------|-------------|
| `bind_addr` | `"0.0.0.0"` | Bind address for TCP/UDP listeners |
| `port` | 29999 | Listen port |
| `max_clients` | 64 | Maximum simultaneous client connections |
| `tls` | false | Enable TLS for TCP signaling |
| `tls_cert_path` | -- | Path to server certificate PEM file |
| `tls_key_path` | -- | Path to server private key PEM file |

### Server Lifecycle

#### `poc_server_create`

```c
poc_server_t *poc_server_create(const poc_server_config_t *cfg,
                                const poc_server_callbacks_t *cb);
```

Create a new server context. Does not start listening -- call `poc_server_start()` after adding users and groups.

**Returns:** Opaque server pointer, or NULL on error.

#### `poc_server_destroy`

```c
void poc_server_destroy(poc_server_t *srv);
```

Stop the server (if running), disconnect all clients, free all resources. Safe to call with NULL.

### User and Group Management

Users and groups can be added before or after the server is started.

#### `poc_server_add_user`

```c
typedef struct {
    const char *account;
    const char *name;            /* Display name (NULL = use account) */
    const char *password;        /* Raw password (library SHA1-hashes internally) */
    uint32_t    user_id;
    uint32_t    priority;        /* PTT floor priority (0=normal, higher=more priority) */
} poc_server_user_t;

int poc_server_add_user(poc_server_t *srv, const poc_server_user_t *user);
```

Register a user with the server. The `priority` field controls PTT floor pre-emption: a user with higher priority can take the floor from a user with lower priority. Equal or lower priority users are denied when the floor is held. See [PTT Floor Control](#ptt-floor-control).

#### `poc_server_add_group`

```c
typedef struct {
    uint32_t    id;
    const char *name;
    const uint32_t *member_ids;  /* Allowed user IDs (NULL = open group) */
    int         member_count;    /* 0 = open to all */
} poc_server_group_t;

int poc_server_add_group(poc_server_t *srv, const poc_server_group_t *group);
```

Register a group. If `member_ids` is NULL and `member_count` is 0, the group is open to all users.

#### `poc_server_remove_user` / `poc_server_remove_group`

```c
int poc_server_remove_user(poc_server_t *srv, uint32_t user_id);
int poc_server_remove_group(poc_server_t *srv, uint32_t group_id);
```

Remove a user or group from the server configuration.

### Server Start/Stop

#### `poc_server_start`

```c
int poc_server_start(poc_server_t *srv);
```

Bind TCP and UDP sockets and start the I/O thread. Clients can now connect.

**Returns:** `POC_OK` or error code.

#### `poc_server_stop`

```c
int poc_server_stop(poc_server_t *srv);
```

Stop the I/O thread and close listener sockets. Connected clients are disconnected.

### Server Poll

#### `poc_server_poll`

```c
int poc_server_poll(poc_server_t *srv, int timeout_ms);
```

Drain the server event queue and fire callbacks. Must be called regularly from the main thread. This is the **only** function that fires server callbacks.

### Server-Initiated Actions

#### `poc_server_send_message`

```c
int poc_server_send_message(poc_server_t *srv, uint32_t from_id,
                            uint32_t target_id, const char *text);
```

Send a text message from `from_id` to `target_id` (user or group).

#### `poc_server_broadcast`

```c
int poc_server_broadcast(poc_server_t *srv, const char *text);
```

Send a text message to all connected clients.

#### `poc_server_kick`

```c
int poc_server_kick(poc_server_t *srv, uint32_t user_id);
```

Disconnect a client by user ID. Sends a force-exit message before closing the connection.

#### `poc_server_pull_to_group`

```c
int poc_server_pull_to_group(poc_server_t *srv, uint32_t user_id,
                             uint32_t group_id);
```

Force a connected user into a specific group.

#### `poc_server_send_sos`

```c
int poc_server_send_sos(poc_server_t *srv, uint32_t user_id,
                        int alert_type);
```

Broadcast an SOS alert on behalf of a user.

### Audio Injection

#### `poc_server_inject_audio`

```c
int poc_server_inject_audio(poc_server_t *srv, uint32_t group_id,
                            uint32_t virtual_user_id,
                            const int16_t *pcm, int n_samples);
```

Inject PCM audio into a group as a virtual user. Use this to bridge external audio sources (e.g., SIP, analog radio) into the PoC network. The server encodes and distributes the audio to all group members.

**Parameters:**
- `group_id` -- Target group.
- `virtual_user_id` -- User ID to appear as the speaker.
- `pcm` -- 16-bit signed PCM samples at 8kHz.
- `n_samples` -- Number of samples (must be a multiple of 160).

### Virtual PTT

#### `poc_server_start_ptt_for` / `poc_server_end_ptt_for`

```c
int poc_server_start_ptt_for(poc_server_t *srv, uint32_t group_id,
                             uint32_t virtual_user_id, const char *name);
int poc_server_end_ptt_for(poc_server_t *srv, uint32_t group_id,
                           uint32_t virtual_user_id);
```

Send PTT start/end notifications as a virtual user. Use with `poc_server_inject_audio` to provide a complete bridged audio experience -- clients see the PTT indicator and hear the audio.

### Server Query

#### `poc_server_client_count`

```c
int poc_server_client_count(const poc_server_t *srv);
```

**Returns:** Number of currently connected and authenticated clients.

#### `poc_server_get_clients`

```c
int poc_server_get_clients(const poc_server_t *srv,
                           poc_user_t *out, int max);
```

Copy up to `max` connected client descriptors into the caller-provided array.

**Returns:** Number of clients actually copied.

#### `poc_server_is_user_online`

```c
bool poc_server_is_user_online(const poc_server_t *srv, uint32_t user_id);
```

**Returns:** true if the specified user is currently connected.

### Server Callbacks

```c
typedef struct {
    void (*on_client_connect)(poc_server_t *srv, uint32_t user_id,
                              const char *account, void *ud);
    void (*on_client_disconnect)(poc_server_t *srv, uint32_t user_id,
                                 const char *account, void *ud);
    bool (*on_ptt_request)(poc_server_t *srv, uint32_t user_id,
                           uint32_t group_id, void *ud);
    void (*on_ptt_end)(poc_server_t *srv, uint32_t user_id,
                       uint32_t group_id, void *ud);
    void (*on_ptt_preempted)(poc_server_t *srv, uint32_t old_user_id,
                             uint32_t new_user_id, uint32_t group_id, void *ud);
    void (*on_message)(poc_server_t *srv, uint32_t from_id,
                       uint32_t target_id, const char *text, void *ud);
    void (*on_sos)(poc_server_t *srv, uint32_t user_id,
                   int alert_type, void *ud);
    void (*on_group_enter)(poc_server_t *srv, uint32_t user_id,
                           uint32_t group_id, void *ud);
    void (*on_group_leave)(poc_server_t *srv, uint32_t user_id,
                           uint32_t group_id, void *ud);
    void (*on_audio)(poc_server_t *srv, uint32_t speaker_id,
                     uint32_t group_id, const int16_t *pcm,
                     int n_samples, void *ud);
    void *userdata;
} poc_server_callbacks_t;
```

All server callbacks are optional and fire from the thread calling `poc_server_poll()`.

| Callback | When | Key Parameters |
|----------|------|----------------|
| `on_client_connect` | Client completes authentication | `user_id`, `account` |
| `on_client_disconnect` | Client disconnects or is kicked | `user_id`, `account` |
| `on_ptt_request` | Client requests PTT floor | `user_id`, `group_id`. Return `true` to grant, `false` to deny. If NULL, the library auto-grants (first-come-first-served with priority pre-emption). |
| `on_ptt_end` | Client releases PTT floor | `user_id`, `group_id` |
| `on_ptt_preempted` | Higher-priority user takes floor | `old_user_id`: pre-empted speaker, `new_user_id`: new speaker, `group_id` |
| `on_message` | Client sends a text message | `from_id`, `target_id`, `text` |
| `on_sos` | Client sends emergency alert | `user_id`, `alert_type` |
| `on_group_enter` | Client enters a group | `user_id`, `group_id` |
| `on_group_leave` | Client leaves a group | `user_id`, `group_id` |
| `on_audio` | Client sends voice audio | `speaker_id`, `group_id`, `pcm`: decoded 8kHz PCM, `n_samples` |

## PTT Floor Control

The server manages PTT floor arbitration using a priority-based pre-emption model.

### How It Works

1. **Floor is free:** The first user to request PTT is granted the floor.
2. **Floor is held, requestor has higher priority:** The current speaker is pre-empted. The server sends a PTT-end to the current speaker, grants the floor to the new speaker, and fires the `on_ptt_preempted` callback.
3. **Floor is held, requestor has equal or lower priority:** The request is denied. The requestor receives `on_ptt_granted(false)`.
4. **Floor release:** When the speaker calls `poc_ptt_stop`, the floor becomes free for the next request.

### Priority Assignment

Priority is assigned per-user via the `priority` field of `poc_server_user_t`:

```c
poc_server_add_user(srv, &(poc_server_user_t){
    .account  = "dispatch",
    .password = "secret",
    .user_id  = 1000,
    .priority = 10,    /* high priority — can pre-empt field units */
});

poc_server_add_user(srv, &(poc_server_user_t){
    .account  = "field01",
    .password = "secret",
    .user_id  = 2000,
    .priority = 0,     /* normal priority */
});
```

- `priority = 0` is normal (default).
- Higher values have more priority.
- A user with `priority = 10` can pre-empt a user with `priority = 0`.
- Users with equal priority follow first-come-first-served -- no pre-emption.

### Floor Timeout

If a client holds the floor for 60 seconds without sending audio, the server automatically releases the floor and broadcasts a PTT-end notification to the group. This prevents a stuck floor from a crashed or unresponsive client.

Heartbeat timeout is 90 seconds — if a client sends no heartbeats for 90s, the server disconnects it (releasing any held floor).

### Custom Floor Logic

Set the `on_ptt_request` callback to implement custom floor control logic beyond priority-based pre-emption:

```c
bool my_ptt_policy(poc_server_t *srv, uint32_t user_id,
                   uint32_t group_id, void *ud) {
    /* Example: deny PTT to a specific user */
    if (user_id == BLOCKED_USER_ID) return false;
    /* Otherwise, let the library's default priority logic decide */
    return true;
}
```

### Audio Level Metering

The client fires `on_audio_level` after each received audio frame with the RMS level in dBFS:

```c
void on_level(poc_ctx_t *ctx, uint32_t speaker_id, float rms_db, void *ud) {
    /* rms_db: 0.0 = full scale, -96.0 = silence */
    printf("speaker %u: %.1f dBFS\n", speaker_id, rms_db);
}
```

This avoids the caller having to compute levels from raw PCM. Useful for squelch, VOX, and UI metering.

If `on_ptt_request` is NULL, the library uses automatic first-come-first-served with priority pre-emption.

## Threading Model

```
┌──────────────────────────┐       ┌──────────────────────────┐
│       I/O Thread         │       │     Your Thread          │
│                          │       │                          │
│  poll(TCP, UDP, wakeup)  │       │  poc_poll(ctx, 0)        │
│  ├─ TCP recv → deframe   │       │  ├─ drain evt_queue      │
│  │  → parse → evt_queue ─┼──────▶│  │  → fire callbacks     │
│  ├─ UDP recv → decode    │       │  ├─ drain rx_ring        │
│  │  → decrypt → rx_ring ─┼──────▶│  │  → on_audio_frame()   │
│  ├─ drain tx_ring ◀──────┼───────┼──┤                       │
│  │  → encode → encrypt   │       │  │  poc_ptt_send_audio() │
│  │  → UDP send           │       │  │  → push to tx_ring    │
│  ├─ heartbeat timer      │       │  └────────────────────── │
│  └─ GPS timer            │       └──────────────────────────┘
└──────────────────────────┘

Shared state (lock-free SPSC):
  rx_ring:    I/O thread produces → your thread consumes (decoded PCM)
  tx_ring:    your thread produces → I/O thread consumes (raw PCM)
  evt_queue:  I/O thread produces → your thread consumes (events)
```

- The I/O thread polls TCP + UDP sockets on a **20ms cadence** matching the audio frame rate.
- All callbacks fire from **your thread** when you call `poc_poll()`. Never from the I/O thread.
- Ring buffers use **C11 atomics** -- no mutexes, no locks.
- The I/O thread is started by `poc_connect()` and stopped by `poc_disconnect()`.
- A wakeup pipe allows `poc_ptt_send_audio()` to nudge the I/O thread immediately when new TX audio is queued.
- A signaling mutex (`sig_mutex`) protects TCP frame sends and group state that are accessed from both threads. The audio rings and event queue are fully lock-free and do not use this mutex.

**Thread safety:** `poc_poll()`, `poc_ptt_send_audio()`, `poc_get_state()`, `poc_get_user_id()`, and `poc_get_account()` are safe to call from any thread. All other functions should be called from the same thread that calls `poc_poll()`.

The server uses the same architecture: an I/O thread handles TCP/UDP networking, and `poc_server_poll()` drains the event queue on the main thread.

## Audio Flow

### Receiving (PoC -> your application)

```
Server UDP ─────▶ I/O thread recv()
                  ├─ Dedup (8-slot seq ring)
                  ├─ Decrypt (AES/SM4 if enabled)
                  ├─ Codec decode (compressed → PCM)
                  └─ Push to rx_ring
                            │
                            ▼
Your thread ◀──── poc_poll()
                  ├─ Pop from rx_ring
                  └─ on_audio_frame(frame)
                     └─ frame->samples: PCM at codec sample rate
```

### Transmitting (your application -> PoC)

```
Your thread ────▶ poc_ptt_send_audio(pcm, n_samples)
                  └─ Push to tx_ring
                            │
                            ▼
I/O thread ◀───── drain tx_ring
                  ├─ Codec encode (PCM → compressed)
                  ├─ Encrypt (AES/SM4 if enabled)
                  ├─ FEC wrap (optional parity frame)
                  └─ UDP sendto() ─────▶ Server
```

### Sample Rate Conversion

libpoc operates at the sample rate of the configured codec. If your application uses a different sample rate (e.g., 48000 Hz for PortAudio), you must resample at the boundary:

- **RX:** Upsample codec rate -> your rate after `on_audio_frame`
- **TX:** Downsample your rate -> codec rate before `poc_ptt_send_audio`

Check `frame->sample_rate` in the audio callback for the actual rate.

## State Machines

### Client Connection State

The client exposes `poc_state_t` via `poc_get_state()`. Internally, a finer-grained `login_state_t` drives the authentication handshake.

```
                    poc_connect()
  ┌─────────┐ ─────────────────────▶ ┌────────────┐
  │ OFFLINE │                        │ CONNECTING │
  └─────────┘ ◀── timeout/error ──── └────────────┘
       ▲                                    │
       │                        Login ──▶ Challenge ──▶ Validate
       │                                    │
       │               poc_disconnect()     ▼
       │         ◀───────────────────── ┌────────┐
       │                                │ ONLINE │
       │         Server force-exit      └────────┘
       ◀────────────────────────────────────┘
```

**Internal login state machine** (I/O thread):

```
  LOGIN_IDLE ──▶ LOGIN_CONNECTING ──▶ LOGIN_SENT_LOGIN
                                          │
                                  challenge received
                                          │
                                          ▼
                   LOGIN_ONLINE ◀── LOGIN_SENT_VALIDATE
                                          │
                                   bad HMAC / timeout
                                          │
                                          ▼
                                    LOGIN_FAILED
```

| Transition | Trigger | Timeout |
|------------|---------|---------|
| OFFLINE → CONNECTING | `poc_connect()` | — |
| CONNECTING → ONLINE | Login handshake succeeds | — |
| CONNECTING → OFFLINE | 5 login retries exhausted | 7s per retry |
| ONLINE → CONNECTING | Network error (auto-reconnect) | — |
| CONNECTING → CONNECTING | Reconnect backoff | 2s → 4s → 8s → ... → 512s |
| CONNECTING → OFFLINE | Reconnect backoff exhausted | 512s max |
| ONLINE → OFFLINE | `poc_disconnect()` or server force-exit | — |

### Client PTT State

PTT has its own state machine, active only while ONLINE:

```
        poc_ptt_start()             on_ptt_granted(true)
  ┌──────┐ ──────────▶ ┌────────────┐ ──────────────▶ ┌──────────────┐
  │ IDLE │             │ REQUESTING │                 │ TRANSMITTING │
  └──────┘ ◀────────── └────────────┘                 └──────────────┘
               denied        │                              │
          on_ptt_granted     │    poc_ptt_stop()            │
             (false)         │    or pre-empted             │
                             ▼                              ▼
                           ┌──────┐ ◀───────────────── ┌──────┐
                           │ IDLE │                    │ IDLE │
                           └──────┘                    └──────┘
```

Receiving side (another client is talking):

```
          on_ptt_start()                      on_ptt_end()
  ┌──────┐ ──────────────▶ ┌───────────┐ ──────────────▶ ┌──────┐
  │ IDLE │                 │ RECEIVING │                 │ IDLE │
  └──────┘                 └───────────┘                 └──────┘
                                │
                         on_audio_frame()
                         on_audio_level()
                           (per frame)
```

### Server Client Lifecycle

Each client connected to the server progresses through these states:

```
  TCP accept
      │
      ▼
  ┌─────────┐  login msg   ┌─────────────┐  validate ok  ┌────────┐
  │   NEW   │ ──────────▶  │ CHALLENGED  │ ────────────▶ │ ONLINE │
  └─────────┘              └─────────────┘               └────────┘
      │                          │                             │
  TCP close               validate fail                   TCP close
  or timeout              or timeout                  heartbeat timeout
      │                          │                    server kick/stun
      ▼                          ▼                         │
  ┌──────────────────────────────────────────────────┐     │
  │                  DISCONNECTED                    │ ◀───┘
  └──────────────────────────────────────────────────┘
```

| Transition | Trigger | Timeout |
|------------|---------|---------|
| (accept) → NEW | TCP connection accepted | — |
| NEW → CHALLENGED | Client sends login message | 7s auth timeout |
| CHALLENGED → ONLINE | HMAC-SHA1 validated | 7s auth timeout |
| CHALLENGED → DISCONNECTED | Bad credentials | — |
| ONLINE → DISCONNECTED | TCP close, heartbeat timeout (90s), server kick | — |

On disconnect: floor released, group leave callback fired, private call state cleaned up, status broadcast sent to all remaining clients.

### Server PTT Floor State (per group)

```
                  ptt_start (floor free)
  ┌──────┐ ────────────────────────────────────▶ ┌──────┐
  │ FREE │                                       │ HELD │
  └──────┘ ◀── ptt_stop / disconnect / timeout ─ └──────┘
                                                     │
                                            ptt_start from
                                          higher-priority user
                                                     │
                                                     ▼
                                              ┌─────────────┐
                                              │  PRE-EMPT   │
                                              │ (end→grant) │
                                              └─────────────┘
                                                     │
                                                     ▼
                                                 ┌──────┐
                                                 │ HELD │ (new speaker)
                                                 └──────┘
```

| Transition | Trigger | Condition |
|------------|---------|-----------|
| FREE → HELD | `ptt_start` received | Floor free, callback allows |
| HELD → HELD | `ptt_start` from higher-priority user | Pre-emption: old speaker gets END_PTT |
| HELD → HELD (denied) | `ptt_start` from equal/lower priority | Request denied, floor unchanged |
| HELD → FREE | `ptt_stop` received | Speaker releases voluntarily |
| HELD → FREE | Speaker disconnects | Cleanup in `srv_disconnect()` |
| HELD → FREE | Floor timeout (60s) | No audio received from holder |

### Server Group Membership

```
                poc_enter_group()         poc_leave_group()
  ┌──────────┐ ────────────────▶ ┌──────────┐ ──────────────▶ ┌──────────┐
  │ NO GROUP │                   │ IN GROUP │                 │ NO GROUP │
  └──────────┘                   └──────────┘                 └──────────┘
                                      │                            ▲
                                  disconnect                       │
                                 or server pull                    │
                                      │         poc_enter_group()  │
                                      ▼         (different group)  │
                                 ┌──────────┐ ─────────────────────┘
                                 │ NO GROUP │
                                 └──────────┘
```

Only one group active at a time. Entering a new group implicitly leaves the current one. Server fires `on_group_enter` / `on_group_leave` callbacks on transitions.

## Forward Error Correction

When `enable_fec` is set in the config, the library wraps encoded audio with XOR parity frames:

- Every `fec_group_size` data frames (default 3), one parity frame is appended
- The parity frame is the XOR of all data frames in the group
- If one data frame is lost in transit, the receiver reconstructs it from the parity + remaining frames
- FEC adds ~33% bandwidth overhead (3 data + 1 parity = 4 packets per 3 audio frames)

FEC is applied after codec encoding and encryption, before UDP transmission.

## Protocol Overview

The library implements a binary signaling protocol over TCP and UDP:

| Layer | Transport | Port | Purpose |
|-------|-----------|------|---------|
| Signaling | TCP | 29999 | Login, groups, PTT floor control, heartbeat |
| Voice | UDP | Dynamic | Encoded audio frames with sequence numbers |

### TCP Framing

All TCP messages use a 4-byte header:

```
┌───┬───┬───────┬───────┬──────────────┐
│ M │ S │ LEN_H │ LEN_L │   Payload    │
└───┴───┴───────┴───────┴──────────────┘
```

Magic bytes `0x4D 0x53` ("MS"), followed by a big-endian 16-bit payload length.

### Authentication

```
Client                          Server
  │                                │
  ├── Login (account, IMEI) ──────▶│
  │                                │
  │◀── Challenge (nonce, keys) ────┤
  │                                │
  ├── Validate (HMAC-SHA1) ───────▶│
  │                                │
  │◀── UserData (groups, users) ───┤
  │                                │
  ╞══ ONLINE ══════════════════════╡
```

The Validate message contains `HMAC-SHA1(SHA1_hex_password, 4-byte_nonce)` -- a 20-byte digest proving the client knows the password without transmitting it.

### UDP Voice Packets

```
┌────────┬──────────┬─────┬──────┬───────────────┐
│ SeqNum │ SenderID │ Pad │ Type │ Audio Payload │
│ 2B BE  │  4B BE   │ 1B  │  1B  │   20 bytes    │
└────────┴──────────┴─────┴──────┴───────────────┘
```

Minimum packet size: 8 bytes (header only). Duplicate packets are suppressed using an 8-slot sequence number ring.

## Test Suite

```bash
make check    # runs test_libpoc (unit) + test_integration (loopback)
```

### Unit Tests (232 tests)

| Module | Tests | Coverage |
|--------|-------|----------|
| Utility functions | 11 | Byte order, monotonic clock |
| Crypto | 9 | SHA1 known vectors, HMAC-SHA1 RFC 2202 |
| TCP framing | 10 | Magic bytes, length encoding, error handling |
| Message builders | 22 | Login, validate, heartbeat, PTT, groups, messages |
| Message parser | 26 | Challenge, PTT start/end, force exit, privilege, temp groups, pull, voice messages, auth failure |
| Audio codecs | 134 | All 10 codec modes through vtable interface: create, sample rate, frame size, encode, decode, roundtrip, 100-frame stress, known-value PCMU/PCMA, Opus VBR, availability, factory edge cases |
| Encryption | 12 | AES roundtrip, per-group keys, disabled state |
| GPS | 8 | Heartbeat format, float packing, APRS output |
| FEC | 8 | Parity generation, XOR correctness, reconstruction |

Note: The codec test count includes Opus codec tests when compiled with `HAVE_OPUS`. Without libopus, the codec module runs 72 tests (Speex + G.711 only).

### Integration Tests (15 tests)

The integration test suite spins up a `poc_server_t` on `127.0.0.1`, connects one or more `poc_ctx_t` clients, and exercises the full protocol stack end-to-end. All tests run single-threaded -- the I/O threads handle networking while the test drives both server and client poll loops.

| Category | Test | What it verifies |
|----------|------|------------------|
| Login | Successful handshake | Client reaches `POC_STATE_ONLINE` |
| Login | Server sees client | `on_client_connect` fires, client count increments |
| Login | Invalid password rejected | `on_login_error` fires with auth error |
| Login | User ID assigned | `poc_get_user_id()` returns correct ID after login |
| Login | Groups received | `on_groups_updated` fires with server's group list |
| Connection | Clean disconnect | Client transitions to `POC_STATE_OFFLINE` |
| Connection | Client count tracking | Client count tracks connect/disconnect |
| Groups | Enter group | `poc_enter_group()` succeeds |
| PTT | Floor granted when free | PTT request granted when no one is talking |
| PTT | Floor denied when busy | Second user denied when floor is held (equal priority) |
| PTT | Stop releases floor | Next user can take floor after release |
| PTT | Priority pre-emption | High-priority user (10) takes floor from low-priority user (0) |
| PTT | Equal priority no pre-empt | Equal-priority user cannot pre-empt |
| Audio | Frames reach listener | 1kHz tone roundtrips through server to second client |
| Messaging | Group message delivered | Text message relayed to group member |

### WAV Codec Test Tool

A standalone tool roundtrips WAV files through the Speex codec for listening tests:

```bash
./tests/test_codec_wav tests/wav/
```

Reads 8kHz mono WAV files, encodes through Speex, decodes back, writes output to `tests/wav/speex/`. Includes 14 test phrases from FreeSWITCH Callie voice prompts.

## Example Programs

### poc_cli

Standalone test client that connects, logs in, enters a group, and dumps all protocol messages and audio frame counts:

```bash
./examples/poc_cli server.example.com:29999 12345678 mypassword 100
```

Arguments: `<host[:port]> <account> <password> [group_id]`

### poc_server

Standalone test server with interactive linenoise console for server management:

```bash
./examples/poc_server [-v|-q] [config.ini]
```

Loads user/group configuration from an INI file (`poc_server.conf.ini` by default). Provides a console with tab-completion for live server commands:

| Command | Description |
|---------|-------------|
| `clients` | List online clients |
| `status` | Show server stats |
| `kick <uid>` | Disconnect a user |
| `broadcast <text>` | Message all clients |
| `msg <uid\|gid> <text>` | Send message to user or group |
| `pull <uid> <gid>` | Force user into group |
| `sos <uid>` | Trigger SOS alert |
| `shutdown` | Stop server |

## Project Structure

```
libpoc/
├── include/libpoc/
│   ├── poc.h                  # Public client API (all types and functions)
│   ├── poc_server.h           # Public server API (server types and functions)
│   ├── poc_proto.h            # Shared protocol constants (MS-frame, command types)
│   └── version.h              # Library version macros
├── src/
│   ├── poc_internal.h         # Private types, protocol constants, 40+ message types
│   ├── poc_server_internal.h  # Server-side private types and client state
│   ├── poc_ring.h             # Lock-free SPSC ring buffer (C11 atomics)
│   ├── poc_events.h           # Lock-free SPSC event queue (18 event types)
│   ├── poc_codec.h            # Audio codec abstraction vtable (pluggable codecs)
│   ├── poc_ctx.c              # Client context, I/O thread, poll loop, public API
│   ├── poc_server_ctx.c       # Server context, I/O thread, client management, PTT arbitration
│   ├── poc_tcp.c              # TCP connect, TLS, MS-frame send/recv/deframe
│   ├── poc_udp.c              # UDP voice send/recv with dedup
│   ├── poc_msg_build.c        # Build: login, validate, heartbeat, PTT, groups, messages
│   ├── poc_msg_parse.c        # Parse: 40+ message type dispatch, challenge handler
│   ├── poc_codec.c            # Codec factory: Speex NB/WB/UWB, G.711 PCMU/PCMA, Opus NB/WB/SWB/FB/32K
│   ├── poc_crypto.c           # SHA1, HMAC-SHA1 (OpenSSL)
│   ├── poc_encrypt.c          # AES/SM4 per-group audio encryption
│   ├── poc_gps.c              # GPS heartbeat and APRS position format
│   ├── poc_fec.c              # XOR-based forward error correction
│   └── poc_util.c             # Byte order, monotonic clock, logging
├── tests/
│   ├── test_main.c            # Unit test harness (232 tests across 9 modules)
│   ├── test_util.c            # Byte order, monotonic clock tests
│   ├── test_crypto.c          # SHA1, HMAC-SHA1 tests
│   ├── test_tcp_frame.c       # MS-frame framing tests
│   ├── test_msg_build.c       # Message builder tests
│   ├── test_msg_parse.c       # Message parser tests
│   ├── test_codec.c           # All codec modes: Speex, G.711, Opus vtable tests
│   ├── test_encrypt.c         # AES encryption roundtrip tests
│   ├── test_gps.c             # GPS reporting tests
│   ├── test_fec.c             # Forward error correction tests
│   ├── test_integration.c     # Server+client loopback integration tests (15 tests)
│   ├── test_codec_wav.c       # WAV roundtrip tool
│   └── wav/                   # Test audio (FreeSWITCH Callie 8kHz)
├── examples/
│   ├── poc_cli.c              # Standalone test client
│   ├── poc_server.c           # Standalone test server with interactive console
│   └── poc_server.conf.ini    # Example server configuration
├── debian/                    # Debian packaging (libpoc0 + libpoc-dev)
├── .github/workflows/         # CI + 6-platform release matrix
├── configure.ac               # Autotools configuration (Opus auto-detected)
├── Makefile.am                # Build recipes
├── libpoc.pc.in               # pkg-config template
├── autogen.sh                 # Bootstrap script
└── LICENSE                    # MIT
```

## License

MIT License. See [LICENSE](LICENSE).
