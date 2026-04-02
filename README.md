# libpoc

C library for **PoC** (Push-to-Talk over Cellular) radio protocol. Implements the binary signaling and audio transport used by common LTE PoC radios (Retevis, TYT, etc.) for group and private push-to-talk over cellular networks.

Connects to a PoC server, authenticates via HMAC-SHA1 challenge-response, joins talk groups, and handles bidirectional half-duplex PTT voice using Speex narrowband codec over UDP. Designed for embedding into repeater controllers, dispatch consoles, and radio gateways.

C11/POSIX, callback-driven, threaded I/O. Dependencies: libspeex, OpenSSL, pthreads.

## Table of Contents

- [Features](#features)
- [Building](#building)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
  - [Configuration](#configuration)
  - [Lifecycle](#lifecycle)
  - [Connection](#connection)
  - [Groups](#groups)
  - [PTT Voice](#ptt-voice)
  - [Private Calls](#private-calls)
  - [GPS](#gps)
  - [Messaging](#messaging)
  - [Encryption](#encryption)
  - [State and Info](#state-and-info)
  - [Callbacks](#callbacks)
  - [Data Types](#data-types)
  - [Error Codes](#error-codes)
- [Threading Model](#threading-model)
- [Audio Flow](#audio-flow)
- [State Machine](#state-machine)
- [Forward Error Correction](#forward-error-correction)
- [Protocol Overview](#protocol-overview)
- [Test Suite](#test-suite)
- [Example Programs](#example-programs)
- [Project Structure](#project-structure)
- [License](#license)

## Features

- **TCP Signaling** — Custom MS-framed binary protocol on port 29999 with login, heartbeat, group management, and PTT floor control
- **HMAC-SHA1 Authentication** — SHA1 password hashing with server challenge-response handshake
- **UDP Voice Transport** — Real-time audio with sequence numbering and duplicate suppression
- **Speex Narrowband Codec** — 8kHz, 20ms frames (160 samples -> 20 bytes encoded)
- **AES/SM4 Audio Encryption** — Per-group and per-session key support for encrypted voice
- **GPS Position Reporting** — Periodic position heartbeats over the signaling channel
- **Audio FEC** — XOR-based forward error correction with configurable group size
- **Text Messaging** — Group and private text messages
- **Private Calls** — Direct user-to-user voice calls
- **Threaded I/O** — Dedicated I/O thread with lock-free SPSC ring buffers for zero-copy audio handoff
- **Non-blocking API** — `poc_poll()` drains event and audio queues from any thread without blocking

### Audio Parameters

| Parameter | Value |
|-----------|-------|
| Sample rate | 8000 Hz |
| Frame size | 160 samples (20 ms) |
| Codec | Speex narrowband, quality 4 |
| Encoded frame | 20 bytes |
| PCM frame | 320 bytes (160 x 16-bit) |

## Building

```bash
bash autogen.sh   # generate configure (requires autoconf, automake, libtool)
./configure
make               # builds libpoc.so, libpoc.a, poc_cli, and test binaries
make check         # runs 92 unit tests
make install       # installs library, headers, and pkg-config file
```

### Dependencies

| Library | Package | Purpose |
|---------|---------|---------|
| libspeex | `libspeex-dev` | Speex narrowband audio codec |
| OpenSSL | `libssl-dev` | SHA1, HMAC-SHA1, AES encryption |
| pthreads | libc | I/O thread |

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
```

## Quick Start

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

## API Reference

All functions are declared in `<libpoc/poc.h>`. The library uses an opaque context (`poc_ctx_t`).

### Configuration

```c
typedef struct {
    const char *server_host;     /* Server hostname or IP address */
    uint16_t    server_port;     /* Server port (default: 29999) */
    const char *account;         /* Account ID string */
    const char *password;        /* Raw password (library SHA1-hashes internally) */
    const char *imei;            /* Device IMEI (optional, may be NULL) */
    const char *iccid;           /* SIM ICCID (optional, may be NULL) */
    int         codec;           /* POC_CODEC_SPEEX (only supported value) */
    int         heartbeat_ms;    /* Heartbeat interval in ms (0 = default 30000) */
    bool        enable_fec;      /* Enable audio forward error correction */
    int         fec_group_size;  /* FEC group size: N data + 1 parity (0 = default 3) */
    int         gps_interval_ms; /* GPS report interval in ms (0 = default 60000) */
} poc_config_t;
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `server_host` | Yes | — | Server hostname or IP |
| `server_port` | No | 29999 | TCP/UDP port |
| `account` | Yes | — | Account ID for authentication |
| `password` | Yes | — | Plaintext password (SHA1 hashed internally) |
| `imei` | No | NULL | Device IMEI sent during login |
| `iccid` | No | NULL | SIM ICCID sent during login |
| `codec` | No | `POC_CODEC_SPEEX` | Audio codec selection |
| `heartbeat_ms` | No | 30000 | Keepalive interval (ms) |
| `enable_fec` | No | false | Enable audio FEC |
| `fec_group_size` | No | 3 | FEC data frames per parity frame |
| `gps_interval_ms` | No | 60000 | GPS report interval (ms) |

### Lifecycle

#### `poc_create`

```c
poc_ctx_t *poc_create(const poc_config_t *cfg, const poc_callbacks_t *cb);
```

Create a new PoC context. Copies all config strings internally. Initializes the Speex codec, ring buffers, and event queues. Does not connect.

**Parameters:**
- `cfg` — Server and codec configuration. `server_host`, `account`, and `password` are required.
- `cb` — Callback struct. All callback pointers are optional (NULL = not called). The `userdata` field is passed to every callback.

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

Resolve the server hostname, establish a TCP connection, send the login message, open a UDP socket for audio, and start the I/O thread. The login handshake (challenge-response) completes asynchronously — use the `on_state_change` callback to detect when `POC_STATE_ONLINE` is reached.

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
- `timeout_ms` — Currently ignored (always non-blocking). Reserved for future use.

**Returns:** `POC_OK`, or `POC_ERR_STATE` if context is NULL.

**Important:** Callbacks fire synchronously inside `poc_poll()`. Keep callback handlers fast — long-running work will block audio delivery.

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

Push PCM audio into the TX ring buffer. The I/O thread encodes (Speex), optionally encrypts and FEC-wraps, then sends via UDP.

**Parameters:**
- `pcm` — 16-bit signed PCM samples at 8000 Hz.
- `n_samples` — Number of samples. Must be a multiple of 160 (20ms frames). Partial frames at the end are silently discarded.

Audio is queued, not sent synchronously. If the TX ring is full (320ms backlog), excess frames are dropped with a log message.

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

### GPS

#### `poc_set_gps`

```c
int poc_set_gps(poc_ctx_t *ctx, float lat, float lng);
```

Set the device's GPS position. The position is sent to the server automatically at the interval configured by `gps_interval_ms`. The I/O thread handles the timing — just call this whenever you have a new fix.

**Parameters:**
- `lat` — Latitude in decimal degrees (positive = North).
- `lng` — Longitude in decimal degrees (positive = East).

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

### Encryption

Audio encryption is configured per-group by the server during the login handshake. The library handles encrypt/decrypt transparently in the I/O thread — no caller action needed.

#### `poc_is_encrypted`

```c
bool poc_is_encrypted(const poc_ctx_t *ctx);
```

**Returns:** true if audio encryption is active for the current session.

Supported ciphers (selected by server):
- **AES-128/192/256-ECB** (type 0x02)
- **SM4-ECB** (type 0x06, Chinese national standard)

Per-group keys are delivered in the login response. Session-level keys are used for private calls.

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
| `on_audio_frame` | Decoded audio frame ready | `frame->samples`: 160 x int16 at 8kHz |
| `on_ptt_granted` | Floor request result | `granted`: true if you may transmit |
| `on_message` | Text message received | `from_id`: sender, `text`: message body |

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
    int      status;       /* 0 = offline, 1 = online */
    uint32_t privilege;    /* Permission bitmask */
} poc_user_t;
```

#### `poc_audio_frame_t`

```c
typedef struct {
    const int16_t *samples;    /* PCM sample buffer */
    int            n_samples;  /* Always 160 (20ms at 8kHz) */
    int            sample_rate;/* Always 8000 */
    uint32_t       speaker_id; /* User ID of the speaker */
    uint32_t       group_id;   /* Group this audio belongs to */
} poc_audio_frame_t;
```

The `samples` pointer is valid only for the duration of the `on_audio_frame` callback. Copy the data if you need it later.

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
- Ring buffers use **C11 atomics** — no mutexes, no locks.
- The I/O thread is started by `poc_connect()` and stopped by `poc_disconnect()`.
- A wakeup pipe allows `poc_ptt_send_audio()` to nudge the I/O thread immediately when new TX audio is queued.

**Thread safety:** `poc_poll()`, `poc_ptt_send_audio()`, `poc_get_state()`, `poc_get_user_id()`, and `poc_get_account()` are safe to call from any thread. All other functions should be called from the same thread that calls `poc_poll()`.

## Audio Flow

### Receiving (PoC -> your application)

```
Server UDP ─────▶ I/O thread recv()
                  ├─ Dedup (8-slot seq ring)
                  ├─ Decrypt (AES/SM4 if enabled)
                  ├─ Speex decode (20 bytes → 160 samples)
                  └─ Push to rx_ring
                            │
                            ▼
Your thread ◀──── poc_poll()
                  ├─ Pop from rx_ring
                  └─ on_audio_frame(frame)
                     └─ frame->samples: 160 x int16 @ 8kHz
```

### Transmitting (your application -> PoC)

```
Your thread ────▶ poc_ptt_send_audio(pcm, 160)
                  └─ Push to tx_ring
                            │
                            ▼
I/O thread ◀───── drain tx_ring
                  ├─ Speex encode (160 samples → 20 bytes)
                  ├─ Encrypt (AES/SM4 if enabled)
                  ├─ FEC wrap (optional parity frame)
                  └─ UDP sendto() ─────▶ Server
```

### Sample Rate Conversion

libpoc operates at **8000 Hz**. If your application uses a different sample rate (e.g., 48000 Hz for PortAudio), you must resample at the boundary:

- **RX:** Upsample 8kHz → 48kHz after `on_audio_frame`
- **TX:** Downsample 48kHz → 8kHz before `poc_ptt_send_audio`

Linear interpolation is sufficient for voice quality.

## State Machine

```
                poc_connect()
  OFFLINE ──────────────────────▶ CONNECTING
     ▲                                │
     │                     Login + Challenge + Validate
     │                                │
     │          poc_disconnect()      ▼
     ◀──────────────────────────── ONLINE
     │                                │
     │          Server force-exit     │
     ◀────────────────────────────────┘
```

| Transition | Trigger |
|------------|---------|
| OFFLINE → CONNECTING | `poc_connect()` called |
| CONNECTING → ONLINE | Login handshake succeeds |
| CONNECTING → OFFLINE | Login timeout (5 retries) or network error |
| ONLINE → OFFLINE | `poc_disconnect()`, network error, or server force-exit |

## Forward Error Correction

When `enable_fec` is set in the config, the library wraps encoded audio with XOR parity frames:

- Every `fec_group_size` data frames (default 3), one parity frame is appended
- The parity frame is the XOR of all data frames in the group
- If one data frame is lost in transit, the receiver reconstructs it from the parity + remaining frames
- FEC adds ~33% bandwidth overhead (3 data + 1 parity = 4 packets per 3 audio frames)

FEC is applied after Speex encoding and encryption, before UDP transmission.

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

The Validate message contains `HMAC-SHA1(SHA1_hex_password, 4-byte_nonce)` — a 20-byte digest proving the client knows the password without transmitting it.

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
make check    # 92 tests
```

| Module | Tests | Coverage |
|--------|-------|----------|
| Utility functions | 10 | Byte order, monotonic clock |
| Crypto | 8 | SHA1 known vectors, HMAC-SHA1 RFC 2202 |
| TCP framing | 8 | Magic bytes, length encoding, error handling |
| Message builders | 18 | Login, validate, heartbeat, PTT, groups |
| Message parser | 13 | Challenge, PTT start/end, force exit, privilege |
| Speex codec | 11 | Encode, decode, roundtrip, 100-frame stability |
| Encryption | 8 | AES roundtrip, per-group keys, disabled state |
| GPS | 7 | Heartbeat format, float packing, APRS output |
| FEC | 5 | Parity generation, XOR correctness, reconstruction |

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

## Project Structure

```
libpoc/
├── include/libpoc/
│   └── poc.h                  # Public API (all types and functions)
├── src/
│   ├── poc_internal.h         # Private types, protocol constants, 40+ message types
│   ├── poc_ring.h             # Lock-free SPSC ring buffer (C11 atomics)
│   ├── poc_events.h           # Lock-free SPSC event queue
│   ├── poc_ctx.c              # Context, I/O thread, poll loop, public API
│   ├── poc_tcp.c              # TCP connect, MS-frame send/recv/deframe
│   ├── poc_udp.c              # UDP voice send/recv with dedup
│   ├── poc_msg_build.c        # Build: login, validate, heartbeat, PTT, groups, messages
│   ├── poc_msg_parse.c        # Parse: 40+ message type dispatch, challenge handler
│   ├── poc_codec.c            # Speex narrowband encode/decode
│   ├── poc_crypto.c           # SHA1, HMAC-SHA1 (OpenSSL)
│   ├── poc_encrypt.c          # AES/SM4 per-group audio encryption
│   ├── poc_gps.c              # GPS heartbeat and APRS position format
│   ├── poc_fec.c              # XOR-based forward error correction
│   └── poc_util.c             # Byte order, monotonic clock, logging
├── tests/
│   ├── test_main.c            # Test harness (92 tests)
│   ├── test_*.c               # Per-module test files (10 files)
│   ├── test_codec_wav.c       # WAV roundtrip tool
│   └── wav/                   # Test audio (FreeSWITCH Callie 8kHz)
├── examples/
│   └── poc_cli.c              # Standalone test client
├── debian/                    # Debian packaging (libpoc0 + libpoc-dev)
├── .github/workflows/         # CI + 6-platform release matrix
├── configure.ac               # Autotools configuration
├── Makefile.am                # Build recipes
├── libpoc.pc.in               # pkg-config template
├── autogen.sh                 # Bootstrap script
└── LICENSE                    # MIT
```

## License

MIT License. See [LICENSE](LICENSE).
