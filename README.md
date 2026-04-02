# libpoc

C library for **PoC** (Push-to-Talk over Cellular) radio protocol. Implements the binary signaling and audio transport used by common LTE PoC radios (Retevis, TYT, etc.) for group and private push-to-talk over cellular networks.

Connects to a PoC server, authenticates via HMAC-SHA1 challenge-response, joins talk groups, and handles bidirectional half-duplex PTT voice using Speex narrowband codec over UDP. Designed for embedding into repeater controllers, dispatch consoles, and radio gateways.

C11/POSIX, callback-driven, threaded I/O. Dependencies: libspeex, OpenSSL, pthreads.

## Table of Contents

- [Features](#features)
- [Building](#building)
- [API Overview](#api-overview)
  - [Lifecycle](#lifecycle)
  - [Connection](#connection)
  - [Groups](#groups)
  - [PTT Voice](#ptt-voice)
  - [Private Calls](#private-calls)
  - [GPS](#gps)
  - [Messaging](#messaging)
  - [Encryption](#encryption)
  - [Callbacks](#callbacks)
  - [Error Codes](#error-codes)
- [Threading Model](#threading-model)
- [Protocol](#protocol)
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

## API Overview

All functions are declared in `<libpoc/poc.h>`. The library uses an opaque context (`poc_ctx_t`) and a callback struct for event delivery.

### Lifecycle

```c
// Create context with server config and callbacks
poc_ctx_t *ctx = poc_create(&config, &callbacks);

// Connect, authenticate, and start I/O thread
poc_connect(ctx);

// Poll for events and audio (call from your main/audio thread)
poc_poll(ctx, 0);

// Disconnect and destroy
poc_disconnect(ctx);
poc_destroy(ctx);
```

### Connection

```c
poc_config_t cfg = {
    .server_host  = "server.example.com",
    .server_port  = 29999,
    .account      = "12345678",
    .password     = "mypassword",   // library SHA1-hashes this
    .heartbeat_ms = 30000,
};
```

Optional fields: `.imei`, `.iccid`, `.enable_fec`, `.fec_group_size`, `.gps_interval_ms`.

### Groups

```c
poc_enter_group(ctx, group_id);   // join a talk group
poc_leave_group(ctx);             // leave current group

// Query groups (populated after login)
int n = poc_get_group_count(ctx);
poc_group_t groups[64];
poc_get_groups(ctx, groups, 64);
```

### PTT Voice

```c
// Start transmitting (requests floor from server)
poc_ptt_start(ctx);

// Send 8kHz 16-bit PCM audio (160 samples = 20ms per call)
int16_t pcm[160];
poc_ptt_send_audio(ctx, pcm, 160);

// Stop transmitting (releases floor)
poc_ptt_stop(ctx);
```

Incoming audio arrives via the `on_audio_frame` callback:

```c
void on_audio(poc_ctx_t *ctx, const poc_audio_frame_t *frame, void *ud) {
    // frame->samples: 160 x int16_t at 8000 Hz
    // frame->speaker_id: who is talking
    // frame->group_id: which group
    play_audio(frame->samples, frame->n_samples);
}
```

### Private Calls

```c
poc_call_user(ctx, user_id);       // initiate private call
poc_ptt_send_audio(ctx, pcm, n);   // send audio (same as group PTT)
poc_call_end(ctx);                 // end call
```

### GPS

```c
poc_set_gps(ctx, 37.7749f, -122.4194f);   // set position (lat, lng)
// Position is reported automatically at the configured interval
```

### Messaging

```c
poc_send_group_msg(ctx, group_id, "Hello group");
poc_send_user_msg(ctx, user_id, "Hello user");
```

### Encryption

Audio encryption is configured per-group by the server during login. The library handles encryption/decryption transparently.

```c
bool encrypted = poc_is_encrypted(ctx);
```

Supported ciphers: AES-128/192/256-ECB, SM4-ECB.

### Callbacks

```c
poc_callbacks_t cb = {
    .on_state_change  = my_state_handler,     // OFFLINE -> CONNECTING -> ONLINE
    .on_login_error   = my_error_handler,     // authentication failures
    .on_groups_updated = my_groups_handler,    // group list changed
    .on_ptt_start     = my_ptt_start_handler, // someone started talking
    .on_ptt_end       = my_ptt_end_handler,   // someone stopped talking
    .on_audio_frame   = my_audio_handler,     // decoded audio frame ready
    .on_ptt_granted   = my_grant_handler,     // floor request accepted/denied
    .on_message       = my_msg_handler,       // text message received
    .userdata         = my_context,
};
```

All callbacks fire from the thread that calls `poc_poll()`, never from the I/O thread.

### Error Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `POC_OK` | Success |
| -1 | `POC_ERR` | General error |
| -2 | `POC_ERR_AUTH` | Authentication failed |
| -3 | `POC_ERR_TIMEOUT` | Operation timed out |
| -4 | `POC_ERR_NETWORK` | Network error |
| -5 | `POC_ERR_STATE` | Invalid state for operation |
| -6 | `POC_ERR_NOMEM` | Memory allocation failed |

## Threading Model

```
┌──────────────────────────┐       ┌──────────────────────────┐
│       I/O Thread          │       │     Your Thread           │
│                          │       │                          │
│  poll(TCP, UDP, wakeup)  │       │  poc_poll(ctx, 0)        │
│  ├─ TCP recv → deframe   │       │  ├─ drain evt_queue      │
│  │  → parse → evt_queue ─┼──────▶│  │  → fire callbacks     │
│  ├─ UDP recv → decode    │       │  ├─ drain rx_ring        │
│  │  → decrypt → rx_ring ─┼──────▶│  │  → on_audio_frame()   │
│  ├─ drain tx_ring ◀──────┼───────┼──┤                       │
│  │  → encode → encrypt   │       │  │  poc_ptt_send_audio() │
│  │  → UDP send           │       │  │  → push to tx_ring    │
│  ├─ heartbeat timer      │       │  └──────────────────────  │
│  └─ GPS timer            │       └──────────────────────────┘
└──────────────────────────┘

Shared state (lock-free SPSC):
  rx_ring:    I/O thread produces → your thread consumes (decoded PCM)
  tx_ring:    your thread produces → I/O thread consumes (raw PCM)
  evt_queue:  I/O thread produces → your thread consumes (events)
```

The I/O thread polls TCP + UDP sockets on a 20ms cadence matching the audio frame rate. All callbacks fire from your thread when you call `poc_poll()`. No locks are used — ring buffers use C11 atomics.

## Protocol

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
  ╞══ ONLINE ═════════════════════╡
```

### UDP Voice Packets

```
┌────────┬──────────┬─────┬──────┬──────────────┐
│ SeqNum │ SenderID │ Pad │ Type │ Audio Payload │
│ 2B BE  │  4B BE   │ 1B  │  1B  │   20 bytes    │
└────────┴──────────┴─────┴──────┴──────────────┘
```

## Test Suite

```bash
make check    # 92 tests
```

```
Utility functions:            10 tests (byte order, timers)
Crypto (SHA1, HMAC-SHA1):      8 tests (RFC 2202 vectors)
TCP MS-frame framing:          8 tests (magic, length, payload)
Message builders:             18 tests (login, validate, PTT, groups)
Message parser dispatch:      13 tests (challenge, PTT, force exit)
Speex codec:                  11 tests (encode, decode, roundtrip)
Encryption (AES/SM4):         8 tests (roundtrip, per-group keys)
GPS reporting:                 7 tests (heartbeat, APRS format)
Forward Error Correction:      5 tests (parity, reconstruction)
```

### WAV Codec Test Tool

A standalone tool roundtrips WAV files through the Speex codec for listening tests:

```bash
./tests/test_codec_wav tests/wav/
```

## Example Programs

### poc_cli

Standalone test client that connects, logs in, and dumps all protocol messages:

```bash
./examples/poc_cli server.example.com:29999 12345678 mypassword [group_id]
```

## Project Structure

```
libpoc/
├── include/libpoc/
│   └── poc.h                  # Public API
├── src/
│   ├── poc_internal.h         # Private types, protocol constants
│   ├── poc_ring.h             # Lock-free SPSC ring buffer
│   ├── poc_events.h           # Lock-free event queue
│   ├── poc_ctx.c              # Context, I/O thread, poll loop
│   ├── poc_tcp.c              # TCP connect, MS-frame send/recv
│   ├── poc_udp.c              # UDP voice send/recv with dedup
│   ├── poc_msg_build.c        # Build protocol messages
│   ├── poc_msg_parse.c        # Parse and dispatch messages
│   ├── poc_codec.c            # Speex codec wrapper
│   ├── poc_crypto.c           # SHA1, HMAC-SHA1
│   ├── poc_encrypt.c          # AES/SM4 audio encryption
│   ├── poc_gps.c              # GPS reporting
│   ├── poc_fec.c              # Audio FEC
│   └── poc_util.c             # Byte order, clock, logging
├── tests/
│   ├── test_main.c            # Test harness (92 tests)
│   ├── test_*.c               # Per-module test files
│   ├── test_codec_wav.c       # WAV roundtrip tool
│   └── wav/                   # Test WAV files (FreeSWITCH Callie 8kHz)
├── examples/
│   └── poc_cli.c              # Standalone test client
├── debian/                    # Debian packaging
├── .github/workflows/         # CI + release (6-platform matrix)
├── configure.ac
├── Makefile.am
├── libpoc.pc.in
├── autogen.sh
└── LICENSE
```

## License

MIT License. See [LICENSE](LICENSE).
