# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

libpoc is a C library implementing the PoC (Push-to-Talk over Cellular) binary protocol used by LTE PoC radios. It provides both a client API (`poc.h`) and a server API (`poc_server.h`). C11/POSIX, callback-driven, threaded I/O.

## Build Commands

```bash
bash autogen.sh          # bootstrap (requires autoconf, automake, libtool)
./configure
make                     # builds libpoc.so, libpoc.a, poc_cli, test binaries
make check               # runs 232 unit + 15 integration tests (two binaries)
make install             # installs library, headers, pkg-config file
dpkg-buildpackage -us -uc -b  # Debian packages
```

Dependencies: `libspeex-dev`, `libssl-dev`, pthreads (libc). Optional: `libopus-dev` (Opus codec support, auto-detected).

## Test Infrastructure

Two test binaries run via `make check`:
- **`tests/test_libpoc`** (232 unit tests) — per-module tests for codec, crypto, framing, messages, encryption, GPS, FEC. Built from `test_main.c` + `test_*.c` files.
- **`tests/test_integration`** (13 integration tests) — server+client loopback on localhost. Tests login handshake, invalid credentials, group enter, PTT floor arbitration (grant/deny/release), audio roundtrip, text messaging, disconnect, client counting.

Tests use a minimal custom harness (`test_begin`/`test_assert`/`test_end` — no framework). `tests/test_codec_wav` is a separate non-test tool for WAV roundtrip.

## Architecture

### Two APIs

- **Client API** (`include/libpoc/poc.h`) — connect to a PoC server, join groups, PTT voice, messaging, GPS. Opaque `poc_ctx_t`.
- **Server API** (`include/libpoc/poc_server.h`) — TCP/UDP listener, client auth, floor arbitration, audio relay, virtual PTT/audio injection. Opaque `poc_server_t`.

### Threading Model

The I/O thread (started by `poc_connect()`) polls TCP+UDP on a 20ms cadence. Communication with the caller's thread is via lock-free SPSC ring buffers (`poc_ring.h` for audio, `poc_events.h` for events) using C11 atomics — no mutexes. All callbacks fire from the caller's thread inside `poc_poll()`, never from the I/O thread.

### Source Layout (src/)

| File | Role |
|------|------|
| `poc_ctx.c` | Client context, I/O thread main loop, public API entry points |
| `poc_server_ctx.c` | Server context, accept loop, per-client state, audio relay |
| `poc_tcp.c` | TCP connect, MS-frame (magic `0x4D53` + 2-byte length) send/recv/deframing |
| `poc_udp.c` | UDP voice send/recv with 8-slot sequence dedup ring |
| `poc_msg_build.c` | Builds all outbound TCP messages (login, validate, heartbeat, PTT, groups, text) |
| `poc_msg_parse.c` | Parses 40+ inbound message types, dispatches to event queue |
| `poc_codec.h` | Codec abstraction vtable (`poc_codec_t`) — encode/decode/destroy + metadata |
| `poc_codec.c` | All codec implementations: Speex NB/WB/UWB, G.711 PCMU/PCMA, Opus NB/WB/SWB/FB |
| `poc_crypto.c` | SHA1, HMAC-SHA1 via OpenSSL |
| `poc_encrypt.c` | AES-ECB (128/192/256) per-group audio encryption |
| `poc_gps.c` | GPS heartbeat formatting |
| `poc_fec.c` | XOR-based forward error correction |
| `poc_ring.h` | Lock-free SPSC ring buffer (header-only, C11 atomics) |
| `poc_events.h` | Lock-free SPSC event queue (header-only) |
| `poc_internal.h` | Client internal types, protocol constants, all message type codes |
| `poc_server_internal.h` | Server internal types and per-client state |

### Key Patterns

- **MS framing**: All TCP messages start with `0x4D 0x53` + big-endian 16-bit payload length.
- **Auth flow**: Login → server Challenge (nonce) → Validate (`HMAC-SHA1(SHA1_hex(password), nonce)`) → UserData → ONLINE.
- **Codec abstraction**: `poc_codec_t` vtable in `poc_codec.h` — all codecs implement `encode`/`decode`/`destroy`. Factory: `poc_codec_create(POC_CODEC_*)`. Codecs: Speex NB/WB/UWB (8/16/32kHz), G.711 PCMU/PCMA (8kHz), Opus NB/WB/SWB/FB (8/16/24/48kHz, optional). Buffers sized for up to 48kHz (`POC_CODEC_MAX_FRAME_SAMPLES = 960`). Use `poc_codec_available()` to probe at runtime.
- **PTT floor control**: Priority-based pre-emption — higher-priority users override current speaker. Server `on_ptt_preempted` callback fires. Equal/lower priority denied while floor is held.
- **Audio pipeline**: PCM → codec encode → optional encrypt → optional FEC → UDP send (and reverse on receive).
- Compiler flags: `-std=c11 -D_GNU_SOURCE -Wall -Wextra`.
