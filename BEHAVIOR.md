# PoC Protocol Behavior Reference

Detailed behavior of each protocol feature as observed in the stock PoC radio firmware.

---

## 1. Login

### Sequence

1. Client resolves server hostname (URLs contain `%d` for server index rotation — up to 4 servers tried in sequence)
2. TCP connect to port 29999
3. UDP socket opened for audio
4. Client sends **Login (type 0x01)**: session ID, UserID=0xFFFFFFFF, protocol version, account name (max 30 chars), IMEI (8 bytes big-endian uint64), ICCID (null-terminated)
5. Server sends **Challenge (type 0x07)**: assigned UserID, random 4-byte nonce, privilege flags, encryption key type, GPS config
6. Client sends **Validate (type 0x04)**: session ID, UserID, HMAC-SHA1 digest (20 bytes)
   - HMAC key = 40-char hex SHA1 of password
   - HMAC data = 4-byte challenge nonce
7. Server sends **UserData (type 0x0B)**: default group ID, privilege bitmask (upper 16 bits = GPS interval in seconds), codec type, username, log server URL, extended privileges, group list
8. Client enters default group

### Timeouts and Retries

- Login timeout: **7 seconds**. If no challenge received, retry.
- Retry intervals: 1s (fast), 2s (medium), 4s (standard) — fixed, no exponential backoff in stock firmware.
- Server rotation: up to 4 server addresses tried, wraps to index 0 after exhausting all.
- Max retries: unbounded in stock firmware (keeps trying until success or user cancels).

### Error Codes

| Response | Meaning | Behavior |
|----------|---------|----------|
| 0x00 | Success | Enter default group |
| 0x01-0x05 | Generic failure | Auto-retry in 4s |
| 0x06 | Account error | No retry — show error |
| 0x07 | Generic failure | Auto-retry in 4s |
| 0x08 | Version mismatch | No retry — show error |
| 0x09 | Server failure | No retry |
| 0x0B | ICCID mismatch | No retry — show error |
| 0x0C | IMEI mismatch | No retry — show error |
| 0x88 | Timeout | Auto-retry |

### IMEI/ICCID

- IMEI is converted from decimal string to uint64 via `strtoull()`, then sent as 8 bytes big-endian
- ICCID is sent as a null-terminated string after the IMEI field
- Server may reject login if IMEI/ICCID doesn't match the account binding (codes 0x0B/0x0C)

---

## 2. Heartbeat

### Mechanism

The heartbeat serves dual purpose: **NAT keepalive** and **server liveness detection**.

- A 2-second base timer fires `HandleCmdNatMap()` periodically
- An interval counter determines how many ticks before actually sending a heartbeat packet
- The heartbeat message type is **0x0D**, 12 bytes total (header only, no payload)

### Interval

- **Power-save foreground**: uses "active" interval value from server config
- **Power-save background**: uses "background" interval (longer)
- **Normal mode, first packet**: uses background interval
- **Subsequent packets**: adaptive — increments/decrements by configurable step, bounded by min/max values
- Typical effective interval: 15-30 seconds

### Disconnect Detection

- Counter tracks heartbeats sent since last ACK
- When counter exceeds configured max misses → **declared offline**
- On offline detection: saves GPS, stops voice call, enters retry login with 4s delay
- Typical threshold: 3-5 missed heartbeats

### Voice Channel Heartbeat

- Separate heartbeat for active voice calls: 512-byte zero-filled packet, type **6**
- Sent on the same 2-second base timer tick when a voice call is active
- Keeps the UDP audio path alive through NATs

### GPS Heartbeat

- Separate 5-second timer for GPS position reports
- Sends `GPSHeart()` message via TCP
- Forced send every 3 cycles (15s) even if no position change

---

## 3. PTT Floor Control

### Request Flow

1. Client calls `StartPTT(broadcast)`:
   - Rejects if: voice call active, not logged in, already in PTT
   - **Geofence check**: if fence privilege bit set and user is outside fence → rejected with error 0xE1
   - Increments session ID
   - Sends StartPTT message (type **0x28** for group, **0x4D** for group broadcast)
   - Starts timeout timer

2. Server responds:
   - **Success (0x00)**: floor granted, client starts audio recording
   - **Floor busy (0x25)**: someone else is talking — denied, plays failure tone
   - **Priority denied (0x26)**: caller's priority too low for preemption
   - **Timeout (0xFF)**: no response — tries re-entering group
   - **Session timeout (0x88)**: from call manager timer

### Floor Arbitration

- **No queue** — PTT requests are denied immediately if floor is busy
- **No priority preemption in basic mode** — first-come-first-served
- **PTT time limit**: configurable max transmission duration. When timer fires, if more than 2 seconds have passed since grant, auto-releases floor

### PTT Variants

| Variant | Type Byte | Description |
|---------|-----------|-------------|
| Group PTT | 0x28 | Standard group talk |
| Broadcast PTT | 0x28 | Same type, server handles distribution |
| Group Broadcast PTT | 0x4D | Broadcast within a specific group |
| Single (Private) PTT | variant | Direct user-to-user |
| Single Group PTT | variant | Direct to specific group |
| End PTT | 0x29 | Release floor |
| Group Broadcast End | 0x4E | Release group broadcast floor |

### Notifications

When a user gets the floor, the server sends `OnNotifyUserStartPTT` to all group members with the speaker's user ID, name, and codec type. When released, `OnNotifyUserEndPTT` with the user ID.

---

## 4. Groups

### Enter Group

- If target group == current group and no temp group → error 0xFC (already in group)
- If group ID == -1 → error
- If group not in local group list → error 0xFE
- On enter: stops any active PTT, sends EnterGroup (type **0x08**) with group ID
- Server handles transition — client doesn't explicitly leave old group first
- On success: leaves any temp group, saves new group ID to config
- On failure during first login: tries entering the group from the response data

### Leave Group

- Sends EnterGroup with **group ID = 0xFFFFFFFF** (-1) — reuses the same message type
- Server interprets -1 as "leave current group"
- Client then enters its default group

### Group State Updates

Server pushes notifications for:
- Group added (0x33), removed (0x35), renamed (0x37)
- User added to group (0x3B), removed from group (0x3D)
- Group master changed (0x39)

---

## 5. Temporary Groups

### Creation

1. Client sends `InviteTmpGroup` (type **0x1F**) with array of user IDs (max 25)
2. Server creates the temp group and sends invite notifications to all listed users
3. Each invited user receives `OnNotifyUserInviteTmpGroup`

### Acceptance

- If auto-accept is configured: immediately sends accept (0x00) via `AnswerInviteTmpGroup` (type **0x09**)
- Otherwise: sends reject (0xFF) and waits for UI action
- Accept/reject answer byte: 0x00 = accept, 0xFF = reject

### SOS Integration

When SOS is triggered, the `SendSOSManager`:
1. Fetches nearby users via HTTP API `getUsersPosition()`
2. Selects up to 10 nearest users
3. Creates a temp group with those users via `inviteTmpGroup()`

### Lifecycle

- Temp groups exist as long as members are present
- When the last member leaves, the server destroys the group
- Entering a regular group automatically leaves any temp group
- `HasTmpGroup()` check gates various behaviors throughout the code

---

## 6. Monitor Groups

### Behavior

- Add monitor: type **0x24**, payload = group ID
- Remove monitor: type **0x25**, payload = group ID
- Monitor mode is **listen-only** — you receive PTT audio but cannot transmit
- Multiple groups can be monitored simultaneously
- Monitoring does not affect the active group — you stay in your current group
- `GroupIsMonitor()` returns per-group monitor status

---

## 7. Force Exit (Stun)

### Mechanism

1. Dispatcher sends `ForceUserExit` (type **0x16**) with array of user IDs
2. Timeout = **3x normal session timeout** (longer than usual operations)
3. Server sends `OnForceExit` notification to stunned users
4. Stunned radio goes offline

### Response

- Success: server returns list of affected user IDs as JSON array
- Timeout (0x88): returns error to dispatcher UI
- The stunned radio receives the force exit notification and disconnects
- Whether the radio auto-reconnects depends on server-side account configuration

---

## 8. User Status

### When Updates Are Sent

- **On login success**: client sends `ModifyUserStatus` (type **0x6A**) with current status
- **On user status change**: via direct API call
- **On disconnect**: server infers offline status (no explicit message from disconnecting client)

### Server Push

- Server sends `OnNotifyUserModifyStatus` (type 0x25) to all connected clients when a user's status changes
- Payload: user ID (4 bytes) + status byte (1 byte)

---

## 9. GPS Reporting

### Data Format

- GPS data is transmitted as a text string (up to 1500 bytes)
- Format prefix: `"pos:"` followed by comma-separated values
- Sent via UDP to the content server address
- APRS format also supported: `"%s>APRS,TCPIP*:@%02d%02d%02dz%s/%s%c%s"`

### Timing

- Periodic 5-second GPS heartbeat timer (TCP path)
- Forced send every 15 seconds (3 × 5s cycles) even without position change
- GPS interval from server: upper 16 bits of privilege field in login response (in seconds)
- If GPS privilege bit 3 is not set, GPS reporting is disabled

### Offline Behavior

- If not connected when GPS fix arrives: saved to offline buffer via `SaveOffLineLocation()`
- Uploaded when connection is re-established

---

## 10. Audio Encryption

### Key Exchange

- During login, the Challenge message contains `keyUpType` (upload encryption type) and `keyGetType` (download encryption type)
- Per-group keys are fetched via HTTP (`CHttpEncryptHandler`)
- Key validation is tied to `CHttpValidateHandler`
- Keys have a deadline (`CKeyDeadline`), checked on each heartbeat cycle

### Encryption Process

1. Check `IsEncrypted()` flag — if not set, audio sent in plaintext
2. Check `IsUpdate()` — if key needs refresh, request new keys via `RequestGroupsKey()`
3. Get per-group key via `GetGroupKey(groupId)` — if missing, request via HTTP
4. Prepend header: key type byte + group ID (4 bytes) + original data length (2 bytes)
5. Pad data to 16-byte boundary (AES block size)
6. Call `Encrypt(output, input, padded_length, key)`
7. Max encrypted payload: 1024 bytes

### Cipher Types

| Type | Cipher |
|------|--------|
| 0x02 | AES-ECB |
| 0x06 | SM4-ECB |

### Key Scope

- **Per-group keys**: fetched from server per group ID, stored in `CContentCrypt`
- **Org-wide key**: used for video encryption (`GetOrgKey`)
- Keys rotate based on server-configured deadline

---

## 11. Voice Messages

### Playback

1. `PlayNoteVoice(noteId, mode)` initiates playback (mode 0, 1, or 2)
2. If TTS is active, stops TTS first and waits 150ms before playing
3. Retry mechanism: if TTS is still speaking after stop, retries with 150ms delay
4. Audio data played via `CEMAudioUtility::PlayNoteData()`

### Query API

| Function | Purpose |
|----------|---------|
| `GetNoteCount()` | Number of stored messages |
| `GetNoteData(i)` | Audio data for message i |
| `GetNoteDatetime(i)` | Timestamp |
| `GetNoteSrc(i)` | Sender info |
| `GetNoteUrl(i)` | Download URL |
| `GetNoteType(i)` | Message type |
| `GetNoteLength(i)` | Duration |
| `GetPendingNote()` | Unread messages |

### Incoming Notifications

- `OnNotifyVoiceIncome` / `OnNotifyVoiceIncome2` — voice message arrival
- `OnNotifyNoteIncome` / `OnNotifyNoteIncome2` — general note/message arrival

---

## 12. SOS / Emergency

### Trigger Flow

1. User presses SOS button (or ManDown/FallDetection triggers automatically)
2. `SendSOSManager` fetches nearby users via HTTP `getUsersPosition()` API
3. Parses response as position list, selects up to 10 nearest users
4. Creates temp group with those users via `inviteTmpGroup()`
5. User then uses normal PTT in the temp group to communicate

### SOS Does NOT

- Auto-PTT at the protocol level (it's a client-side feature via `needStartPTTAfterSendSOS()`)
- Override floor control
- Send a special SOS packet type

### SOS Creates a Temp Group

The emergency mechanism is **temp group creation with nearby users**, not a special protocol message. The "SOS" behavior is entirely client-side logic built on top of temp groups.

### ManDown / Fall Detection

- `FallDetectionManager` uses Android sensors to detect falls
- Triggers the same `SendSOSManager` path
- Timer-based detection for ManDown (inactivity timeout)

### Alert Types (client-side)

| Type | Trigger |
|------|---------|
| SOS | Manual button press |
| ManDown | Inactivity timeout |
| FallDetection | Accelerometer spike |
| CallAlarm | Incoming call alarm |

---

## 13. Reconnect

### Stock Firmware Behavior

The stock radio uses **fixed-interval retries**, not exponential backoff:

| Path | Interval | Trigger |
|------|----------|---------|
| `RetryLogin_1()` | 1000ms | Fast retry (network glitch) |
| `RetryLogin_2()` | 2000ms | Medium retry (re-opens network) |
| `RetryLogin(3, 1)` | 4000ms | Standard retry (login failure) |

- No exponential backoff in the stock firmware
- Server rotation: cycles through up to 4 server addresses, resets to 0 after all tried
- Login timeout: 7 seconds per attempt
- Logout retry: up to 3 attempts, then hard stop

### libpoc Enhancement

Our implementation uses exponential backoff (2s → 4s → 8s → ... → 512s → give up) which is more network-friendly than the stock firmware's aggressive flat retry.

---

## 14. Audio FEC

### Architecture

The FEC encoder/decoder uses a **Reed-Solomon-like** scheme:

- **5 data symbols + 5 parity symbols** per FEC group (50% redundancy)
- Each symbol is **112 bytes** (0x70)
- Created via `NewFecEncoder(callback, buffer, 0x70, 5, 5, 0x28, 4)`

### Frame Format

Each FEC frame has:
- **1 byte status**: 0=FRAME_START, 1=FRAME_MIDDLE, 2=FRAME_END, 3=FRAME_TOTAL
- **2 bytes length** (big-endian)
- For FRAME_START and FRAME_TOTAL: **8 extra header bytes** (4 bytes data length + 4 bytes parameter)
- **Payload**: max 109 bytes for START, 108 bytes for MIDDLE/END

### Encoding

1. Audio frames are accumulated into the FEC encoder
2. When 5 data frames are collected, 5 parity frames are generated
3. All 10 frames (5 data + 5 parity) are sent
4. Codec type byte offset = `codec_type + 0x0A` (10 = direct mode, bypasses FEC)

### Decoding

1. Frames are received and added to audio cache
2. Packet IDs and group numbers tracked for reordering
3. When a complete FEC group is available, decoded
4. Missing data frames reconstructed from parity
5. Decoded audio played via `RecvAudioFecSteam()`

### Direct Mode

When codec type == 0x0A (10), FEC is bypassed entirely:
- Audio sent directly via `SendAudioContent()` with fixed 120-byte (0x78) payload
- No parity frames generated

---

## Protocol Message Type Table

These are the actual type bytes at offset 0x0B in the message header, as observed in the decompiled firmware:

| Byte | Command | Direction |
|------|---------|-----------|
| 0x01 | Login | C→S |
| 0x04 | Validate (HMAC-SHA1) | C→S |
| 0x08 | EnterGroup / LeaveGroup (gid=-1) | C→S |
| 0x09 | AnswerInviteTmpGroup | C→S |
| 0x0D | NatMap (heartbeat) | C↔S |
| 0x0E | Ack | S→C |
| 0x0F | ModifyName | C→S |
| 0x16 | ForceUserExit | C→S |
| 0x1F | InviteTmpGroup | C→S |
| 0x24 | AddMonitorGroup | C→S |
| 0x25 | RemoveMonitorGroup | C→S |
| 0x28 | StartPTT / BCastStartPTT | C→S |
| 0x29 | EndPTT / BCastEndPTT | C→S |
| 0x4D | GroupBCastStartPTT | C→S |
| 0x4E | GroupBCastEndPTT | C→S |
| 0x52 | UserUploadMsg | C→S |
| 0x6A | ModifyUserStatusEx | C→S |

### Server → Client Notification Types

These are the cmd bytes at offset 1 in server→client messages:

| Byte | Notification |
|------|-------------|
| 0x01 | ResponseResult (generic ACK/NACK) |
| 0x06 | Heartbeat ACK |
| 0x07 | Challenge (login nonce) |
| 0x0B | UserData (group list after login) |
| 0x0D | PTT start notification |
| 0x0F | PTT end notification |
| 0x11 | User entered group |
| 0x13 | TmpGroup invite |
| 0x15 | TmpGroup enter |
| 0x17 | TmpGroup leave |
| 0x19 | TmpGroup reject |
| 0x1D | Package ACK |
| 0x1F | User name changed |
| 0x21 | User default group changed |
| 0x25 | User status changed |
| 0x27 | User privilege changed |
| 0x29 | User priority changed |
| 0x2B | User removed |
| 0x2D | Force exit (stun) |
| 0x33 | Group added |
| 0x35 | Group removed |
| 0x37 | Group renamed |
| 0x39 | Group master changed |
| 0x3B | User added to group |
| 0x3D | User removed from group |
| 0x43 | Extended data (text messages) |
| 0x4D | Pull to group |
| 0x5D | PTT start (primary) |
| 0x5E | PTT end (primary) |
| 0x66 | PTT start (alternate) |
| 0x67 | PTT end (alternate) |
| 0x70 | Note/message income |
| 0x72 | Voice message income |
| 0x73 | Voice message notification |
| 0x80 | Content data (audio on TCP) |
| 0x84 | Multicast data |

---

## Key Differences: Stock Firmware vs libpoc

| Feature | Stock Firmware | libpoc |
|---------|---------------|--------|
| Reconnect | Fixed 1-4s retry, no backoff | Exponential backoff 2s-512s, then give up |
| Logging | No structured logging | Leveled (ERROR/WARN/INFO/DEBUG) with callback |
| Threading | Single-threaded with callbacks | Dedicated I/O thread + lock-free rings |
| Audio codec | Speex + EVRC | Speex only |
| Encryption | AES-ECB + SM4-ECB with HTTP key exchange | AES-ECB + SM4-ECB (keys from login challenge) |
| FEC | 5+5 Reed-Solomon (50% redundancy) | XOR parity (33% redundancy, simpler) |
| GPS | UDP to content server + APRS | TCP heartbeat |
| SOS | Temp group with nearby users via HTTP geolocation | SOS message type (no geolocation) |
