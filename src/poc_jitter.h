/*
 * poc_jitter.h — Receive-side jitter buffer for the PoC client
 *
 * Holds a small ring of encoded Opus packets keyed by sequence number.
 * Decodes them in order, fills single-packet gaps via Opus inband FEC
 * (LBRR redundancy carried in packet N+1 covers a lost frame N), and
 * extends to PLC for longer outages.
 *
 * Drain runs inline on each push: by the time poc_jb_push() returns,
 * any contiguous decodable frames have been emitted via the callback.
 * That keeps the design timer-free — packets in, PCM frames out.
 *
 * Single speaker at a time. The PoC protocol enforces one PTT floor
 * holder per group, so this matches the wire reality. A change of
 * speaker_id transparently resets the buffer.
 */

#ifndef POC_JITTER_H
#define POC_JITTER_H

#include <stdbool.h>
#include <stdint.h>
#include "poc_codec.h"

typedef struct {
    bool      filled;
    uint16_t  seq;
    int       len;
    /* +32 pad covers the encryption tag/iv when present. */
    uint8_t   data[POC_CODEC_MAX_ENCODED_SIZE + 32];
} poc_jb_slot_t;

typedef struct {
    poc_jb_slot_t *slots;
    int            cap;             /* ring depth in 20 ms frames */
    uint16_t       next_seq;        /* next sequence we will emit */
    bool           initialized;     /* false until the first push */
    uint32_t       speaker_id;      /* current sender; reset on change */

    /* Counters — purely diagnostic, surfaced via poc_jb_stats(). */
    uint32_t       pushed;
    uint32_t       decoded;
    uint32_t       fec_recovered;
    uint32_t       plc_filled;
    uint32_t       dropped_dup;
    uint32_t       dropped_late;
    uint32_t       forced_advance; /* slots > cap ahead, had to skip forward */
} poc_jb_t;

/* Fired by poc_jb_push() when a decoded PCM frame becomes available
 * in the correct order. n_samples is whatever the codec returns
 * (always 480 for Opus SWB). speaker_id is the current floor holder. */
typedef void (*poc_jb_emit_fn)(const int16_t *pcm, int n_samples,
                               uint32_t speaker_id, void *ud);

/* depth_frames ≤ 0 selects the default (6 frames = 120 ms). */
int  poc_jb_init(poc_jb_t *jb, int depth_frames);
void poc_jb_destroy(poc_jb_t *jb);
void poc_jb_reset(poc_jb_t *jb);

/* Insert an encoded (and decrypted, if encryption was negotiated)
 * packet. Drives draining inline so contiguous frames flow out via
 * `emit` before this function returns. */
void poc_jb_push(poc_jb_t *jb, poc_codec_t *codec,
                 uint32_t speaker_id, uint16_t seq,
                 const uint8_t *data, int len,
                 poc_jb_emit_fn emit, void *ud);

#endif /* POC_JITTER_H */
