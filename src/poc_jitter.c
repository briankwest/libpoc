/*
 * poc_jitter.c — Implementation of the receive-side jitter buffer.
 *
 * Algorithm: each push inserts the encoded packet at slot[seq % cap]
 * and then drains in-order frames from the next-expected sequence.
 *
 *   - normal frame  : slot[next_seq] is filled with seq == next_seq
 *                     → decode, emit, advance next_seq
 *   - one packet lost: slot[next_seq] empty, slot[next_seq+1] filled
 *                     → decode_fec(packet[next_seq+1]) — Opus extracts
 *                       the LBRR copy of frame next_seq from N+1's
 *                       payload — emit, advance. Don't consume N+1
 *                       yet; next loop iteration picks it up via the
 *                       normal path.
 *   - longer outage : neither N nor N+1 is filled. Stop draining and
 *                     wait for more packets, OR (if we're more than
 *                     `cap` ahead) force-advance with PLC to keep the
 *                     buffer bounded.
 *
 * Sequence math uses signed 16-bit deltas to handle wrap-around at
 * 65 536 (≈22 minutes at 50 fps — well past any single PTT session).
 */

#include "poc_jitter.h"
#include "poc_internal.h"  /* poc_log_at, POC_LOG_* */
#include <stdlib.h>
#include <string.h>

#define DEFAULT_DEPTH_FRAMES  6   /* 120 ms at 20 ms/frame */

static inline int seq_delta(uint16_t a, uint16_t b)
{
    return (int)(int16_t)(a - b);
}

int poc_jb_init(poc_jb_t *jb, int depth_frames)
{
    if (depth_frames <= 0) depth_frames = DEFAULT_DEPTH_FRAMES;
    memset(jb, 0, sizeof(*jb));
    jb->slots = calloc((size_t)depth_frames, sizeof(poc_jb_slot_t));
    if (!jb->slots) return -1;
    jb->cap = depth_frames;
    return 0;
}

void poc_jb_destroy(poc_jb_t *jb)
{
    if (!jb) return;
    free(jb->slots);
    jb->slots = NULL;
    jb->cap = 0;
    jb->initialized = false;
}

void poc_jb_reset(poc_jb_t *jb)
{
    if (!jb || !jb->slots) return;
    for (int i = 0; i < jb->cap; i++) jb->slots[i].filled = false;
    jb->initialized = false;
    jb->speaker_id = 0;
    jb->next_seq = 0;
}

static void emit_normal(poc_jb_t *jb, poc_codec_t *codec,
                        const uint8_t *data, int len,
                        poc_jb_emit_fn emit, void *ud)
{
    int16_t pcm[POC_CODEC_MAX_FRAME_SAMPLES];
    int n = poc_codec_decode(codec, data, len, pcm, POC_CODEC_MAX_FRAME_SAMPLES);
    if (n > 0) {
        emit(pcm, n, jb->speaker_id, ud);
        jb->decoded++;
    }
}

static void emit_plc(poc_jb_t *jb, poc_codec_t *codec,
                     poc_jb_emit_fn emit, void *ud)
{
    int16_t pcm[POC_CODEC_MAX_FRAME_SAMPLES];
    int n = poc_codec_decode(codec, NULL, 0, pcm, POC_CODEC_MAX_FRAME_SAMPLES);
    if (n > 0) {
        emit(pcm, n, jb->speaker_id, ud);
        jb->plc_filled++;
    }
}

/* FEC-recover a single missing frame from the next packet's LBRR.
 * Falls back to PLC if Opus reports no redundancy was carried. */
static void emit_fec_or_plc(poc_jb_t *jb, poc_codec_t *codec,
                            const uint8_t *next_data, int next_len,
                            poc_jb_emit_fn emit, void *ud)
{
    int16_t pcm[POC_CODEC_MAX_FRAME_SAMPLES];
    int n = poc_codec_decode_fec(codec, next_data, next_len,
                                 pcm, POC_CODEC_MAX_FRAME_SAMPLES);
    if (n > 0) {
        emit(pcm, n, jb->speaker_id, ud);
        jb->fec_recovered++;
        return;
    }
    emit_plc(jb, codec, emit, ud);
}

void poc_jb_push(poc_jb_t *jb, poc_codec_t *codec,
                 uint32_t speaker_id, uint16_t seq,
                 const uint8_t *data, int len,
                 poc_jb_emit_fn emit, void *ud)
{
    if (!jb->slots || !codec || !emit || !data || len <= 0)
        return;
    if ((size_t)len > sizeof(jb->slots[0].data)) {
        jb->dropped_late++;  /* misuse — packet too big */
        return;
    }

    jb->pushed++;

    /* Speaker change (or first packet) — reset and resync to this seq. */
    if (!jb->initialized || speaker_id != jb->speaker_id) {
        poc_jb_reset(jb);
        jb->speaker_id = speaker_id;
        jb->next_seq = seq;
        jb->initialized = true;
    }

    /* Late packet — already past it. Drop. */
    if (seq_delta(seq, jb->next_seq) < 0) {
        jb->dropped_late++;
        return;
    }

    /* Force-advance if the new packet is more than `cap-1` ahead.
     * This bounds the buffer and prevents the index from outrunning
     * the ring on extended bursts of lost packets. */
    int ahead = seq_delta(seq, jb->next_seq);
    if (ahead >= jb->cap) {
        int catchup = ahead - (jb->cap - 1);
        for (int i = 0; i < catchup; i++) {
            int next_idx = (uint16_t)(jb->next_seq + 1) % jb->cap;
            poc_jb_slot_t *nxt = &jb->slots[next_idx];
            if (nxt->filled && nxt->seq == (uint16_t)(jb->next_seq + 1)) {
                emit_fec_or_plc(jb, codec, nxt->data, nxt->len, emit, ud);
            } else {
                emit_plc(jb, codec, emit, ud);
            }
            jb->next_seq++;
            jb->forced_advance++;
        }
    }

    /* Insert the new packet. Duplicate detection: same seq already
     * filled means a retransmit or wrap collision — drop. */
    int idx = seq % jb->cap;
    poc_jb_slot_t *slot = &jb->slots[idx];
    if (slot->filled && slot->seq == seq) {
        jb->dropped_dup++;
        return;
    }
    slot->filled = true;
    slot->seq = seq;
    slot->len = len;
    memcpy(slot->data, data, (size_t)len);

    /* Drain contiguous frames from next_seq, FEC-recovering single gaps. */
    for (;;) {
        int cur_idx = jb->next_seq % jb->cap;
        poc_jb_slot_t *cur = &jb->slots[cur_idx];

        if (cur->filled && cur->seq == jb->next_seq) {
            emit_normal(jb, codec, cur->data, cur->len, emit, ud);
            cur->filled = false;
            jb->next_seq++;
            continue;
        }

        /* current slot empty — peek at next. If filled, FEC-recover. */
        int next_idx = (uint16_t)(jb->next_seq + 1) % jb->cap;
        poc_jb_slot_t *nxt = &jb->slots[next_idx];
        if (nxt->filled && nxt->seq == (uint16_t)(jb->next_seq + 1)) {
            emit_fec_or_plc(jb, codec, nxt->data, nxt->len, emit, ud);
            jb->next_seq++;
            continue;  /* next iteration consumes the N+1 packet normally */
        }

        break;  /* nothing to drain — wait for more packets */
    }
}
