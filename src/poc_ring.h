/*
 * poc_ring.h — Lock-free SPSC ring buffer for audio frames
 *
 * Single-producer, single-consumer. No locks. Uses C11 atomics.
 * Each slot holds one 20ms audio frame (160 int16 samples = 320 bytes)
 * plus metadata (speaker_id, group_id).
 */

#ifndef POC_RING_H
#define POC_RING_H

#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define POC_RING_FRAME_SAMPLES  160

typedef struct {
    int16_t  samples[POC_RING_FRAME_SAMPLES];
    uint32_t speaker_id;
    uint32_t group_id;
} poc_ring_frame_t;

typedef struct {
    poc_ring_frame_t *buf;
    int               capacity;    /* must be power of 2 */
    int               mask;        /* capacity - 1 */
    atomic_uint       head;        /* write index (producer) */
    atomic_uint       tail;        /* read index (consumer) */
} poc_ring_t;

static inline int poc_ring_init(poc_ring_t *r, int capacity)
{
    /* Round up to power of 2 */
    int cap = 1;
    while (cap < capacity) cap <<= 1;

    r->buf = (poc_ring_frame_t *)calloc(cap, sizeof(poc_ring_frame_t));
    if (!r->buf) return -1;

    r->capacity = cap;
    r->mask = cap - 1;
    atomic_store(&r->head, 0);
    atomic_store(&r->tail, 0);
    return 0;
}

static inline void poc_ring_destroy(poc_ring_t *r)
{
    free(r->buf);
    r->buf = NULL;
}

static inline int poc_ring_count(const poc_ring_t *r)
{
    return (int)(atomic_load(&r->head) - atomic_load(&r->tail));
}

static inline bool poc_ring_full(const poc_ring_t *r)
{
    return poc_ring_count(r) >= r->capacity;
}

static inline bool poc_ring_empty(const poc_ring_t *r)
{
    return atomic_load(&r->head) == atomic_load(&r->tail);
}

/*
 * Push one frame. Returns true on success, false if full.
 * Called from producer thread only.
 */
static inline bool poc_ring_push(poc_ring_t *r,
                                 const int16_t *samples, int n_samples,
                                 uint32_t speaker_id, uint32_t group_id)
{
    if (poc_ring_full(r))
        return false;

    unsigned idx = atomic_load_explicit(&r->head, memory_order_relaxed) & r->mask;
    poc_ring_frame_t *f = &r->buf[idx];

    int copy = n_samples < POC_RING_FRAME_SAMPLES ? n_samples : POC_RING_FRAME_SAMPLES;
    memcpy(f->samples, samples, copy * sizeof(int16_t));
    if (copy < POC_RING_FRAME_SAMPLES)
        memset(f->samples + copy, 0, (POC_RING_FRAME_SAMPLES - copy) * sizeof(int16_t));

    f->speaker_id = speaker_id;
    f->group_id = group_id;

    atomic_fetch_add_explicit(&r->head, 1, memory_order_release);
    return true;
}

/*
 * Pop one frame. Returns true on success, false if empty.
 * Called from consumer thread only.
 */
static inline bool poc_ring_pop(poc_ring_t *r, poc_ring_frame_t *out)
{
    if (poc_ring_empty(r))
        return false;

    unsigned idx = atomic_load_explicit(&r->tail, memory_order_relaxed) & r->mask;
    *out = r->buf[idx];

    atomic_fetch_add_explicit(&r->tail, 1, memory_order_release);
    return true;
}

/*
 * Flush — discard all frames. Safe from consumer side.
 */
static inline void poc_ring_flush(poc_ring_t *r)
{
    atomic_store(&r->tail, atomic_load(&r->head));
}

#endif /* POC_RING_H */
