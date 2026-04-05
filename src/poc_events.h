/*
 * poc_events.h — Lock-free SPSC event queue
 *
 * The I/O thread produces events, poc_poll() consumes and fires callbacks.
 */

#ifndef POC_EVENTS_H
#define POC_EVENTS_H

#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    POC_EVT_STATE_CHANGE,
    POC_EVT_LOGIN_ERROR,
    POC_EVT_GROUPS_UPDATED,
    POC_EVT_PTT_START,
    POC_EVT_PTT_END,
    POC_EVT_PTT_GRANTED,
    POC_EVT_MESSAGE,
    POC_EVT_FORCE_EXIT,
    /* Phase 1: user status + group state */
    POC_EVT_USER_STATUS,
    POC_EVT_USER_REMOVED,
    /* Phase 2: temp groups + dispatch */
    POC_EVT_TMP_GROUP_INVITE,
    POC_EVT_PULL_TO_GROUP,
    /* Phase 3: voice messages + emergency */
    POC_EVT_VOICE_MESSAGE,
    POC_EVT_SOS,
    /* Messaging: receipts + typing */
    POC_EVT_MSG_DELIVERED,
    POC_EVT_MSG_READ,
    POC_EVT_TYPING,
    /* Server-side: decoded audio from PoC client */
    POC_EVT_AUDIO,
} poc_evt_type_t;

typedef struct {
    poc_evt_type_t type;
    union {
        struct { int state; } state_change;
        struct { int code; char msg[64]; } login_error;
        struct { uint32_t speaker_id; uint32_t group_id; char name[64]; } ptt_start;
        struct { uint32_t speaker_id; uint32_t group_id; } ptt_end;
        struct { bool granted; } ptt_granted;
        struct { uint32_t from_id; char text[256]; } message;
        struct { uint32_t user_id; int status; } user_status;
        struct { uint32_t user_id; } user_removed;
        struct { uint32_t group_id; uint32_t inviter_id; } tmp_group_invite;
        struct { uint32_t group_id; } pull_to_group;
        struct { uint32_t from_id; uint64_t note_id; char desc[128]; } voice_message;
        struct { uint32_t user_id; int alert_type; } sos;
        struct { uint32_t user_id; } msg_delivered;
        struct { uint32_t user_id; } msg_read;
        struct { uint32_t user_id; bool typing; } typing;
        struct { uint32_t speaker_id; uint32_t group_id;
                 int16_t pcm[160]; } audio;
    };
} poc_event_t;

#define POC_EVT_QUEUE_SIZE 64  /* must be power of 2 */

typedef struct {
    poc_event_t  buf[POC_EVT_QUEUE_SIZE];
    atomic_uint  head;
    atomic_uint  tail;
} poc_evt_queue_t;

static inline void poc_evt_init(poc_evt_queue_t *q)
{
    atomic_store(&q->head, 0);
    atomic_store(&q->tail, 0);
}

static inline bool poc_evt_push(poc_evt_queue_t *q, const poc_event_t *evt)
{
    unsigned h = atomic_load_explicit(&q->head, memory_order_relaxed);
    unsigned t = atomic_load_explicit(&q->tail, memory_order_acquire);
    if (h - t >= POC_EVT_QUEUE_SIZE)
        return false;  /* full */

    q->buf[h & (POC_EVT_QUEUE_SIZE - 1)] = *evt;
    atomic_fetch_add_explicit(&q->head, 1, memory_order_release);
    return true;
}

static inline bool poc_evt_pop(poc_evt_queue_t *q, poc_event_t *out)
{
    unsigned t = atomic_load_explicit(&q->tail, memory_order_relaxed);
    unsigned h = atomic_load_explicit(&q->head, memory_order_acquire);
    if (t == h)
        return false;  /* empty */

    *out = q->buf[t & (POC_EVT_QUEUE_SIZE - 1)];
    atomic_fetch_add_explicit(&q->tail, 1, memory_order_release);
    return true;
}

#endif /* POC_EVENTS_H */
