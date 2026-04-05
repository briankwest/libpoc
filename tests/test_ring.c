/*
 * test_ring.c — Tests for ring buffer and event queue
 */

#include "poc_internal.h"
#include <string.h>
#include <stdlib.h>

extern void test_begin(const char *name);
extern void test_assert(int cond, const char *msg);
extern void test_end(void);

void test_ring(void)
{
    /* ── Ring buffer tests ────────────────────────────────────────── */

    {
        test_begin("ring: init and empty");
        poc_ring_t r;
        int rc = poc_ring_init(&r, 8);
        int ok = (rc == 0 &&
                  poc_ring_empty(&r) &&
                  !poc_ring_full(&r) &&
                  poc_ring_count(&r) == 0);
        test_assert(ok, "init cap=8: empty, not full, count=0");
        poc_ring_destroy(&r);
    }

    {
        test_begin("ring: push and pop");
        poc_ring_t r;
        poc_ring_init(&r, 8);

        int16_t samples[160];
        for (int i = 0; i < 160; i++)
            samples[i] = (int16_t)(i * 3);

        bool pushed = poc_ring_push(&r, samples, 160, 100, 200);

        poc_ring_frame_t frame;
        bool popped = poc_ring_pop(&r, &frame);

        int ok = (pushed && popped &&
                  frame.n_samples == 160 &&
                  memcmp(frame.samples, samples, 160 * sizeof(int16_t)) == 0);
        test_assert(ok, "push/pop roundtrip matches");
        poc_ring_destroy(&r);
    }

    {
        test_begin("ring: full detection");
        poc_ring_t r;
        poc_ring_init(&r, 8);

        int16_t samples[160];
        memset(samples, 0, sizeof(samples));

        bool all_pushed = true;
        for (int i = 0; i < 8; i++) {
            if (!poc_ring_push(&r, samples, 160, 0, 0))
                all_pushed = false;
        }

        bool is_full = poc_ring_full(&r);
        bool overflow = poc_ring_push(&r, samples, 160, 0, 0);

        test_assert(all_pushed && is_full && !overflow,
                    "8 pushes fill cap=8, 9th returns false");
        poc_ring_destroy(&r);
    }

    {
        test_begin("ring: flush clears");
        poc_ring_t r;
        poc_ring_init(&r, 8);

        int16_t samples[160];
        memset(samples, 0, sizeof(samples));

        for (int i = 0; i < 4; i++)
            poc_ring_push(&r, samples, 160, 0, 0);

        poc_ring_flush(&r);
        test_assert(poc_ring_empty(&r) && poc_ring_count(&r) == 0,
                    "flush makes ring empty");
        poc_ring_destroy(&r);
    }

    {
        test_begin("ring: n_samples preserved");
        poc_ring_t r;
        poc_ring_init(&r, 8);

        int16_t samples[320];
        memset(samples, 0, sizeof(samples));

        poc_ring_push(&r, samples, 320, 0, 0);

        poc_ring_frame_t frame = {0};
        poc_ring_pop(&r, &frame);
        test_assert(frame.n_samples == 320, "n_samples==320 after pop");
        poc_ring_destroy(&r);
    }

    {
        test_begin("ring: speaker_id and group_id preserved");
        poc_ring_t r;
        poc_ring_init(&r, 8);

        int16_t samples[160];
        memset(samples, 0, sizeof(samples));

        poc_ring_push(&r, samples, 160, 42, 99);

        poc_ring_frame_t frame = {0};
        poc_ring_pop(&r, &frame);
        test_assert(frame.speaker_id == 42 && frame.group_id == 99,
                    "metadata roundtrip");
        poc_ring_destroy(&r);
    }

    {
        test_begin("ring: wrap around");
        poc_ring_t r;
        poc_ring_init(&r, 4);

        int16_t samples[160];
        int ok = 1;

        /* Push and pop more than capacity to force wrap */
        for (int round = 0; round < 3; round++) {
            for (int i = 0; i < 4; i++) {
                memset(samples, 0, sizeof(samples));
                samples[0] = (int16_t)(round * 4 + i);
                poc_ring_push(&r, samples, 160, 0, 0);
            }
            for (int i = 0; i < 4; i++) {
                poc_ring_frame_t frame;
                memset(&frame, 0, sizeof(frame));
                poc_ring_pop(&r, &frame);
                if (frame.samples[0] != (int16_t)(round * 4 + i))
                    ok = 0;
            }
        }

        test_assert(ok, "FIFO order preserved across wrap");
        poc_ring_destroy(&r);
    }

    {
        test_begin("ring: destroy");
        poc_ring_t r;
        poc_ring_init(&r, 8);
        poc_ring_destroy(&r);
        test_assert(r.buf == NULL, "buf is NULL after destroy");
    }

    /* ── Event queue tests ────────────────────────────────────────── */

    {
        test_begin("evt: init and empty");
        poc_evt_queue_t q;
        poc_evt_init(&q);
        poc_event_t out;
        test_assert(!poc_evt_pop(&q, &out), "pop on empty returns false");
    }

    {
        test_begin("evt: push and pop");
        poc_evt_queue_t q;
        poc_evt_init(&q);

        poc_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.type = POC_EVT_STATE_CHANGE;
        evt.state_change.state = 42;

        poc_evt_push(&q, &evt);

        poc_event_t out;
        bool ok = poc_evt_pop(&q, &out);
        test_assert(ok && out.type == POC_EVT_STATE_CHANGE &&
                    out.state_change.state == 42,
                    "push/pop roundtrip");
    }

    {
        test_begin("evt: FIFO order");
        poc_evt_queue_t q;
        poc_evt_init(&q);

        poc_event_t evt;
        memset(&evt, 0, sizeof(evt));

        evt.type = POC_EVT_STATE_CHANGE;
        poc_evt_push(&q, &evt);
        evt.type = POC_EVT_LOGIN_ERROR;
        poc_evt_push(&q, &evt);
        evt.type = POC_EVT_PTT_GRANTED;
        poc_evt_push(&q, &evt);

        poc_event_t out;
        memset(&out, 0, sizeof(out));
        poc_evt_pop(&q, &out);
        int ok = (out.type == POC_EVT_STATE_CHANGE);
        poc_evt_pop(&q, &out);
        ok = ok && (out.type == POC_EVT_LOGIN_ERROR);
        poc_evt_pop(&q, &out);
        ok = ok && (out.type == POC_EVT_PTT_GRANTED);
        test_assert(ok, "events dequeue in push order");
    }

    {
        test_begin("evt: full detection");
        poc_evt_queue_t q;
        poc_evt_init(&q);

        poc_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.type = POC_EVT_STATE_CHANGE;

        bool all_pushed = true;
        for (int i = 0; i < POC_EVT_QUEUE_SIZE; i++) {
            if (!poc_evt_push(&q, &evt))
                all_pushed = false;
        }

        bool overflow = poc_evt_push(&q, &evt);
        test_assert(all_pushed && !overflow,
                    "64 pushes succeed, 65th returns false");
    }

    {
        test_begin("evt: message event preserves text");
        poc_evt_queue_t q;
        poc_evt_init(&q);

        poc_event_t evt;
        memset(&evt, 0, sizeof(evt));
        evt.type = POC_EVT_MESSAGE;
        evt.message.from_id = 12345;
        strncpy(evt.message.text, "Hello, PTT world!", sizeof(evt.message.text) - 1);

        poc_evt_push(&q, &evt);

        poc_event_t out;
        poc_evt_pop(&q, &out);
        test_assert(out.type == POC_EVT_MESSAGE &&
                    out.message.from_id == 12345 &&
                    strcmp(out.message.text, "Hello, PTT world!") == 0,
                    "message text roundtrip");
    }
}
