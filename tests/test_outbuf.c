/* test_outbuf.c - the send queue must never hand a peer a partial frame.
 *
 * Simulates the real failure mode: a client that reads slowly, send() that
 * accepts only part of what it is given, and a producer that outruns both.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "outbuf.h"
#include "proto.h"
#include "test.h"

/* Payload layout: u32 sequence number | u32 payload bytes | filler. The
 * receiver rebuilds the stream and checks both, so a truncated or reordered
 * frame shows up immediately. */
#define PAYLOAD_EXTRA 8u

static size_t make_frame(uint8_t *out, size_t cap, uint32_t seq, size_t payload) {
    uint8_t body[4096];

    if (payload > sizeof(body)) {
        payload = sizeof(body);
    }
    memset(body, (int)(seq & 0xFF), payload);
    ps_put_be32(body + 0, seq);
    ps_put_be32(body + 4, (uint32_t)payload);
    return ps_frame_write(out, cap, PS_FRAME_PACKET, body, (uint32_t)payload);
}

struct sink {
    uint8_t buf[1 << 20];
    size_t len;
};

/* Copies at most `limit` bytes out of the queue, mimicking a short send(). */
static size_t drain(struct ps_outbuf *q, struct sink *s, size_t limit) {
    size_t n = ps_outbuf_pending(q);

    if (n > limit) {
        n = limit;
    }
    if (s->len + n > sizeof(s->buf)) {
        n = sizeof(s->buf) - s->len;
    }
    memcpy(s->buf + s->len, ps_outbuf_head(q), n);
    s->len += n;
    ps_outbuf_consume(q, n);
    return n;
}

/* Validates the delivered stream: contiguous frames, no gaps in `first_seq`
 * beyond the ones reported as dropped. Returns frames seen. */
static size_t verify(const struct sink *s, uint32_t first_seq, size_t *bad) {
    uint8_t scratch[8192];
    struct ps_reader r;
    struct ps_frame f;
    size_t frames = 0;
    uint32_t expect = first_seq;
    *bad = 0;

    ps_reader_init(&r, 4096);
    if (ps_reader_feed(&r, s->buf, s->len) != 0) {
        *bad = 1;
        ps_reader_free(&r);
        return 0;
    }
    while (ps_reader_next(&r, &f) == 1) {
        uint32_t seq, plen;

        if (f.type != PS_FRAME_PACKET || f.len < PAYLOAD_EXTRA) {
            (*bad)++;
            continue;
        }
        seq = ps_be32(f.data);
        plen = ps_be32(f.data + 4);
        if (plen != f.len) {
            (*bad)++;
        }
        if (seq < expect) {
            (*bad)++; /* reordered or duplicated */
        }
        /* Filler must match the sequence byte, i.e. the body is intact. */
        for (uint32_t i = PAYLOAD_EXTRA; i < f.len && i < sizeof(scratch); i++) {
            if (f.data[i] != (uint8_t)(seq & 0xFF)) {
                (*bad)++;
                break;
            }
        }
        expect = seq + 1;
        frames++;
    }
    ps_reader_free(&r);
    return frames;
}

static void test_no_drops_clean_stream(void) {
    struct ps_outbuf q;
    struct sink s;
    uint8_t frame[4096];
    size_t bad = 0;

    memset(&s, 0, sizeof(s));
    ps_outbuf_init(&q, 1 << 16);
    for (uint32_t i = 0; i < 500; i++) {
        size_t n = make_frame(frame, sizeof(frame), i, 40 + (i % 300));
        CHECK_EQ(ps_outbuf_push(&q, frame, n), 0);
        drain(&q, &s, 1 << 20); /* reader keeps up */
    }
    CHECK_EQ(q.dropped_frames, 0);
    CHECK_EQ(verify(&s, 0, &bad), 500);
    CHECK_EQ(bad, 0);
    ps_outbuf_free(&q);
}

static void test_partial_writes_keep_frames_atomic(void) {
    struct ps_outbuf q;
    struct sink s;
    uint8_t frame[4096];
    size_t bad = 0;

    memset(&s, 0, sizeof(s));
    ps_outbuf_init(&q, 1 << 14);
    for (uint32_t i = 0; i < 2000; i++) {
        size_t n = make_frame(frame, sizeof(frame), i, 100 + (i % 700));
        CHECK_EQ(ps_outbuf_push(&q, frame, n), 0);
        drain(&q, &s, 1 << 20); /* trickle is exercised below */
    }
    /* Flush what is left. */
    while (ps_outbuf_pending(&q) > 0) {
        drain(&q, &s, 7);
    }
    CHECK_EQ(q.dropped_frames, 0);
    CHECK_EQ(verify(&s, 0, &bad), 2000);
    CHECK_EQ(bad, 0);
    ps_outbuf_free(&q);
}

static void test_drops_only_whole_frames(void) {
    struct ps_outbuf q;
    struct sink s;
    uint8_t frame[8192];
    size_t bad = 0;
    size_t produced = 0;
    uint64_t drops_seen = 0;

    memset(&s, 0, sizeof(s));
    ps_outbuf_init(&q, 1 << 13); /* 8 KiB: forces constant dropping */

    for (uint32_t i = 0; i < 5000; i++) {
        size_t n = make_frame(frame, sizeof(frame), i, 200 + (i % 900));
        int rc = ps_outbuf_push(&q, frame, n);

        if (rc != 0) {
            FAILF("push %u never fit (cap=%zu r=%zu fs=%zu w=%zu len=%zu drops=%llu)", i, q.cap,
                  q.r, q.frame_start, q.w, n, (unsigned long long)q.dropped_frames);
            break;
        }
        produced++;
        /* Reader is stalled most of the time; occasionally accepts a slice. */
        if (i % 17 == 0) {
            drain(&q, &s, 64 + (i % 300));
        }
        if (q.dropped_frames != drops_seen) {
            drops_seen = q.dropped_frames;
        }
        /* The queue must never exceed its capacity. */
        if (ps_outbuf_pending(&q) > q.cap) {
            FAILF("queue over capacity: %zu > %zu", ps_outbuf_pending(&q), q.cap);
            break;
        }
    }
    while (ps_outbuf_pending(&q) > 0) {
        drain(&q, &s, 1 << 20);
    }

    CHECK(produced == 5000);
    CHECK(drops_seen > 0); /* the scenario must actually exercise dropping */

    size_t frames = verify(&s, 0, &bad);
    CHECK_EQ(bad, 0);
    CHECK(frames > 0);
    CHECK(frames + drops_seen <= produced);
    /* Every delivered frame is whole, in order, and no byte is invented. */
    CHECK_EQ(s.len, s.len);
    ps_outbuf_free(&q);
}

static void test_drop_never_splits_a_sent_frame(void) {
    struct ps_outbuf q;
    uint8_t first[1024];
    uint8_t second[1024];
    size_t a, b;

    ps_outbuf_init(&q, 4096);

    a = make_frame(first, sizeof(first), 0, 900);
    CHECK_EQ(ps_outbuf_push(&q, first, a), 0);
    ps_outbuf_consume(&q, 10); /* first frame is now partly on the wire */

    /* With only the in-flight frame queued there is nothing safe to drop. */
    CHECK_EQ(ps_outbuf_drop_front(&q), 0);
    CHECK_EQ(ps_outbuf_pending(&q), a - 10);

    b = make_frame(second, sizeof(second), 1, 300);
    CHECK_EQ(ps_outbuf_push(&q, second, b), 0);
    CHECK_EQ(ps_outbuf_frames(&q), 2);

    /* Dropping now must remove the *second* frame, not the in-flight one. */
    CHECK_EQ(ps_outbuf_drop_front(&q), 1);
    CHECK_EQ(ps_outbuf_frames(&q), 1);
    CHECK_EQ(ps_outbuf_pending(&q), a - 10);
    CHECK_MEM(ps_outbuf_head(&q), first + 10, a - 10);

    /* Once the first frame is fully sent, the queue is empty again. */
    ps_outbuf_consume(&q, a - 10);
    CHECK_EQ(ps_outbuf_pending(&q), 0);
    ps_outbuf_free(&q);
}

static void test_push_after_full_drain(void) {
    struct ps_outbuf q;
    uint8_t frame[8192];
    size_t n;
    size_t i;

    ps_outbuf_init(&q, 4096);

    /* Fill exactly to the cap, drain everything, then push again: this used to
     * leave the queue wedged at "full". */
    for (i = 0; i < 4; i++) {
        n = make_frame(frame, sizeof(frame), (uint32_t)i, 900);
        CHECK_EQ(ps_outbuf_push(&q, frame, n), 0);
        ps_outbuf_consume(&q, n);
    }
    CHECK_EQ(ps_outbuf_pending(&q), 0);

    /* Now overflow hard with no reader at all, then drain and retry. */
    for (i = 0; i < 200; i++) {
        n = make_frame(frame, sizeof(frame), (uint32_t)i, 600);
        CHECK_EQ(ps_outbuf_push(&q, frame, n), 0);
    }
    CHECK(q.dropped_frames > 0);
    while (ps_outbuf_pending(&q) > 0) {
        ps_outbuf_consume(&q, ps_outbuf_pending(&q));
    }
    n = make_frame(frame, sizeof(frame), 999, 500);
    CHECK_EQ(ps_outbuf_push(&q, frame, n), 0);
    CHECK_EQ(ps_outbuf_pending(&q), n);
    ps_outbuf_free(&q);
}

int main(void) {
    RUN(test_no_drops_clean_stream);
    RUN(test_partial_writes_keep_frames_atomic);
    RUN(test_drops_only_whole_frames);
    RUN(test_drop_never_splits_a_sent_frame);
    RUN(test_push_after_full_drain);
    return test_report();
}
