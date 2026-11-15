/* outbuf.c - frame-atomic send queue.
 *
 * Invariants, in order of importance:
 *
 *   1. The bytes handed to the peer are always a sequence of whole frames.
 *   2. A frame whose bytes are (partly) on the wire can never be dropped - the
 *      peer would be left mid-frame, which desynchronises the stream.
 *   3. Therefore only wholly unsent frames may be discarded, and only when the
 *      queue is full.
 *   4. `r` is the send cursor, `frame_start` the start of the oldest frame that
 *      still has unsent bytes, so frame_start <= r <= w always holds.
 */
#include "outbuf.h"

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "proto.h"
#include "util.h"

void ps_outbuf_init(struct ps_outbuf *q, size_t cap) {
    memset(q, 0, sizeof(*q));
    if (cap < 4096) {
        cap = 4096;
    }
    q->data = ps_xmalloc(cap);
    q->cap = cap;
}

void ps_outbuf_free(struct ps_outbuf *q) {
    free(q->data);
    memset(q, 0, sizeof(*q));
}

size_t ps_outbuf_pending(const struct ps_outbuf *q) { return q->w - q->r; }

const uint8_t *ps_outbuf_head(const struct ps_outbuf *q) { return q->data + q->r; }

static void reset(struct ps_outbuf *q) { q->r = q->w = q->frame_start = 0; }

/* Shift the queue to offset 0. Only bytes before frame_start are dead (sent and
 * no longer droppable); everything from frame_start onwards must be preserved,
 * which keeps the "partially sent" state intact. */
static void compact(struct ps_outbuf *q) {
    if (q->frame_start == 0) {
        return;
    }
    memmove(q->data, q->data + q->frame_start, q->w - q->frame_start);
    q->w -= q->frame_start;
    q->r -= q->frame_start;
    q->frame_start = 0;
}

/* Finds the first queued frame that has no bytes on the wire yet. */
static int first_droppable(const struct ps_outbuf *q, size_t *start, size_t *total) {
    size_t fs = q->frame_start;

    while (fs + PS_HEADER_LEN <= q->w) {
        size_t t = PS_HEADER_LEN + (size_t)ps_be32(q->data + fs + 8);

        if (fs + t > q->w) {
            return 0; /* truncated tail: nothing safe to drop */
        }
        if (fs >= q->r) {
            *start = fs;
            *total = t;
            return 1;
        }
        fs += t;
    }
    return 0;
}

int ps_outbuf_drop_front(struct ps_outbuf *q) {
    size_t start, total;

    if (!first_droppable(q, &start, &total)) {
        return 0;
    }
    memmove(q->data + start, q->data + start + total, q->w - (start + total));
    q->w -= total;
    q->dropped_bytes += total;
    q->dropped_frames++;

    if (q->r == q->w) {
        reset(q);
    }
    return 1;
}

int ps_outbuf_push(struct ps_outbuf *q, const uint8_t *frame, size_t len) {
    if (len > q->cap) {
        return -1;
    }
    if (q->w + len > q->cap) {
        compact(q);
    }
    while (q->w + len > q->cap) {
        if (!ps_outbuf_drop_front(q)) {
            break; /* only the in-flight frame is left; it cannot be dropped */
        }
        compact(q);
    }
    if (q->w + len > q->cap) {
        return -1;
    }
    memcpy(q->data + q->w, frame, len);
    q->w += len;
    return 0;
}

void ps_outbuf_consume(struct ps_outbuf *q, size_t n) {
    if (n > q->w - q->r) {
        n = q->w - q->r;
    }
    q->r += n;
    if (q->r == q->w) {
        reset(q);
        return;
    }
    /* Advance frame_start to the frame containing the send cursor. */
    while (q->frame_start + PS_HEADER_LEN <= q->r) {
        size_t t = PS_HEADER_LEN + (size_t)ps_be32(q->data + q->frame_start + 8);

        if (q->frame_start + t > q->r) {
            break;
        }
        q->frame_start += t;
    }
}

size_t ps_outbuf_frames(const struct ps_outbuf *q) {
    size_t off = q->frame_start;
    size_t n = 0;

    while (off + PS_HEADER_LEN <= q->w) {
        size_t t = PS_HEADER_LEN + (size_t)ps_be32(q->data + off + 8);

        if (off + t > q->w) {
            break;
        }
        off += t;
        n++;
    }
    return n;
}
