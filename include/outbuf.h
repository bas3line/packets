/* outbuf.h - per-client send queue that only ever drops whole frames.
 *
 * The capture loop must never block on a slow client, and the client must never
 * see a half frame, so this is a byte queue with an explicit notion of "next
 * frame boundary". Bytes may be partially sent; anything dropped is removed at
 * a frame boundary, and any bytes of that frame already handed to send() are
 * left untouched (they are already on the wire).
 */
#ifndef PS_OUTBUF_H
#define PS_OUTBUF_H

#include <stddef.h>
#include <stdint.h>

struct ps_outbuf {
    uint8_t *data;
    size_t cap;
    size_t r;           /* bytes already handed to the socket */
    size_t frame_start; /* offset of the oldest queued frame boundary */
    size_t w;           /* end of queued data */
    uint64_t dropped_bytes;
    uint64_t dropped_frames;
};

void ps_outbuf_init(struct ps_outbuf *q, size_t cap);
void ps_outbuf_free(struct ps_outbuf *q);

/* Append one complete frame. Returns 0 on success, -1 if it can never fit.
 * When the queue is full, older whole frames are discarded first. */
int ps_outbuf_push(struct ps_outbuf *q, const uint8_t *frame, size_t len);

/* Bytes waiting to be written to the socket. */
size_t ps_outbuf_pending(const struct ps_outbuf *q);
const uint8_t *ps_outbuf_head(const struct ps_outbuf *q);

/* Account for `n` bytes accepted by send(). */
void ps_outbuf_consume(struct ps_outbuf *q, size_t n);

/* Drop the oldest whole frame; returns 1 if one was dropped, 0 if empty. */
int ps_outbuf_drop_front(struct ps_outbuf *q);

/* Number of complete frames currently queued (for diagnostics only). */
size_t ps_outbuf_frames(const struct ps_outbuf *q);

#endif /* PS_OUTBUF_H */
