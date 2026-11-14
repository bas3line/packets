/* proto.c - framing, payload codecs, incremental reader. */
#include "proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

const char *ps_frame_type_name(uint16_t type) {
    switch (type) {
    case PS_FRAME_HELLO:
        return "HELLO";
    case PS_FRAME_PACKET:
        return "PACKET";
    case PS_FRAME_STATS:
        return "STATS";
    case PS_FRAME_BYE:
        return "BYE";
    case PS_FRAME_ERR:
        return "ERR";
    default:
        return "UNKNOWN";
    }
}

size_t ps_frame_write(uint8_t *out, size_t cap, uint16_t type, const uint8_t *payload, uint32_t len) {
    if (cap < PS_HEADER_LEN + (size_t)len) {
        return 0;
    }
    ps_put_be32(out + 0, PS_PROTO_MAGIC);
    ps_put_be16(out + 4, (uint16_t)PS_PROTO_VERSION);
    ps_put_be16(out + 6, type);
    ps_put_be32(out + 8, len);
    if (len > 0) {
        memcpy(out + PS_HEADER_LEN, payload, len);
    }
    return PS_HEADER_LEN + len;
}

size_t ps_packet_encode(uint8_t *out, size_t cap, const struct ps_record *rec) {
    size_t total = PS_PKT_HDR_LEN + rec->caplen;

    if (cap < total) {
        return 0;
    }
    ps_put_be32(out + 0, rec->ts_sec);
    ps_put_be32(out + 4, rec->ts_usec);
    ps_put_be32(out + 8, rec->caplen);
    ps_put_be32(out + 12, rec->origlen);
    memcpy(out + PS_PKT_HDR_LEN, rec->data, rec->caplen);
    return total;
}

int ps_packet_decode(const uint8_t *in, uint32_t len, struct ps_record *rec) {
    uint32_t caplen;

    if (len < PS_PKT_HDR_LEN) {
        return -1;
    }
    caplen = ps_be32(in + 8);
    if (caplen > len - PS_PKT_HDR_LEN) {
        return -1;
    }
    rec->ts_sec = ps_be32(in + 0);
    rec->ts_usec = ps_be32(in + 4);
    rec->caplen = caplen;
    rec->origlen = ps_be32(in + 12);
    rec->data = in + PS_PKT_HDR_LEN;
    return 0;
}

/* Strings are packed back-to-back, each NUL terminated. */
static size_t pack_string(uint8_t *out, size_t cap, size_t off, const char *s) {
    size_t n = strlen(s) + 1;
    if (off + n > cap) {
        return 0;
    }
    memcpy(out + off, s, n);
    return off + n;
}

static int unpack_string(const uint8_t *in, uint32_t len, uint32_t *off, char *dst, size_t cap) {
    const uint8_t *nul;
    size_t remain;

    if (*off >= len) {
        return -1;
    }
    remain = len - *off;
    nul = memchr(in + *off, '\0', remain);
    if (!nul) {
        return -1;
    }
    ps_strlcpy(dst, (const char *)(in + *off), cap);
    *off += (uint32_t)(nul - (in + *off)) + 1;
    return 0;
}

size_t ps_hello_encode(const struct ps_hello *hello, uint8_t *out, size_t cap) {
    size_t off;

    if (cap < 6) {
        return 0;
    }
    ps_put_be16(out + 0, hello->linktype);
    ps_put_be32(out + 2, hello->snaplen);
    off = 6;

    off = pack_string(out, cap, off, hello->hostname);
    if (off == 0) {
        return 0;
    }
    off = pack_string(out, cap, off, hello->iface);
    if (off == 0) {
        return 0;
    }
    return pack_string(out, cap, off, hello->filter);
}

int ps_hello_decode(const uint8_t *in, uint32_t len, struct ps_hello *hello) {
    uint32_t off = 6;

    if (len < 6) {
        return -1;
    }
    memset(hello, 0, sizeof(*hello));
    hello->linktype = ps_be16(in + 0);
    hello->snaplen = ps_be32(in + 2);

    if (unpack_string(in, len, &off, hello->hostname, sizeof(hello->hostname)) != 0 ||
        unpack_string(in, len, &off, hello->iface, sizeof(hello->iface)) != 0 ||
        unpack_string(in, len, &off, hello->filter, sizeof(hello->filter)) != 0) {
        return -1;
    }
    return 0;
}

size_t ps_string_encode(const char *s, uint8_t *out, size_t cap) {
    size_t n = strlen(s) + 1;

    if (cap < n) {
        return 0;
    }
    memcpy(out, s, n);
    return n;
}

/* ---- reader ---- */

int ps_reader_init(struct ps_reader *r, size_t initial_cap) {
    memset(r, 0, sizeof(*r));
    if (initial_cap < 4096) {
        initial_cap = 4096;
    }
    r->buf = ps_xmalloc(initial_cap);
    r->cap = initial_cap;
    return 0;
}

void ps_reader_free(struct ps_reader *r) {
    free(r->buf);
    free(r->frame);
    memset(r, 0, sizeof(*r));
}

void ps_reader_reset(struct ps_reader *r) {
    r->len = 0;
    r->error = 0;
}

int ps_reader_feed(struct ps_reader *r, const uint8_t *data, size_t n) {
    if (r->error) {
        return -1;
    }
    if (n == 0) {
        return 0;
    }
    if (r->len + n > PS_MAX_FRAME) {
        r->error = 1;
        return -1;
    }
    if (r->len + n > r->cap) {
        size_t want = r->cap;
        while (want < r->len + n) {
            want *= 2;
        }
        r->buf = ps_xrealloc(r->buf, want);
        r->cap = want;
    }
    memcpy(r->buf + r->len, data, n);
    r->len += n;
    return 0;
}

static void reader_consume(struct ps_reader *r, size_t n) {
    if (n >= r->len) {
        r->len = 0;
        return;
    }
    memmove(r->buf, r->buf + n, r->len - n);
    r->len -= n;
}

int ps_reader_next(struct ps_reader *r, struct ps_frame *out) {
    uint32_t magic, len;
    uint16_t version, type;

    if (r->error) {
        return -1;
    }
    if (r->len < PS_HEADER_LEN) {
        return 0;
    }

    magic = ps_be32(r->buf + 0);
    version = ps_be16(r->buf + 4);
    type = ps_be16(r->buf + 6);
    len = ps_be32(r->buf + 8);

    if (magic != PS_PROTO_MAGIC) {
        r->error = 1;
        return -1;
    }
    if (version != PS_PROTO_VERSION) {
        r->error = 1;
        return -1;
    }
    if (len > PS_MAX_FRAME) {
        r->error = 1;
        return -1;
    }
    if (r->len < PS_HEADER_LEN + (size_t)len) {
        return 0; /* partial frame, wait for more */
    }

    if (len > r->frame_cap) {
        r->frame = ps_xrealloc(r->frame, len);
        r->frame_cap = len;
    }
    if (len > 0) {
        memcpy(r->frame, r->buf + PS_HEADER_LEN, len);
    }

    reader_consume(r, PS_HEADER_LEN + (size_t)len);

    out->type = type;
    out->len = len;
    out->data = r->frame;
    return 1;
}
