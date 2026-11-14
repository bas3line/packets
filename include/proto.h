/* proto.h - pktsniff wire protocol, version 1.
 *
 * Every message is a length-prefixed frame:
 *
 *   +--------+---------+--------+--------+------------------+
 *   | magic  | version | type   | length | payload[length]  |
 *   | 4 (BE) | 2 (BE)  | 2 (BE) | 4 (BE) | ...              |
 *   +--------+---------+--------+--------+------------------+
 *
 * Payloads are typed by `type`; see docs/PROTOCOL.md. Raw captured frames
 * travel inside PS_FRAME_PACKET so the client can decode, filter, render or
 * write them to a .pcap without the server having to understand anything but
 * Ethernet.
 */
#ifndef PS_PROTO_H
#define PS_PROTO_H

#include "common.h"

#define PS_PROTO_MAGIC 0x50534E46u /* "PSNF" */
#define PS_PROTO_VERSION 1u
#define PS_HEADER_LEN 12u

enum ps_frame_type {
    PS_FRAME_HELLO = 1,  /* server -> client: session metadata */
    PS_FRAME_PACKET = 2, /* server -> client: one captured frame */
    PS_FRAME_STATS = 3,  /* server -> client: counters */
    PS_FRAME_BYE = 4,    /* server -> client: clean shutdown */
    PS_FRAME_ERR = 5,    /* either direction: human-readable error */
};

/* PS_FRAME_PACKET payload, all integers big-endian:
 *   u32 ts_sec | u32 ts_usec | u32 caplen | u32 origlen | u8 data[caplen] */
#define PS_PKT_HDR_LEN 16u

struct ps_record {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t origlen;
    const uint8_t *data;
};

struct ps_frame {
    uint16_t type;
    uint32_t len;
    const uint8_t *data;
};

/* ---- builders. Each returns the number of bytes written, 0 on failure. ---- */
size_t ps_frame_write(uint8_t *out, size_t cap, uint16_t type, const uint8_t *payload, uint32_t len);
size_t ps_packet_encode(uint8_t *out, size_t cap, const struct ps_record *rec);

/* PS_FRAME_HELLO payload: u16 linktype | u32 snaplen | 3 x NUL-terminated
 * strings (hostname, interface, bpf filter; empty string allowed). */
struct ps_hello {
    uint16_t linktype;
    uint32_t snaplen;
    char hostname[64];
    char iface[32];
    char filter[256];
};

size_t ps_hello_encode(const struct ps_hello *hello, uint8_t *out, size_t cap);
int ps_hello_decode(const uint8_t *in, uint32_t len, struct ps_hello *hello);

int ps_packet_decode(const uint8_t *in, uint32_t len, struct ps_record *rec);

/* PS_FRAME_ERR/BYE payload is a bare NUL-terminated string. */
size_t ps_string_encode(const char *s, uint8_t *out, size_t cap);

/* ---- incremental frame reader (handles TCP segmentation correctly) ---- */
struct ps_reader {
    uint8_t *buf;   /* accumulated socket bytes */
    size_t cap;
    size_t len;
    uint8_t *frame; /* scratch copy of the frame handed to the caller */
    size_t frame_cap;
    int error; /* sticky; set on protocol violation */
};

int ps_reader_init(struct ps_reader *r, size_t initial_cap);
void ps_reader_free(struct ps_reader *r);
void ps_reader_reset(struct ps_reader *r);
/* Append bytes from the socket. Returns 0 on success, -1 if the reader would
 * exceed PS_MAX_FRAME (protocol garbage). */
int ps_reader_feed(struct ps_reader *r, const uint8_t *data, size_t n);
/* 1 = frame ready, 0 = need more bytes, -1 = protocol error.
 * The returned payload is a private copy, valid until the next call. */
int ps_reader_next(struct ps_reader *r, struct ps_frame *out);

const char *ps_frame_type_name(uint16_t type);

#endif /* PS_PROTO_H */
