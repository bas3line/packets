/* common.h - shared primitives: fixed-width types, endian helpers, limits. */
#ifndef PS_COMMON_H
#define PS_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#define PS_NAME "pktsniff"
#define PS_VERSION_STR "2.0.0"

#define PS_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#define PS_UNUSED(x) ((void)(x))

/* ---- link-layer types we understand (values match libpcap's DLT_*) ---- */
#define PS_DLT_NULL 0       /* BSD loopback, 4-byte AF family */
#define PS_DLT_EN10MB 1     /* Ethernet II */
#define PS_DLT_RAW 12       /* bare IP */
#define PS_DLT_LOOP 108     /* OpenBSD loopback, big-endian AF family */
#define PS_DLT_LINUX_SLL 113  /* Linux "cooked" v1 */
#define PS_DLT_LINUX_SLL2 276 /* Linux "cooked" v2 */

/* Returned by ps_capture_open() on Linux so peers know what they receive. */
#define PS_LINKTYPE_ETHERNET PS_DLT_EN10MB

#define PS_SNAPLEN_DEFAULT 262144u
#define PS_SNAPLEN_MAX 524288u
#define PS_MAX_FRAME (2u * 1024u * 1024u)

/* ---- unaligned big-endian readers (network order, wire protocol) ---- */
static inline uint16_t ps_be16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)((uint16_t)b[0] << 8 | (uint16_t)b[1]);
}

static inline uint32_t ps_be32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | (uint32_t)b[3];
}

static inline uint64_t ps_be64(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint64_t)ps_be32(b) << 32 | ps_be32(b + 4);
}

/* ---- unaligned little-endian readers (pcap file format) ---- */
static inline uint16_t ps_le16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)((uint16_t)b[1] << 8 | (uint16_t)b[0]);
}

static inline uint32_t ps_le32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[3] << 24 | (uint32_t)b[2] << 16 | (uint32_t)b[1] << 8 | (uint32_t)b[0];
}

/* ---- unaligned big-endian writers ---- */
static inline void ps_put_be16(void *p, uint16_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
}

static inline void ps_put_be32(void *p, uint32_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

static inline void ps_put_be64(void *p, uint64_t v) {
    uint8_t *b = (uint8_t *)p;
    ps_put_be32(b, (uint32_t)(v >> 32));
    ps_put_be32(b + 4, (uint32_t)v);
}

/* ---- unaligned little-endian writers (pcap file format) ---- */
static inline void ps_put_le16(void *p, uint16_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
}

static inline void ps_put_le32(void *p, uint32_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
    b[2] = (uint8_t)(v >> 16);
    b[3] = (uint8_t)(v >> 24);
}

#endif /* PS_COMMON_H */
