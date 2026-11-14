/* stats.h - traffic counters, serialised with an X-macro so the wire format
 * and the struct can never drift apart. */
#ifndef PS_STATS_H
#define PS_STATS_H

#include "common.h"

/* name = struct field = wire field, in this exact order. */
#define PS_COUNTER_FIELDS(X)                                                                       \
    X(seen)                                                                                        \
    X(captured)                                                                                    \
    X(bytes)                                                                                       \
    X(tcp)                                                                                         \
    X(udp)                                                                                         \
    X(icmp)                                                                                        \
    X(arp)                                                                                         \
    X(dns)                                                                                         \
    X(tls)                                                                                         \
    X(ipv6)                                                                                        \
    X(fragmented)                                                                                  \
    X(other)

struct ps_counters {
#define PS_COUNTER_DECL(name) uint64_t name;
    PS_COUNTER_FIELDS(PS_COUNTER_DECL)
#undef PS_COUNTER_DECL
    uint64_t dropped_kernel; /* kernel ring drops, server side */
    uint64_t dropped_client; /* slow-consumer drops, server side */
};

/* 12 X-macro fields + kernel/client drops. stats.c static_asserts this
 * against sizeof(struct ps_counters) so the two cannot drift. */
#define PS_COUNTER_WIRE_FIELDS 14u
#define PS_COUNTER_WIRE_SIZE (PS_COUNTER_WIRE_FIELDS * 8u)

void ps_counters_clear(struct ps_counters *c);
void ps_counters_add(struct ps_counters *dst, const struct ps_counters *src);

size_t ps_counters_encode(const struct ps_counters *c, uint8_t *out, size_t cap);
int ps_counters_decode(const uint8_t *in, uint32_t len, struct ps_counters *c);

/* Compact single-line rendering used by both sides' status output. */
void ps_counters_format(const struct ps_counters *c, char *out, size_t cap);

#endif /* PS_STATS_H */
