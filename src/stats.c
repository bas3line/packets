/* stats.c - counter plumbing and wire (de)serialisation. */
#include "stats.h"

#include <stdio.h>
#include <string.h>

#include "util.h"

_Static_assert(sizeof(struct ps_counters) == PS_COUNTER_WIRE_SIZE,
               "counter struct drifted from its wire format");

void ps_counters_clear(struct ps_counters *c) { memset(c, 0, sizeof(*c)); }

void ps_counters_add(struct ps_counters *dst, const struct ps_counters *src) {
#define PS_COUNTER_ADD(name) dst->name += src->name;
    PS_COUNTER_FIELDS(PS_COUNTER_ADD)
#undef PS_COUNTER_ADD
    dst->dropped_kernel += src->dropped_kernel;
    dst->dropped_client += src->dropped_client;
}

size_t ps_counters_encode(const struct ps_counters *c, uint8_t *out, size_t cap) {
    /* Field order is defined once, in PS_COUNTER_FIELDS. */
    const uint64_t *fields[PS_COUNTER_WIRE_FIELDS] = {
#define PS_COUNTER_ADDR(name) &c->name,
        PS_COUNTER_FIELDS(PS_COUNTER_ADDR)
#undef PS_COUNTER_ADDR
        &c->dropped_kernel,
        &c->dropped_client,
    };

    if (cap < PS_COUNTER_WIRE_SIZE) {
        return 0;
    }
    for (size_t i = 0; i < PS_COUNTER_WIRE_FIELDS; i++) {
        ps_put_be64(out + i * 8, *fields[i]);
    }
    return PS_COUNTER_WIRE_SIZE;
}

int ps_counters_decode(const uint8_t *in, uint32_t len, struct ps_counters *c) {
    uint64_t *fields[PS_COUNTER_WIRE_FIELDS] = {
#define PS_COUNTER_PTR(name) &c->name,
        PS_COUNTER_FIELDS(PS_COUNTER_PTR)
#undef PS_COUNTER_PTR
        &c->dropped_kernel,
        &c->dropped_client,
    };

    if (len < PS_COUNTER_WIRE_SIZE) {
        return -1;
    }
    for (size_t i = 0; i < PS_COUNTER_WIRE_FIELDS; i++) {
        *fields[i] = ps_be64(in + i * 8);
    }
    return 0;
}

void ps_counters_format(const struct ps_counters *c, char *out, size_t cap) {
    char bytes[24];
    size_t off = 0;

    ps_fmt_bytes(bytes, sizeof(bytes), c->bytes);
    off = ps_appendf(out, cap, off, "seen=%llu captured=%llu bytes=%s",
                     (unsigned long long)c->seen, (unsigned long long)c->captured, bytes);
    off = ps_appendf(out, cap, off, " tcp=%llu udp=%llu icmp=%llu arp=%llu",
                     (unsigned long long)c->tcp, (unsigned long long)c->udp,
                     (unsigned long long)c->icmp, (unsigned long long)c->arp);
    off = ps_appendf(out, cap, off, " dns=%llu tls=%llu ipv6=%llu other=%llu",
                     (unsigned long long)c->dns, (unsigned long long)c->tls,
                     (unsigned long long)c->ipv6, (unsigned long long)c->other);
    if (c->dropped_kernel || c->dropped_client) {
        ps_appendf(out, cap, off, " dropped=%llu+%llu",
                   (unsigned long long)c->dropped_kernel, (unsigned long long)c->dropped_client);
    }
}
