/* filter.h - client-side display filter.
 *
 * The server can be given a real BPF expression (`--filter`), but the client
 * needs its own cheap filter so a busy link does not drown the terminal.
 *
 * Grammar: groups joined by `or`, terms inside a group joined by `and`
 * (comma or whitespace also work; `and` is noise). Prefix a term with `!` to
 * negate it.
 *
 *   proto:tcp proto:udp proto:icmp proto:icmp6 proto:arp proto:ip6
 *   proto:dns proto:tls proto:http
 *   port:443  sport:53  dport:53
 *   host:10.0.0.1   host:10.0.0.0/8   src:...  dst:...
 *   contains:GET    bytes:>500
 *   shorthand: tcp udp icmp arp dns tls http 443 10.0.0.1
 *
 * Examples: `proto:tcp port:443 or proto:dns`, `!src:10.0.0.5 bytes:>1400`
 */
#ifndef PS_FILTER_H
#define PS_FILTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "decode.h"

enum ps_filter_kind {
    PS_FILTER_PROTO = 1,
    PS_FILTER_PORT,
    PS_FILTER_SPORT,
    PS_FILTER_DPORT,
    PS_FILTER_HOST,
    PS_FILTER_SRC,
    PS_FILTER_DST,
    PS_FILTER_CONTAINS,
    PS_FILTER_BYTES,
};

enum ps_filter_cmp { PS_CMP_EQ = 0, PS_CMP_GT, PS_CMP_LT, PS_CMP_GE, PS_CMP_LE };

struct ps_filter_clause {
    enum ps_filter_kind kind;
    bool negate;
    char proto[8];
    uint16_t port;
    uint32_t addr4; /* network order */
    uint32_t mask4;
    uint8_t addr6[16];
    uint8_t mask6[16];
    int is_v6;
    char needle[64];
    enum ps_filter_cmp cmp;
    uint32_t bytes;
};

#define PS_FILTER_MAX_CLAUSES 12
#define PS_FILTER_MAX_GROUPS 8

struct ps_filter_group {
    struct ps_filter_clause clauses[PS_FILTER_MAX_CLAUSES];
    size_t count;
};

struct ps_filter {
    struct ps_filter_group groups[PS_FILTER_MAX_GROUPS];
    size_t count;
    char source[256]; /* original expression, for display */
};

/* Returns 0 on success, -1 with a message in err. */
int ps_filter_parse(const char *expr, struct ps_filter *f, char *err, size_t errsz);
/* True when the packet satisfies at least one group in full. */
bool ps_filter_match(const struct ps_filter *f, const struct ps_decoded *d);
/* 1 if the filter is empty (matches everything). */
int ps_filter_is_empty(const struct ps_filter *f);

#endif /* PS_FILTER_H */
