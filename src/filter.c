/* filter.c - client-side display filter. */
#include "filter.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

static int parse_addr(const char *text, struct ps_filter_clause *c) {
    char buf[128];
    char *slash;
    int bits = -1;

    ps_strlcpy(buf, text, sizeof(buf));
    slash = strchr(buf, '/');
    if (slash) {
        char *end = NULL;
        long v;
        *slash = '\0';
        v = strtol(slash + 1, &end, 10);
        if (!end || *end != '\0' || v < 0 || v > 128) {
            return -1;
        }
        bits = (int)v;
    }

    if (inet_pton(AF_INET, buf, &c->addr4) == 1) {
        c->is_v6 = 0;
        if (bits < 0) {
            bits = 32;
        } else if (bits > 32) {
            return -1;
        }
        c->mask4 = bits == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - bits));
        c->addr4 &= c->mask4;
        return 0;
    }
    if (inet_pton(AF_INET6, buf, c->addr6) == 1) {
        c->is_v6 = 1;
        if (bits < 0) {
            bits = 128;
        }
        memset(c->mask6, 0, sizeof(c->mask6));
        for (int i = 0; i < bits; i++) {
            c->mask6[i / 8] |= (uint8_t)(0x80 >> (i % 8));
        }
        for (int i = 0; i < 16; i++) {
            c->addr6[i] &= c->mask6[i];
        }
        return 0;
    }
    return -1;
}

static int addr_matches(const struct ps_filter_clause *c, const char *text) {
    unsigned char raw[16];

    memset(raw, 0, sizeof(raw));
    if (inet_pton(AF_INET, text, raw) == 1) {
        if (c->is_v6) {
            return 0;
        }
        uint32_t v = 0;
        memcpy(&v, raw, 4);
        return (v & c->mask4) == c->addr4;
    }
    if (inet_pton(AF_INET6, text, raw) == 1) {
        if (!c->is_v6) {
            return 0;
        }
        for (int i = 0; i < 16; i++) {
            if ((raw[i] & c->mask6[i]) != c->addr6[i]) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

static int parse_bytes(const char *value, struct ps_filter_clause *c) {
    enum ps_filter_cmp cmp = PS_CMP_EQ;
    const char *p = value;

    if (p[0] == '>') {
        if (p[1] == '=') {
            cmp = PS_CMP_GE;
            p += 2;
        } else {
            cmp = PS_CMP_GT;
            p += 1;
        }
    } else if (p[0] == '<') {
        if (p[1] == '=') {
            cmp = PS_CMP_LE;
            p += 2;
        } else {
            cmp = PS_CMP_LT;
            p += 1;
        }
    } else if (p[0] == '=') {
        p += 1;
    }
    if (ps_parse_u32(p, &c->bytes) != 0) {
        return -1;
    }
    c->cmp = cmp;
    return 0;
}

static const char *const known_protos[] = {
    "tcp", "udp", "icmp", "icmp6", "arp", "ip6", "dns", "tls", "http",
};

static int proto_known(const char *name) {
    for (size_t i = 0; i < sizeof(known_protos) / sizeof(known_protos[0]); i++) {
        if (strcasecmp(name, known_protos[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int looks_numeric(const char *s) {
    if (!*s) {
        return 0;
    }
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s)) {
            return 0;
        }
    }
    return 1;
}

/* Accepts "key:value", "key=value" and bare shorthand: "tcp", "udp", "icmp",
 * "arp", "dns", "443" (port), "10.0.0.1" (host). */
static int parse_clause(char *token, struct ps_filter_group *g, char *err, size_t errsz) {
    struct ps_filter_clause *c;
    char *key = token;
    char *value = NULL;
    int negate = 0;

    if (g->count >= PS_FILTER_MAX_CLAUSES) {
        snprintf(err, errsz, "too many terms in one group (max %d)", PS_FILTER_MAX_CLAUSES);
        return -1;
    }

    if (key[0] == '!') {
        negate = 1;
        key++;
    }

    char *sep = strpbrk(key, ":=");
    if (sep) {
        *sep = '\0';
        value = sep + 1;
    }

    c = &g->clauses[g->count];
    memset(c, 0, sizeof(*c));
    c->negate = negate;

    if (!value) {
        /* shorthand */
        if (strcasecmp(key, "tcp") == 0 || strcasecmp(key, "udp") == 0 ||
            strcasecmp(key, "icmp") == 0 || strcasecmp(key, "icmp6") == 0 ||
            strcasecmp(key, "arp") == 0 || strcasecmp(key, "dns") == 0 ||
            strcasecmp(key, "tls") == 0 || strcasecmp(key, "http") == 0 ||
            strcasecmp(key, "ip6") == 0) {
            c->kind = PS_FILTER_PROTO;
            ps_strlcpy(c->proto, key, sizeof(c->proto));
        } else if (looks_numeric(key)) {
            uint32_t v;
            c->kind = PS_FILTER_PORT;
            if (ps_parse_u32(key, &v) != 0 || v > 65535) {
                snprintf(err, errsz, "bad port '%s'", key);
                return -1;
            }
            c->port = (uint16_t)v;
        } else if (parse_addr(key, c) == 0) {
            c->kind = PS_FILTER_HOST;
        } else {
            snprintf(err, errsz, "cannot understand clause '%s'", key);
            return -1;
        }
        g->count++;
        return 0;
    }

    if (*value == '\0') {
        snprintf(err, errsz, "clause '%s' has an empty value", key);
        return -1;
    }

    if (strcasecmp(key, "proto") == 0) {
        if (!proto_known(value)) {
            snprintf(err, errsz,
                     "unknown protocol '%s' (tcp udp icmp icmp6 arp ip6 dns tls http)", value);
            return -1;
        }
        c->kind = PS_FILTER_PROTO;
        ps_strlcpy(c->proto, value, sizeof(c->proto));
    } else if (strcasecmp(key, "port") == 0 || strcasecmp(key, "sport") == 0 ||
               strcasecmp(key, "dport") == 0) {
        uint32_t v;
        if (ps_parse_u32(value, &v) != 0 || v > 65535) {
            snprintf(err, errsz, "bad port '%s'", value);
            return -1;
        }
        c->port = (uint16_t)v;
        c->kind = strcasecmp(key, "port") == 0   ? PS_FILTER_PORT
                  : strcasecmp(key, "sport") == 0 ? PS_FILTER_SPORT
                                                  : PS_FILTER_DPORT;
    } else if (strcasecmp(key, "host") == 0 || strcasecmp(key, "src") == 0 ||
               strcasecmp(key, "dst") == 0) {
        if (parse_addr(value, c) != 0) {
            snprintf(err, errsz, "bad address '%s'", value);
            return -1;
        }
        c->kind = strcasecmp(key, "host") == 0   ? PS_FILTER_HOST
                  : strcasecmp(key, "src") == 0 ? PS_FILTER_SRC
                                                : PS_FILTER_DST;
    } else if (strcasecmp(key, "contains") == 0) {
        c->kind = PS_FILTER_CONTAINS;
        ps_strlcpy(c->needle, value, sizeof(c->needle));
    } else if (strcasecmp(key, "bytes") == 0 || strcasecmp(key, "len") == 0) {
        c->kind = PS_FILTER_BYTES;
        if (parse_bytes(value, c) != 0) {
            snprintf(err, errsz, "bad length '%s'", value);
            return -1;
        }
    } else {
        snprintf(err, errsz, "unknown filter key '%s'", key);
        return -1;
    }

    g->count++;
    return 0;
}

int ps_filter_parse(const char *expr, struct ps_filter *f, char *err, size_t errsz) {
    char buf[1024];
    char *saveptr = NULL;
    char *token;
    struct ps_filter_group *group;
    size_t w = 0;

    memset(f, 0, sizeof(*f));
    if (!expr || !*expr) {
        return 0;
    }
    ps_strlcpy(f->source, expr, sizeof(f->source));

    /* Normalise separators: ',' is AND (just a space), '|' is an explicit OR. */
    for (const char *p = expr; *p && w + 4 < sizeof(buf); p++) {
        if (*p == '|') {
            memcpy(buf + w, " or ", 4);
            w += 4;
        } else if (*p == ',') {
            buf[w++] = ' ';
        } else {
            buf[w++] = *p;
        }
    }
    buf[w] = '\0';

    group = &f->groups[0];
    f->count = 1;

    for (token = strtok_r(buf, " \t", &saveptr); token; token = strtok_r(NULL, " \t", &saveptr)) {
        if (strcasecmp(token, "or") == 0) {
            if (group->count == 0) {
                snprintf(err, errsz, "empty filter group before 'or'");
                return -1;
            }
            if (f->count >= PS_FILTER_MAX_GROUPS) {
                snprintf(err, errsz, "too many 'or' groups (max %d)", PS_FILTER_MAX_GROUPS);
                return -1;
            }
            group = &f->groups[f->count++];
            continue;
        }
        if (strcasecmp(token, "and") == 0) {
            continue;
        }
        if (parse_clause(token, group, err, errsz) != 0) {
            return -1;
        }
    }

    if (group->count == 0) {
        snprintf(err, errsz, "dangling 'or' with nothing after it");
        return -1;
    }
    if (errsz) {
        err[0] = '\0';
    }
    return 0;
}

int ps_filter_is_empty(const struct ps_filter *f) { return f->count == 0; }

static int proto_matches(const char *proto, const struct ps_decoded *d) {
    if (strcasecmp(proto, "tcp") == 0) {
        return d->l4 == PS_L4_TCP;
    }
    if (strcasecmp(proto, "udp") == 0) {
        return d->l4 == PS_L4_UDP;
    }
    if (strcasecmp(proto, "icmp") == 0) {
        return d->l4 == PS_L4_ICMP;
    }
    if (strcasecmp(proto, "icmp6") == 0) {
        return d->l4 == PS_L4_ICMPV6;
    }
    if (strcasecmp(proto, "arp") == 0) {
        return d->ethertype == 0x0806;
    }
    if (strcasecmp(proto, "ip6") == 0) {
        return d->ip_version == 6;
    }
    if (strcasecmp(proto, "dns") == 0) {
        return (d->app_flags & PS_APP_DNS) != 0;
    }
    if (strcasecmp(proto, "tls") == 0) {
        return (d->app_flags & PS_APP_TLS) != 0;
    }
    if (strcasecmp(proto, "http") == 0) {
        return (d->app_flags & PS_APP_HTTP) != 0;
    }
    return 0;
}

static int payload_contains(const struct ps_decoded *d, const char *needle) {
    size_t n = strlen(needle);

    if (!d->payload || d->payload_len < n || n == 0) {
        return 0;
    }
    const uint8_t *p = d->payload;
    for (uint32_t i = 0; i + n <= d->payload_len; i++) {
        if (memcmp(p + i, needle, n) == 0) {
            return 1;
        }
    }
    return 0;
}

static bool group_matches(const struct ps_filter_group *g, const struct ps_decoded *d) {
    for (size_t i = 0; i < g->count; i++) {
        const struct ps_filter_clause *c = &g->clauses[i];
        int hit = 0;

        switch (c->kind) {
        case PS_FILTER_PROTO:
            hit = proto_matches(c->proto, d);
            break;
        case PS_FILTER_PORT:
            hit = d->sport == c->port || d->dport == c->port;
            break;
        case PS_FILTER_SPORT:
            hit = d->sport == c->port;
            break;
        case PS_FILTER_DPORT:
            hit = d->dport == c->port;
            break;
        case PS_FILTER_HOST:
            hit = addr_matches(c, d->src) || addr_matches(c, d->dst);
            break;
        case PS_FILTER_SRC:
            hit = addr_matches(c, d->src);
            break;
        case PS_FILTER_DST:
            hit = addr_matches(c, d->dst);
            break;
        case PS_FILTER_CONTAINS:
            hit = payload_contains(d, c->needle);
            break;
        case PS_FILTER_BYTES:
            switch (c->cmp) {
            case PS_CMP_EQ:
                hit = d->origlen == c->bytes;
                break;
            case PS_CMP_GT:
                hit = d->origlen > c->bytes;
                break;
            case PS_CMP_LT:
                hit = d->origlen < c->bytes;
                break;
            case PS_CMP_GE:
                hit = d->origlen >= c->bytes;
                break;
            case PS_CMP_LE:
                hit = d->origlen <= c->bytes;
                break;
            }
            break;
        }

        if (c->negate) {
            hit = !hit;
        }
        if (!hit) {
            return false;
        }
    }
    return true;
}

bool ps_filter_match(const struct ps_filter *f, const struct ps_decoded *d) {
    for (size_t i = 0; i < f->count; i++) {
        if (group_matches(&f->groups[i], d)) {
            return true;
        }
    }
    return false;
}
