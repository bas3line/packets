/* decode.c - bounds-checked protocol dissection. */
#include "decode.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

#define ETH_HDR_LEN 14u
#define VLAN_TAG_LEN 4u
#define SLL_HDR_LEN 16u
#define SLL2_HDR_LEN 20u

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_QINQ 0x88A8
#define ETHERTYPE_VLAN_9100 0x9100

const char *ps_l4_name(enum ps_l4 l4) {
    switch (l4) {
    case PS_L4_TCP:
        return "TCP";
    case PS_L4_UDP:
        return "UDP";
    case PS_L4_ICMP:
        return "ICMP";
    case PS_L4_ICMPV6:
        return "ICMP6";
    case PS_L4_OTHER:
        return "L4";
    default:
        return "-";
    }
}

const char *ps_proto_label(const struct ps_decoded *d) {
    if (d->ethertype == ETHERTYPE_ARP) {
        return "ARP";
    }
    if (d->ip_version == 0) {
        return "ETH";
    }
    return ps_l4_name(d->l4);
}

void ps_tcp_flag_str(uint8_t flags, char *buf, size_t cap) {
    static const struct {
        uint8_t bit;
        const char *name;
    } names[] = {
        {PS_TCP_SYN, "SYN"}, {PS_TCP_ACK, "ACK"}, {PS_TCP_FIN, "FIN"}, {PS_TCP_RST, "RST"},
        {PS_TCP_PSH, "PSH"}, {PS_TCP_URG, "URG"}, {PS_TCP_ECE, "ECE"}, {PS_TCP_CWR, "CWR"},
    };
    size_t off = 0;

    buf[0] = '\0';
    for (size_t i = 0; i < PS_ARRAY_LEN(names); i++) {
        if (flags & names[i].bit) {
            off = ps_appendf(buf, cap, off, "%s%s", off ? "," : "", names[i].name);
        }
    }
}

static void fmt_mac(const uint8_t *mac, char *out, size_t cap) {
    snprintf(out, cap, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4],
             mac[5]);
}

/* ---- application layer peeking ---- */

static void dns_name(const uint8_t *p, uint32_t len, uint32_t off, char *out, size_t cap) {
    size_t w = 0;
    int jumps = 0;

    out[0] = '\0';
    while (off < len && jumps < 32) {
        uint8_t label = p[off];

        if (label == 0) {
            break;
        }
        if ((label & 0xC0) == 0xC0) { /* compression pointer */
            if (off + 1 >= len) {
                return;
            }
            off = (uint32_t)((label & 0x3F) << 8 | p[off + 1]);
            jumps++;
            continue;
        }
        if (off + 1 + label >= len) {
            return;
        }
        if (w > 0 && w + 1 < cap) {
            out[w++] = '.';
        }
        for (uint8_t i = 0; i < label && w + 1 < cap; i++) {
            out[w++] = (char)p[off + 1 + i];
        }
        off += 1u + label;
    }
    if (w < cap) {
        out[w] = '\0';
    } else {
        out[cap - 1] = '\0';
    }
}

static void peek_dns(struct ps_decoded *d) {
    const uint8_t *p = d->payload;
    uint32_t len = d->payload_len;
    char name[128];

    if (len < 12) {
        return;
    }
    d->app_flags |= PS_APP_DNS;

    if (d->sport == 53 || d->dport == 53) {
        uint16_t flags = ps_be16(p + 2);
        uint16_t qdcount = ps_be16(p + 4);
        int response = (flags & 0x8000) != 0;

        if (qdcount == 0) {
            snprintf(d->app, sizeof(d->app), "DNS %s", response ? "response" : "query");
            return;
        }
        dns_name(p, len, 12, name, sizeof(name));
        /* Type of the question follows the name; recompute its end. */
        uint32_t off = 12;
        while (off < len && p[off] != 0 && (p[off] & 0xC0) != 0xC0) {
            off += 1u + p[off];
        }
        off += 1;
        const char *qtype = "";
        if (off + 2 <= len) {
            switch (ps_be16(p + off)) {
            case 1:
                qtype = " A";
                break;
            case 2:
                qtype = " NS";
                break;
            case 5:
                qtype = " CNAME";
                break;
            case 12:
                qtype = " PTR";
                break;
            case 15:
                qtype = " MX";
                break;
            case 16:
                qtype = " TXT";
                break;
            case 28:
                qtype = " AAAA";
                break;
            case 33:
                qtype = " SRV";
                break;
            case 65:
                qtype = " HTTPS";
                break;
            default:
                qtype = " ?";
                break;
            }
        }
        snprintf(d->app, sizeof(d->app), "DNS%s%s %s", response ? "(r)" : "", qtype, name);
    }
}

/* Walks a TLS ClientHello looking for the server_name extension (RFC 6066). */
static void peek_tls(struct ps_decoded *d) {
    const uint8_t *p = d->payload;
    uint32_t len = d->payload_len;
    uint32_t off;
    uint32_t ext_end;

    if (len < 43 || p[0] != 0x16 || p[1] != 0x03) {
        return;
    }
    d->app_flags |= PS_APP_TLS;

    /* record(5) handshake(4) version(2) random(32) sid_len(1) sid ... */
    off = 5 + 4 + 2 + 32;
    if (off >= len) {
        goto generic;
    }
    off += 1u + p[off]; /* session id */
    if (off + 2 > len) {
        goto generic;
    }
    off += 2u + ps_be16(p + off); /* cipher suites */
    if (off + 1 > len) {
        goto generic;
    }
    off += 1u + p[off]; /* compression methods */
    if (off + 2 > len) {
        goto generic;
    }
    ext_end = off + 2u + ps_be16(p + off);
    off += 2;
    if (ext_end > len) {
        ext_end = len;
    }

    while (off + 4 <= ext_end) {
        uint16_t ext_type = ps_be16(p + off);
        uint16_t ext_len = ps_be16(p + off + 2);

        off += 4;
        if (off + ext_len > ext_end) {
            break;
        }
        if (ext_type == 0x0000 && ext_len > 5) { /* server_name */
            uint16_t list_len = ps_be16(p + off);
            uint32_t p2 = off + 2;

            if (p2 + 3 <= off + ext_len && list_len >= 3) {
                uint8_t name_type = p[p2];
                uint16_t name_len = ps_be16(p + p2 + 1);
                p2 += 3;
                if (name_type == 0 && p2 + name_len <= off + ext_len) {
                    snprintf(d->app, sizeof(d->app), "TLS SNI=%.*s", (int)name_len,
                             (const char *)(p + p2));
                    return;
                }
            }
        }
        off += ext_len;
    }

generic:
    snprintf(d->app, sizeof(d->app), "TLS handshake");
}

static void peek_http(struct ps_decoded *d) {
    static const char *verbs[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ",
                                  "PATCH ", "HTTP/"};
    const uint8_t *p = d->payload;
    uint32_t len = d->payload_len;

    if (len < 4) {
        return;
    }
    for (size_t i = 0; i < PS_ARRAY_LEN(verbs); i++) {
        size_t n = strlen(verbs[i]);
        if (len >= n && memcmp(p, verbs[i], n) == 0) {
            size_t end = 0;
            while (end < len && p[end] != '\r' && p[end] != '\n' && end < 96) {
                end++;
            }
            snprintf(d->app, sizeof(d->app), "HTTP %.*s", (int)end, (const char *)p);
            d->app_flags |= PS_APP_HTTP;
            return;
        }
    }
}

/* ---- transport layer ---- */

static void decode_tcp(const uint8_t *p, uint32_t len, struct ps_decoded *d) {
    if (len < 20) {
        return;
    }
    d->l4 = PS_L4_TCP;
    d->l4_proto = 6;
    d->sport = ps_be16(p + 0);
    d->dport = ps_be16(p + 2);
    d->seq = ps_be32(p + 4);
    d->ack = ps_be32(p + 8);
    d->tcp_flags = p[13];
    d->window = ps_be16(p + 14);

    uint32_t hdr = (uint32_t)(p[12] >> 4) * 4u;
    if (hdr < 20 || hdr > len) {
        hdr = 20;
    } else {
        /* MSS option, if present (kind 2, len 4). */
        uint32_t opt = 20;
        while (opt + 1 < hdr) {
            uint8_t kind = p[opt];
            if (kind == 0) {
                break;
            }
            if (kind == 1) {
                opt++;
                continue;
            }
            if (opt + 2 > hdr) {
                break;
            }
            uint8_t olen = p[opt + 1];
            if (olen < 2 || opt + olen > hdr) {
                break;
            }
            if (kind == 2 && olen == 4) {
                d->tcp_mss = ps_be16(p + opt + 2);
            }
            opt += olen;
        }
    }

    d->l4_len = (uint16_t)MIN(len, 0xFFFFu);
    d->payload = p + hdr;
    d->payload_len = len - hdr;
}

static void decode_udp(const uint8_t *p, uint32_t len, struct ps_decoded *d) {
    if (len < 8) {
        return;
    }
    d->l4 = PS_L4_UDP;
    d->l4_proto = 17;
    d->sport = ps_be16(p + 0);
    d->dport = ps_be16(p + 2);
    d->l4_len = ps_be16(p + 4);

    d->payload = p + 8;
    d->payload_len = len - 8;
    if (d->l4_len >= 8 && (uint32_t)d->l4_len - 8 < d->payload_len) {
        d->payload_len = d->l4_len - 8;
    }
}

static void decode_icmp(const uint8_t *p, uint32_t len, struct ps_decoded *d, int v6) {
    if (len < 4) {
        return;
    }
    d->l4 = v6 ? PS_L4_ICMPV6 : PS_L4_ICMP;
    d->l4_proto = v6 ? 58 : 1;
    d->icmp_type = p[0];
    d->icmp_code = p[1];
    d->l4_len = (uint16_t)MIN(len, 0xFFFFu);
    d->payload = len > 8 ? p + 8 : NULL;
    d->payload_len = len > 8 ? len - 8 : 0;
}

/* ---- network layer ---- */

static void decode_arp(const uint8_t *p, uint32_t len, struct ps_decoded *d) {
    if (len < 8) {
        return;
    }
    d->arp_op = ps_be16(p + 6);
    if (len >= 28) {
        fmt_mac(p + 8, d->arp_sender_mac, sizeof(d->arp_sender_mac));
        inet_ntop(AF_INET, p + 14, d->arp_sender_ip, sizeof(d->arp_sender_ip));
        inet_ntop(AF_INET, p + 24, d->arp_target_ip, sizeof(d->arp_target_ip));
    }
    switch (d->arp_op) {
    case 1:
        snprintf(d->info, sizeof(d->info), "who-has %s tell %s", d->arp_target_ip,
                 d->arp_sender_ip);
        break;
    case 2:
        snprintf(d->info, sizeof(d->info), "%s is-at %s", d->arp_sender_ip, d->arp_sender_mac);
        break;
    default:
        snprintf(d->info, sizeof(d->info), "op=%u", d->arp_op);
        break;
    }
}

static void decode_ipv4(const uint8_t *p, uint32_t len, struct ps_decoded *d) {
    uint32_t ihl;
    uint32_t total_len;
    uint32_t avail;
    uint16_t frag;

    if (len < 20) {
        return;
    }
    ihl = (uint32_t)(p[0] & 0x0F) * 4u;
    if (ihl < 20 || ihl > len) {
        return;
    }
    total_len = ps_be16(p + 2);
    d->ip_version = 4;
    d->l4_proto = p[9];
    d->ttl = p[8];
    inet_ntop(AF_INET, p + 12, d->src, sizeof(d->src));
    inet_ntop(AF_INET, p + 16, d->dst, sizeof(d->dst));

    frag = ps_be16(p + 6);
    if ((frag & 0x2000) != 0 || (frag & 0x1FFF) != 0) {
        d->fragmented = 1;
    }

    avail = len - ihl;
    if (total_len >= ihl && total_len - ihl < avail) {
        avail = total_len - ihl; /* ignore Ethernet padding */
    }
    if (frag & 0x1FFF) {
        /* Non-first fragment: no transport header present. */
        d->l4 = PS_L4_OTHER;
        return;
    }

    const uint8_t *l4 = p + ihl;
    switch (d->l4_proto) {
    case 6:
        decode_tcp(l4, avail, d);
        break;
    case 17:
        decode_udp(l4, avail, d);
        break;
    case 1:
        decode_icmp(l4, avail, d, 0);
        break;
    case 2:
    case 4:
    case 47:
    case 132:
        d->l4 = PS_L4_OTHER;
        break;
    default:
        d->l4 = PS_L4_OTHER;
        break;
    }
}

static void decode_ipv6(const uint8_t *p, uint32_t len, struct ps_decoded *d) {
    uint8_t next;
    uint32_t off = 40;

    if (len < 40) {
        return;
    }
    d->ip_version = 6;
    d->ttl = p[7];
    next = p[6];
    inet_ntop(AF_INET6, p + 8, d->src, sizeof(d->src));
    inet_ntop(AF_INET6, p + 24, d->dst, sizeof(d->dst));

    /* Skip extension headers. */
    while (off + 8 <= len) {
        if (next == 0 || next == 43 || next == 60) {
            uint8_t hdr_next = p[off];
            uint32_t hdr_len = ((uint32_t)p[off + 1] + 1u) * 8u;
            off += hdr_len;
            next = hdr_next;
            continue;
        }
        if (next == 44) { /* fragment */
            uint16_t frag = ps_be16(p + off + 2);
            d->fragmented = 1;
            next = p[off];
            off += 8;
            if ((frag & 0xFFF8) != 0) {
                d->l4_proto = next;
                d->l4 = PS_L4_OTHER;
                return;
            }
            continue;
        }
        break;
    }
    if (off > len) {
        return;
    }

    d->l4_proto = next;
    const uint8_t *l4 = p + off;
    uint32_t avail = len - off;

    switch (next) {
    case 6:
        decode_tcp(l4, avail, d);
        break;
    case 17:
        decode_udp(l4, avail, d);
        break;
    case 58:
        decode_icmp(l4, avail, d, 1);
        break;
    default:
        d->l4 = PS_L4_OTHER;
        break;
    }
}

/* ---- link layer ---- */

int ps_decode(const uint8_t *data, uint32_t caplen, uint32_t origlen, uint16_t linktype,
              struct ps_decoded *out) {
    uint32_t off = 0;
    uint16_t ethertype = 0;

    memset(out, 0, sizeof(*out));
    out->caplen = caplen;
    out->origlen = origlen;

    switch (linktype) {
    case PS_DLT_EN10MB: {
        if (caplen < ETH_HDR_LEN) {
            return -1;
        }
        out->has_eth = 1;
        fmt_mac(data + 6, out->src_mac, sizeof(out->src_mac));
        fmt_mac(data + 0, out->dst_mac, sizeof(out->dst_mac));
        ethertype = ps_be16(data + 12);
        off = ETH_HDR_LEN;

        while ((ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ ||
                ethertype == ETHERTYPE_VLAN_9100) &&
               caplen >= off + VLAN_TAG_LEN) {
            if (!out->has_vlan) {
                out->has_vlan = 1;
                out->vlan_id = ps_be16(data + off) & 0x0FFF;
            }
            ethertype = ps_be16(data + off + 2);
            off += VLAN_TAG_LEN;
        }
        break;
    }
    case PS_DLT_LINUX_SLL: {
        if (caplen < SLL_HDR_LEN) {
            return -1;
        }
        ethertype = ps_be16(data + 14);
        off = SLL_HDR_LEN;
        break;
    }
    case PS_DLT_LINUX_SLL2: {
        if (caplen < SLL2_HDR_LEN) {
            return -1;
        }
        ethertype = ps_be16(data + 0);
        off = SLL2_HDR_LEN;
        break;
    }
    case PS_DLT_NULL:
    case PS_DLT_LOOP: {
        uint32_t family;

        if (caplen < 4) {
            return -1;
        }
        family = linktype == PS_DLT_NULL ? ps_le32(data) : ps_be32(data);
        off = 4;
        switch (family) {
        case 2: /* AF_INET */
            ethertype = ETHERTYPE_IPV4;
            break;
        case 10:
        case 24:
        case 28:
        case 30: /* AF_INET6 variants */
            ethertype = ETHERTYPE_IPV6;
            break;
        default:
            out->ethertype = (uint16_t)family;
            return 0;
        }
        break;
    }
    case PS_DLT_RAW: {
        if (caplen < 1) {
            return -1;
        }
        ethertype = (data[0] >> 4) == 4 ? ETHERTYPE_IPV4 : ETHERTYPE_IPV6;
        break;
    }
    default:
        return -1;
    }

    out->ethertype = ethertype;
    if (caplen < off) {
        return -1;
    }
    const uint8_t *l3 = data + off;
    uint32_t l3_len = caplen - off;

    switch (ethertype) {
    case ETHERTYPE_IPV4:
        decode_ipv4(l3, l3_len, out);
        break;
    case ETHERTYPE_IPV6:
        decode_ipv6(l3, l3_len, out);
        break;
    case ETHERTYPE_ARP:
        decode_arp(l3, l3_len, out);
        break;
    default:
        out->ip_version = 0;
        break;
    }

    if (out->l4 == PS_L4_UDP && out->payload_len > 0 &&
        (out->sport == 53 || out->dport == 53)) {
        peek_dns(out);
    } else if (out->l4 == PS_L4_TCP && out->payload_len > 0) {
        if (out->payload[0] == 0x16) {
            peek_tls(out);
        } else {
            peek_http(out);
        }
    }
    return 0;
}

/* ---- rendering ---- */

void ps_decoded_format_line(const struct ps_decoded *d, char *out, size_t cap) {
    size_t off = 0;
    char flags[48];
    char ports[96];

    ports[0] = '\0';
    if (d->l4 == PS_L4_TCP || d->l4 == PS_L4_UDP) {
        snprintf(ports, sizeof(ports), ":%u -> %s:%u", d->sport, d->dst, d->dport);
    } else if (d->ip_version) {
        snprintf(ports, sizeof(ports), " -> %s", d->dst);
    }

    if (d->ip_version) {
        off = ps_appendf(out, cap, off, "%-5s %s%s", ps_proto_label(d), d->src, ports);
    } else if (d->ethertype == ETHERTYPE_ARP) {
        off = ps_appendf(out, cap, off, "%-5s %s > %s", "ARP", d->src_mac, d->dst_mac);
    } else {
        off = ps_appendf(out, cap, off, "%-5s %s > %s type=0x%04x", "ETH", d->src_mac,
                         d->dst_mac, d->ethertype);
    }

    off = ps_appendf(out, cap, off, "  %u B", d->origlen);
    if (d->ip_version) {
        off = ps_appendf(out, cap, off, " ttl=%u", d->ttl);
    }
    if (d->has_vlan) {
        off = ps_appendf(out, cap, off, " vlan=%u", d->vlan_id);
    }

    if (d->l4 == PS_L4_TCP) {
        ps_tcp_flag_str(d->tcp_flags, flags, sizeof(flags));
        if (flags[0])
            off = ps_appendf(out, cap, off, " %s", flags);
        off = ps_appendf(out, cap, off, " seq=%u ack=%u win=%u", d->seq, d->ack, d->window);
    } else if (d->l4 == PS_L4_ICMP || d->l4 == PS_L4_ICMPV6) {
        off = ps_appendf(out, cap, off, " type=%u code=%u", d->icmp_type, d->icmp_code);
    }

    if (d->fragmented) {
        off = ps_appendf(out, cap, off, " frag");
    }
    if (d->app[0]) {
        off = ps_appendf(out, cap, off, " | %s", d->app);
    } else if (d->info[0]) {
        ps_appendf(out, cap, off, " | %s", d->info);
    }
}

void ps_hexdump(const uint8_t *data, size_t len, size_t max, char *out, size_t cap) {
    size_t off = 0;
    size_t show = MIN(len, max);
    char ascii[17];

    for (size_t i = 0; i < show; i += 16) {
        off = ps_appendf(out, cap, off, "  %04zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < show) {
                off = ps_appendf(out, cap, off, "%02x ", data[i + j]);
                uint8_t c = data[i + j];
                ascii[j] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
            } else {
                off = ps_appendf(out, cap, off, "   ");
                ascii[j] = ' ';
            }
            if (j == 7) {
                off = ps_appendf(out, cap, off, " ");
            }
        }
        ascii[16] = '\0';
        off = ps_appendf(out, cap, off, " |%s|", ascii);
        if (i + 16 < show) {
            off = ps_appendf(out, cap, off, "\n");
        }
    }
    if (show < len) {
        ps_appendf(out, cap, off, "\n  ... %zu more bytes", len - show);
    }
}
