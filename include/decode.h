/* decode.h - bounds-checked protocol dissection.
 *
 * Understands Ethernet II (+802.1Q/QinQ), Linux cooked capture, BSD loopback,
 * bare IP; ARP, IPv4, IPv6 (+ extension headers); TCP, UDP, ICMP, ICMPv6;
 * and a little application-layer curiosity: DNS names, TLS SNI, HTTP verbs.
 */
#ifndef PS_DECODE_H
#define PS_DECODE_H

#include "common.h"

enum ps_l4 {
    PS_L4_NONE = 0,
    PS_L4_TCP,
    PS_L4_UDP,
    PS_L4_ICMP,
    PS_L4_ICMPV6,
    PS_L4_OTHER
};

#define PS_TCP_FIN 0x01
#define PS_TCP_SYN 0x02
#define PS_TCP_RST 0x04
#define PS_TCP_PSH 0x08
#define PS_TCP_ACK 0x10
#define PS_TCP_URG 0x20
#define PS_TCP_ECE 0x40
#define PS_TCP_CWR 0x80

#define PS_APP_DNS 0x01
#define PS_APP_TLS 0x02
#define PS_APP_HTTP 0x04

struct ps_decoded {
    int has_eth;
    char src_mac[18];
    char dst_mac[18];
    int has_vlan;
    uint16_t vlan_id;
    uint16_t ethertype;

    int ip_version; /* 0 = no IP layer (e.g. ARP) */
    char src[64];   /* formatted address, empty if absent */
    char dst[64];
    uint8_t ttl; /* hop limit for v6 */
    int fragmented;

    uint16_t arp_op;
    char arp_sender_ip[64];
    char arp_target_ip[64];
    char arp_sender_mac[18];

    enum ps_l4 l4;
    uint8_t l4_proto;
    uint16_t sport;
    uint16_t dport;
    uint16_t l4_len; /* TCP/UDP segment length incl. header */

    /* TCP */
    uint32_t seq;
    uint32_t ack;
    uint8_t tcp_flags;
    uint16_t window;
    uint16_t tcp_mss;

    /* ICMP */
    uint8_t icmp_type;
    uint8_t icmp_code;

    const uint8_t *payload; /* application payload, may be NULL */
    uint32_t payload_len;

    unsigned app_flags;
    char app[160];  /* "DNS A example.com", "TLS SNI=...", "HTTP GET /index" */
    char info[192]; /* catch-all detail line for display */

    uint32_t caplen;
    uint32_t origlen;
};

/* Returns 0 on success, -1 if the frame is too short to be what it claims. */
int ps_decode(const uint8_t *data, uint32_t caplen, uint32_t origlen, uint16_t linktype,
              struct ps_decoded *out);

const char *ps_l4_name(enum ps_l4 l4);
const char *ps_proto_label(const struct ps_decoded *d);
/* "SYN,ACK" into buf; empty string when no flags. */
void ps_tcp_flag_str(uint8_t flags, char *buf, size_t cap);

/* One-line human rendering (no trailing newline). */
void ps_decoded_format_line(const struct ps_decoded *d, char *out, size_t cap);
/* Classic offset | hex | ascii dump (no trailing newline). `max` caps bytes. */
void ps_hexdump(const uint8_t *data, size_t len, size_t max, char *out, size_t cap);

#endif /* PS_DECODE_H */
