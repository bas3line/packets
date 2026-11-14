/* test_decode.c - dissection of hand-built frames, including truncation. */
#include <stdio.h>
#include <string.h>

#include "decode.h"
#include "test.h"

/* Builds an Ethernet + IPv4 + UDP frame; returns its length. */
static size_t build_udp(uint8_t *buf, size_t cap) {
    static const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef};
    size_t n = 0;

    memset(buf, 0, cap);
    /* dst mac, src mac */
    memset(buf + 0, 0x11, 6);
    memset(buf + 6, 0x22, 6);
    buf[12] = 0x08;
    buf[13] = 0x00;
    n = 14;

    /* IPv4 */
    buf[n + 0] = 0x45;
    buf[n + 2] = 0;
    buf[n + 3] = (uint8_t)(20 + 8 + sizeof(payload));
    buf[n + 8] = 64; /* ttl */
    buf[n + 9] = 17; /* udp */
    buf[n + 12] = 10;
    buf[n + 13] = 0;
    buf[n + 14] = 0;
    buf[n + 15] = 1;
    buf[n + 16] = 10;
    buf[n + 17] = 0;
    buf[n + 18] = 0;
    buf[n + 19] = 2;
    n += 20;

    /* UDP */
    buf[n + 0] = 0x1F;
    buf[n + 1] = 0x90; /* 8080 */
    buf[n + 2] = 0x00;
    buf[n + 3] = 0x35; /* 53 */
    buf[n + 4] = 0;
    buf[n + 5] = (uint8_t)(8 + sizeof(payload));
    n += 8;

    memcpy(buf + n, payload, sizeof(payload));
    return n + sizeof(payload);
}

/* Rewrites the IPv4 total-length and UDP length fields so the frame is valid
 * for a payload of `payload_len` bytes appended after the 42-byte headers. */
static void fix_lengths_n(uint8_t *frame, size_t payload_len, size_t l4_hdr) {
    uint16_t ip_total = (uint16_t)(20 + l4_hdr + payload_len);

    frame[16] = (uint8_t)(ip_total >> 8);
    frame[17] = (uint8_t)(ip_total & 0xFF);
    if (l4_hdr == 8) {
        uint16_t udp_total = (uint16_t)(8 + payload_len);
        frame[38] = (uint8_t)(udp_total >> 8);
        frame[39] = (uint8_t)(udp_total & 0xFF);
    }
}

static void fix_lengths(uint8_t *frame, size_t payload_len) {
    fix_lengths_n(frame, payload_len, 8);
}

/* Same as build_udp() but over TCP with no payload; returns its length. */
static size_t build_tcp(uint8_t *buf, size_t cap) {
    size_t n = build_udp(buf, cap);

    /* Turn the 42-byte headers into TCP by swapping the transport header. */
    n = 14 + 20;
    buf[14 + 9] = 6; /* protocol */
    memset(buf + n, 0, 20);
    n += 20;
    buf[34] = 0xC3;
    buf[35] = 0x50; /* sport 50000 */
    buf[36] = 0x01;
    buf[37] = 0xBB; /* dport 443 */
    buf[46] = 0x50; /* data offset 5 */
    return n;
}

static void test_udp_basics(void) {
    uint8_t frame[128];
    struct ps_decoded d;
    size_t len = build_udp(frame, sizeof(frame));

    CHECK_EQ(ps_decode(frame, (uint32_t)len, (uint32_t)len, PS_DLT_EN10MB, &d), 0);
    CHECK(d.has_eth);
    CHECK_EQ(d.ip_version, 4);
    CHECK_EQ(d.l4, PS_L4_UDP);
    CHECK_EQ(d.sport, 8080);
    CHECK_EQ(d.dport, 53);
    CHECK_EQ(d.ttl, 64);
    CHECK_STR(d.src, "10.0.0.1");
    CHECK_STR(d.dst, "10.0.0.2");
    CHECK_STR(d.src_mac, "22:22:22:22:22:22");
    CHECK_EQ(d.payload_len, 4);
    CHECK_MEM(d.payload, "\xde\xad\xbe\xef", 4);
}

static void test_every_truncation(void) {
    uint8_t frame[128];
    struct ps_decoded d;
    size_t len = build_udp(frame, sizeof(frame));

    /* No prefix may read out of bounds, and short frames must fail cleanly. */
    for (size_t cut = 0; cut <= len; cut++) {
        int rc = ps_decode(frame, (uint32_t)cut, (uint32_t)len, PS_DLT_EN10MB, &d);
        if (cut < 14) {
            CHECK_EQ(rc, -1);
        } else {
            CHECK_EQ(rc, 0);
        }
    }
}

static void test_vlan_tag(void) {
    uint8_t frame[160];
    struct ps_decoded d;

    memset(frame, 0, sizeof(frame));
    memset(frame + 0, 0x11, 6);
    memset(frame + 6, 0x22, 6);
    frame[12] = 0x81;
    frame[13] = 0x00; /* 802.1Q */
    frame[14] = 0x00;
    frame[15] = 0x2A; /* vlan 42 */
    frame[16] = 0x08;
    frame[17] = 0x00; /* IPv4 */
    frame[18] = 0x45;
    frame[20] = 0x00;
    frame[21] = 40;
    frame[26] = 64;
    frame[27] = 6;
    frame[30] = 192;
    frame[31] = 168;
    frame[32] = 0;
    frame[33] = 1;
    frame[34] = 192;
    frame[35] = 168;
    frame[36] = 0;
    frame[37] = 2;
    /* TCP header (data offset 5) */
    frame[50] = 0x50;
    frame[38] = 0x01;
    frame[39] = 0xBB;
    frame[40] = 0x30;
    frame[41] = 0x39;
    frame[51] = 0x02; /* SYN */

    CHECK_EQ(ps_decode(frame, 58, 58, PS_DLT_EN10MB, &d), 0);
    CHECK(d.has_vlan);
    CHECK_EQ(d.vlan_id, 42);
    CHECK_EQ(d.l4, PS_L4_TCP);
    CHECK_EQ(d.tcp_flags, PS_TCP_SYN);
    CHECK_EQ(d.sport, 443);
    CHECK_EQ(d.dport, 12345);
}

static void test_arp(void) {
    uint8_t frame[64];
    struct ps_decoded d;

    memset(frame, 0, sizeof(frame));
    memset(frame + 0, 0xFF, 6);
    memset(frame + 6, 0x22, 6);
    frame[12] = 0x08;
    frame[13] = 0x06;
    frame[14] = 0x00;
    frame[15] = 0x01;
    frame[16] = 0x08;
    frame[17] = 0x00;
    frame[18] = 6;
    frame[19] = 4;
    frame[20] = 0x00;
    frame[21] = 0x01; /* request */
    memset(frame + 22, 0x22, 6);
    frame[28] = 10, frame[29] = 0, frame[30] = 0, frame[31] = 5;
    memset(frame + 32, 0x00, 6);
    frame[38] = 10, frame[39] = 0, frame[40] = 0, frame[41] = 1;

    CHECK_EQ(ps_decode(frame, 42, 42, PS_DLT_EN10MB, &d), 0);
    CHECK_STR(ps_proto_label(&d), "ARP");
    CHECK_EQ(d.arp_op, 1);
    CHECK_STR(d.arp_sender_ip, "10.0.0.5");
    CHECK_STR(d.arp_target_ip, "10.0.0.1");
    CHECK(strstr(d.info, "who-has 10.0.0.1") != NULL);
}

static void test_raw_ip_and_ipv6(void) {
    uint8_t frame[128];
    struct ps_decoded d;

    /* Bare IPv4 (DLT_RAW). */
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x45;
    frame[9] = 1; /* ICMP */
    frame[12] = 172;
    frame[13] = 16;
    frame[14] = 0;
    frame[15] = 1;
    frame[16] = 172;
    frame[17] = 16;
    frame[18] = 0;
    frame[19] = 2;
    frame[20] = 8; /* echo request */
    CHECK_EQ(ps_decode(frame, 28, 28, PS_DLT_RAW, &d), 0);
    CHECK_EQ(d.l4, PS_L4_ICMP);
    CHECK_EQ(d.icmp_type, 8);

    /* Bare IPv6 (DLT_RAW) + ICMPv6. */
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x60;
    frame[6] = 58; /* next header: ICMPv6 */
    frame[7] = 255;
    frame[8] = 0xfe;
    frame[24] = 0xfe;
    frame[39] = 1;
    frame[40] = 128; /* echo request */
    CHECK_EQ(ps_decode(frame, 48, 48, PS_DLT_RAW, &d), 0);
    CHECK_EQ(d.ip_version, 6);
    CHECK_EQ(d.l4, PS_L4_ICMPV6);
    CHECK_STR(d.dst, "fe00::1");
}

static void test_dns_peek(void) {
    uint8_t frame[128];
    struct ps_decoded d;
    size_t len;
    size_t n;
    static const uint8_t query[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',
        0,    0x00, 0x01, 0x00, 0x01,
    };

    len = build_udp(frame, sizeof(frame));
    n = len - 4;
    memcpy(frame + n, query, sizeof(query));
    len = n + sizeof(query);
    fix_lengths(frame, sizeof(query));

    CHECK_EQ(ps_decode(frame, (uint32_t)len, (uint32_t)len, PS_DLT_EN10MB, &d), 0);
    CHECK(d.app_flags & PS_APP_DNS);
    CHECK_STR(d.app, "DNS A example.com");
}

static void test_tls_sni(void) {
    /* Minimal ClientHello carrying a server_name extension. */
    static const uint8_t hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x3b, /* record header, len 59 */
        0x01, 0x00, 0x00, 0x37,       /* ClientHello, len 55 */
        0x03, 0x03,                   /* client version */
        /* 32-byte random */
        1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        0x00,       /* session id length */
        0x00, 0x02, /* cipher suites length */
        0x13, 0x01, /* TLS_AES_128_GCM_SHA256 */
        0x01, 0x00, /* compression methods */
        0x00, 0x0c, /* extensions length */
        0x00, 0x00, 0x00, 0x08, /* server_name, len 8 */
        0x00, 0x06,             /* server name list, len 6 */
        0x00, 0x00, 0x03,       /* host_name, len 3 */
        'a', '.', 'b',
    };
    uint8_t frame[256];
    struct ps_decoded d;
    size_t n = build_tcp(frame, sizeof(frame));

    memcpy(frame + n, hello, sizeof(hello));
    size_t len = n + sizeof(hello);
    fix_lengths_n(frame, sizeof(hello), 20);

    CHECK_EQ(ps_decode(frame, (uint32_t)len, (uint32_t)len, PS_DLT_EN10MB, &d), 0);
    CHECK(d.app_flags & PS_APP_TLS);
    CHECK_STR(d.app, "TLS SNI=a.b");
}

static void test_hexdump(void) {
    char out[1024];
    static const uint8_t data[] = {'A', 'B', 0x01, 0xff};

    ps_hexdump(data, sizeof(data), 64, out, sizeof(out));
    CHECK(strstr(out, "41 42 01 ff") != NULL);
    CHECK(strstr(out, "|AB..") != NULL);
}

int main(void) {
    RUN(test_udp_basics);
    RUN(test_every_truncation);
    RUN(test_vlan_tag);
    RUN(test_arp);
    RUN(test_raw_ip_and_ipv6);
    RUN(test_dns_peek);
    RUN(test_tls_sni);
    RUN(test_hexdump);
    return test_report();
}
