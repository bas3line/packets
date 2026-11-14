/* test_filter.c - filter grammar and matching. */
#include <stdio.h>
#include <string.h>

#include "filter.h"
#include "test.h"

static struct ps_decoded tcp_pkt(uint16_t sport, uint16_t dport, const char *src,
                                 const char *dst) {
    struct ps_decoded d;

    memset(&d, 0, sizeof(d));
    d.l4 = PS_L4_TCP;
    d.ip_version = 4;
    d.sport = sport;
    d.dport = dport;
    d.origlen = 120;
    strcpy(d.src, src);
    strcpy(d.dst, dst);
    d.payload = (const uint8_t *)"GET /secret HTTP/1.1\r\n";
    d.payload_len = 23;
    return d;
}

static void test_expr_matching(void) {
    struct ps_filter f;
    char err[128];
    struct ps_decoded d = tcp_pkt(51000, 443, "10.1.2.3", "93.184.216.34");

    CHECK_EQ(ps_filter_parse("proto:tcp port:443", &f, err, sizeof(err)), 0);
    CHECK_EQ(f.groups[0].count, 2);
    CHECK(ps_filter_match(&f, &d));

    CHECK_EQ(ps_filter_parse("port:80", &f, err, sizeof(err)), 0);
    CHECK(!ps_filter_match(&f, &d));

    CHECK_EQ(ps_filter_parse("!port:80", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_match(&f, &d));

    CHECK_EQ(ps_filter_parse("host:10.0.0.0/8", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_match(&f, &d));

    CHECK_EQ(ps_filter_parse("host:192.168.0.0/16", &f, err, sizeof(err)), 0);
    CHECK(!ps_filter_match(&f, &d));

    CHECK_EQ(ps_filter_parse("host:10.0.0.0/8,dst:93.184.216.0/24", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_match(&f, &d));

    CHECK_EQ(ps_filter_parse("contains:secret", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_match(&f, &d));

    CHECK_EQ(ps_filter_parse("bytes:>100", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_match(&f, &d));

    CHECK_EQ(ps_filter_parse("443", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_match(&f, &d));
}

static void test_shorthand_and_proto_names(void) {
    struct ps_filter f;
    char err[128];
    struct ps_decoded udp = tcp_pkt(53, 51001, "8.8.8.8", "10.0.0.1");

    udp.l4 = PS_L4_UDP;
    CHECK_EQ(ps_filter_parse("udp", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_match(&f, &udp));

    udp.app_flags = PS_APP_DNS;
    CHECK_EQ(ps_filter_parse("proto:dns", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_match(&f, &udp));

    CHECK_EQ(ps_filter_parse("tcp", &f, err, sizeof(err)), 0);
    CHECK(!ps_filter_match(&f, &udp));

    CHECK_EQ(ps_filter_parse("8.8.8.8", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_match(&f, &udp));
}

static void test_or_groups(void) {
    struct ps_filter f;
    char err[128];
    struct ps_decoded tcp = tcp_pkt(51000, 443, "10.1.2.3", "93.184.216.34");
    struct ps_decoded udp = tcp_pkt(53, 51001, "8.8.8.8", "10.0.0.1");

    udp.l4 = PS_L4_UDP;

    CHECK_EQ(ps_filter_parse("proto:udp or port:443", &f, err, sizeof(err)), 0);
    CHECK_EQ(f.count, 2);
    CHECK(ps_filter_match(&f, &tcp));
    CHECK(ps_filter_match(&f, &udp));

    /* Groups are AND inside, so one failing term kills only that group. */
    CHECK_EQ(ps_filter_parse("proto:udp port:443 or proto:tcp port:443", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_match(&f, &tcp));
    CHECK(!ps_filter_match(&f, &udp));

    CHECK_EQ(ps_filter_parse("udp|icmp", &f, err, sizeof(err)), 0);
    CHECK_EQ(f.count, 2);
}

static void test_bad_expressions(void) {
    struct ps_filter f;
    char err[128];

    CHECK_EQ(ps_filter_parse("port:notaport", &f, err, sizeof(err)), -1);
    CHECK(err[0] != 0);
    CHECK_EQ(ps_filter_parse("bogus:1", &f, err, sizeof(err)), -1);
    CHECK_EQ(ps_filter_parse("host:999.1.1.1", &f, err, sizeof(err)), -1);
    CHECK_EQ(ps_filter_parse("bytes:>", &f, err, sizeof(err)), -1);
    CHECK_EQ(ps_filter_parse("port:", &f, err, sizeof(err)), -1);
    CHECK_EQ(ps_filter_parse("or tcp", &f, err, sizeof(err)), -1);
    CHECK_EQ(ps_filter_parse("tcp or", &f, err, sizeof(err)), -1);
    CHECK_EQ(ps_filter_parse("", &f, err, sizeof(err)), 0);
    CHECK(ps_filter_is_empty(&f));
}

int main(void) {
    RUN(test_expr_matching);
    RUN(test_shorthand_and_proto_names);
    RUN(test_or_groups);
    RUN(test_bad_expressions);
    return test_report();
}
