/* test_proto.c - framing round-trips, byte-at-a-time feeding, error handling. */
#include <stdio.h>
#include <string.h>

#include "proto.h"
#include "stats.h"
#include "test.h"

static void test_frame_roundtrip(void) {
    uint8_t buf[128];
    uint8_t payload[] = {1, 2, 3, 4, 5};
    size_t n = ps_frame_write(buf, sizeof(buf), PS_FRAME_ERR, payload, sizeof(payload));

    CHECK_EQ(n, PS_HEADER_LEN + sizeof(payload));
    CHECK_EQ(ps_be32(buf), PS_PROTO_MAGIC);
    CHECK_EQ(ps_be16(buf + 4), PS_PROTO_VERSION);
    CHECK_EQ(ps_be16(buf + 6), PS_FRAME_ERR);
    CHECK_EQ(ps_be32(buf + 8), sizeof(payload));
    CHECK_MEM(buf + PS_HEADER_LEN, payload, sizeof(payload));
}

static void test_frame_needs_space(void) {
    uint8_t buf[16];
    CHECK_EQ(ps_frame_write(buf, PS_HEADER_LEN, PS_FRAME_BYE, NULL, 0), PS_HEADER_LEN);
    CHECK_EQ(ps_frame_write(buf, PS_HEADER_LEN, PS_FRAME_BYE, NULL, 1), 0);
}

/* The whole point of the reader: one byte at a time must still yield frames. */
static void test_reader_dribble(void) {
    uint8_t wire[256];
    uint8_t payload[] = "hello world";
    size_t h1 = ps_frame_write(wire, sizeof(wire), PS_FRAME_ERR, payload, sizeof(payload));
    size_t h2 = ps_frame_write(wire + h1, sizeof(wire) - h1, PS_FRAME_BYE, NULL, 0);
    size_t total = h1 + h2;
    struct ps_reader r;
    int frames = 0;

    CHECK_EQ(ps_reader_init(&r, 8), 0);
    for (size_t i = 0; i < total; i++) {
        struct ps_frame f;
        CHECK_EQ(ps_reader_feed(&r, wire + i, 1), 0);
        while (ps_reader_next(&r, &f) == 1) {
            frames++;
            if (f.type == PS_FRAME_ERR) {
                CHECK_EQ(f.len, sizeof(payload));
                CHECK_MEM(f.data, payload, sizeof(payload));
            } else {
                CHECK_EQ(f.type, PS_FRAME_BYE);
                CHECK_EQ(f.len, 0);
            }
        }
    }
    CHECK_EQ(frames, 2);
    ps_reader_free(&r);
}

static void test_reader_rejects_garbage(void) {
    struct ps_reader r;
    struct ps_frame f;
    uint8_t junk[PS_HEADER_LEN] = {0};

    ps_reader_init(&r, 8);
    CHECK_EQ(ps_reader_feed(&r, junk, sizeof(junk)), 0);
    CHECK_EQ(ps_reader_next(&r, &f), -1);
    CHECK_EQ(ps_reader_next(&r, &f), -1); /* sticky */
    ps_reader_free(&r);
}

static void test_packet_codec(void) {
    uint8_t data[] = {0xaa, 0xbb, 0xcc};
    uint8_t buf[64];
    struct ps_record in = {.ts_sec = 1000, .ts_usec = 999, .caplen = 3, .origlen = 60, .data = data};
    struct ps_record out;

    size_t n = ps_packet_encode(buf, sizeof(buf), &in);
    CHECK_EQ(n, PS_PKT_HDR_LEN + 3);
    CHECK_EQ(ps_packet_decode(buf, (uint32_t)n, &out), 0);
    CHECK_EQ(out.ts_sec, 1000);
    CHECK_EQ(out.ts_usec, 999);
    CHECK_EQ(out.caplen, 3);
    CHECK_EQ(out.origlen, 60);
    CHECK_MEM(out.data, data, 3);

    /* Truncated payload must be rejected. */
    CHECK_EQ(ps_packet_decode(buf, (uint32_t)n - 1, &out), -1);
}

static void test_hello_roundtrip(void) {
    struct ps_hello in = {.linktype = 1, .snaplen = 4096};
    struct ps_hello out;
    uint8_t buf[256];

    strcpy(in.hostname, "box.example");
    strcpy(in.iface, "eth0");
    strcpy(in.filter, "tcp port 443");

    size_t n = ps_hello_encode(&in, buf, sizeof(buf));
    CHECK(n > 0);
    CHECK_EQ(ps_hello_decode(buf, (uint32_t)n, &out), 0);
    CHECK_EQ(out.linktype, 1);
    CHECK_EQ(out.snaplen, 4096);
    CHECK_STR(out.hostname, "box.example");
    CHECK_STR(out.iface, "eth0");
    CHECK_STR(out.filter, "tcp port 443");

    /* Unterminated strings must fail, not run off the end. */
    CHECK_EQ(ps_hello_decode(buf, (uint32_t)n - 1, &out), -1);
}

static void test_counters_wire(void) {
    struct ps_counters in;
    struct ps_counters out;
    uint8_t buf[PS_COUNTER_WIRE_SIZE];

    ps_counters_clear(&in);
    in.seen = 5000;
    in.tcp = 42;
    in.dns = 7;
    in.dropped_client = 3;
    in.dropped_kernel = 1;

    CHECK_EQ(ps_counters_encode(&in, buf, sizeof(buf)), PS_COUNTER_WIRE_SIZE);
    CHECK_EQ(ps_counters_decode(buf, sizeof(buf), &out), 0);
    CHECK_EQ(out.seen, 5000);
    CHECK_EQ(out.tcp, 42);
    CHECK_EQ(out.dns, 7);
    CHECK_EQ(out.dropped_client, 3);
    CHECK_EQ(out.dropped_kernel, 1);
    CHECK_EQ(out.udp, 0);

    CHECK_EQ(ps_counters_decode(buf, PS_COUNTER_WIRE_SIZE - 1, &out), -1);
}

int main(void) {
    RUN(test_frame_roundtrip);
    RUN(test_frame_needs_space);
    RUN(test_reader_dribble);
    RUN(test_reader_rejects_garbage);
    RUN(test_packet_codec);
    RUN(test_hello_roundtrip);
    RUN(test_counters_wire);
    return test_report();
}
