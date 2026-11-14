/* client.h - consumer side: decode, filter, render, record. */
#ifndef PS_CLIENT_H
#define PS_CLIENT_H

#include "common.h"

struct ps_client_opts {
    const char *host;
    uint16_t port;
    const char *filter;     /* display filter, see filter.h */
    const char *pcap_path;  /* optional local recording */
    uint64_t pcap_rotate_bytes;
    const char *json_path;  /* write NDJSON to this file instead of the screen */
    uint64_t count;         /* stop after N matching packets, 0 = unlimited */
    unsigned duration;      /* stop after N seconds, 0 = unlimited */
    size_t hex_bytes;       /* bytes to hexdump, 0 = no hexdump */
    int show_stats;
    int color;              /* 1 force, 0 off, -1 auto (tty only) */
    int quiet;              /* suppress the header/banner */
    int reconnect;
    unsigned stats_interval;
};

int ps_client_run(const struct ps_client_opts *opts);

#endif /* PS_CLIENT_H */
