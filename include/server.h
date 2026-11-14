/* server.h - capture side: accepts clients, fans frames out, never blocks. */
#ifndef PS_SERVER_H
#define PS_SERVER_H

#include "common.h"
#include "stats.h"

struct ps_server_opts {
    const char *iface;
    const char *bind_addr;
    uint16_t port;
    const char *bpf;      /* kernel filter (requires libpcap) */
    uint32_t snaplen;
    int promisc;
    enum {
        PS_SERVER_DIR_BOTH = 0,
        PS_SERVER_DIR_IN,
        PS_SERVER_DIR_OUT
    } direction;
    int max_clients;
    size_t client_buffer;  /* bytes queued per slow client before dropping */
    unsigned stats_interval;
    const char *pcap_path; /* optional server-side recording */
    uint64_t pcap_rotate_bytes;
    int quiet;
    int capture_control; /* include our own control connection in the capture */
};

/* Blocks until SIGINT/SIGTERM. Returns process exit code. */
int ps_server_run(const struct ps_server_opts *opts);

#endif /* PS_SERVER_H */
