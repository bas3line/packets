/* capture.h - AF_PACKET capture with optional libpcap-compiled BPF.
 *
 * Linux only. The socket is non-blocking and pollable so the server can
 * multiplex it with client sockets in one epoll loop.
 */
#ifndef PS_CAPTURE_H
#define PS_CAPTURE_H

#include <stdio.h>

#include "common.h"
#include "proto.h"

#define PS_IFACE_AUTO ""

enum ps_direction {
    PS_DIR_BOTH = 0,
    PS_DIR_IN = 1, /* ignore packets we sent ourselves */
    PS_DIR_OUT = 2
};

struct ps_capture {
    int fd;
    uint16_t linktype;
    uint32_t snaplen;
    char iface[32];
    uint32_t ifindex;
    int promisc;
    enum ps_direction direction;
    uint64_t drops_prev; /* kernel counter is read-and-clear, so accumulate */
    uint64_t drops_total;
};

/* iface may be "" / "any" to capture on all interfaces. `bpf_expr` may be NULL.
 * Returns 0 on success; on failure fills err and returns -1. */
int ps_capture_open(struct ps_capture *cap, const char *iface, uint32_t snaplen, int promisc,
                    enum ps_direction direction, const char *bpf_expr, char *err, size_t errsz);

/* Non-blocking read of exactly one frame. Returns >0 (bytes captured),
 * 0 when nothing is pending, -1 on fatal error. */
int ps_capture_read(struct ps_capture *cap, uint8_t *buf, size_t bufsz, struct ps_record *rec,
                    int *outgoing);

void ps_capture_update_drops(struct ps_capture *cap);
void ps_capture_close(struct ps_capture *cap);

/* Human-readable interface list, one per line, for --list-interfaces. */
void ps_capture_list_interfaces(FILE *out);

#endif /* PS_CAPTURE_H */
