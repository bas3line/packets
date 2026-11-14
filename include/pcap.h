/* pcap.h - minimal classic .pcap writer (no libpcap dependency).
 *
 * Files are written with a native-endian magic so any libpcap/Wireshark/tcpdump
 * build can open them regardless of the machine that produced them.
 */
#ifndef PS_PCAP_H
#define PS_PCAP_H

#include "common.h"
#include "proto.h"

struct ps_pcap {
    int fd;
    uint32_t snaplen;
    uint16_t linktype;
    uint64_t bytes_written;
    uint64_t packets_written;
    uint64_t rotate_bytes; /* 0 = never rotate */
    char path[512];
    unsigned seq; /* rotation counter */
};

/* Opens `path` (empty path, "-" or NULL means stdout) and writes the global
 * header. Returns 0 on success. */
int ps_pcap_open(struct ps_pcap *w, const char *path, uint32_t snaplen, uint16_t linktype,
                 uint64_t rotate_bytes, char *err, size_t errsz);
int ps_pcap_write(struct ps_pcap *w, const struct ps_record *rec);
int ps_pcap_flush(struct ps_pcap *w);
void ps_pcap_close(struct ps_pcap *w);

#endif /* PS_PCAP_H */
