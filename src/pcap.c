/* pcap.c - minimal classic .pcap writer. */
#include "pcap.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

#define PCAP_GLOBAL_HDR_LEN 24u
#define PCAP_RECORD_HDR_LEN 16u
#define PCAP_MAGIC 0xa1b2c3d4u /* microsecond resolution; always written little-endian */

static int write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t done = 0;

    while (done < len) {
        ssize_t n = write(fd, p + done, len - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

/* "cap.pcap" -> "cap.1.pcap", "cap" -> "cap.1" */
static void rotation_name(char *out, size_t cap, const char *path, unsigned seq) {
    const char *slash = strrchr(path, '/');
    const char *dot = strrchr(path, '.');

    if (seq == 0) {
        ps_strlcpy(out, path, cap);
        return;
    }
    if (dot && (!slash || dot > slash)) {
        snprintf(out, cap, "%.*s.%u%s", (int)(dot - path), path, seq, dot);
    } else {
        snprintf(out, cap, "%s.%u", path, seq);
    }
}

static int write_global_header(const struct ps_pcap *w, int fd) {
    uint8_t hdr[PCAP_GLOBAL_HDR_LEN];

    memset(hdr, 0, sizeof(hdr));
    ps_put_le32(hdr + 0, PCAP_MAGIC);
    ps_put_le16(hdr + 4, 2); /* version major */
    ps_put_le16(hdr + 6, 4); /* version minor */
    ps_put_le32(hdr + 8, 0); /* thiszone */
    ps_put_le32(hdr + 12, 0);
    ps_put_le32(hdr + 16, w->snaplen);
    ps_put_le32(hdr + 20, w->linktype);
    return write_all(fd, hdr, sizeof(hdr));
}

int ps_pcap_open(struct ps_pcap *w, const char *path, uint32_t snaplen, uint16_t linktype,
                 uint64_t rotate_bytes, char *err, size_t errsz) {
    memset(w, 0, sizeof(*w));
    w->snaplen = snaplen ? snaplen : PS_SNAPLEN_DEFAULT;
    w->linktype = linktype;
    w->rotate_bytes = rotate_bytes;
    w->fd = -1;

    if (!path || !*path || strcmp(path, "-") == 0) {
        w->fd = STDOUT_FILENO;
        ps_strlcpy(w->path, "-", sizeof(w->path));
        if (write_global_header(w, w->fd) != 0) {
            snprintf(err, errsz, "cannot write pcap header to stdout: %s", strerror(errno));
            return -1;
        }
        return 0;
    }

    ps_strlcpy(w->path, path, sizeof(w->path));
    w->fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (w->fd < 0) {
        snprintf(err, errsz, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    if (write_global_header(w, w->fd) != 0) {
        snprintf(err, errsz, "cannot write pcap header: %s", strerror(errno));
        close(w->fd);
        w->fd = -1;
        return -1;
    }
    return 0;
}

static int rotate(struct ps_pcap *w) {
    char name[600];

    if (w->fd <= STDOUT_FILENO) {
        return 0;
    }
    close(w->fd);
    w->seq++;
    rotation_name(name, sizeof(name), w->path, w->seq);
    w->fd = open(name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (w->fd < 0) {
        return -1;
    }
    w->bytes_written = 0;
    return write_global_header(w, w->fd);
}

int ps_pcap_write(struct ps_pcap *w, const struct ps_record *rec) {
    uint8_t hdr[PCAP_RECORD_HDR_LEN];
    uint32_t incl = rec->caplen;

    if (w->fd < 0) {
        return -1;
    }
    if (incl > w->snaplen) {
        incl = w->snaplen;
    }
    ps_put_le32(hdr + 0, rec->ts_sec);
    ps_put_le32(hdr + 4, rec->ts_usec);
    ps_put_le32(hdr + 8, incl);
    ps_put_le32(hdr + 12, rec->origlen);

    if (write_all(w->fd, hdr, sizeof(hdr)) != 0 || write_all(w->fd, rec->data, incl) != 0) {
        return -1;
    }
    w->bytes_written += PCAP_RECORD_HDR_LEN + incl;
    w->packets_written++;

    if (w->rotate_bytes && w->bytes_written >= w->rotate_bytes && rotate(w) != 0) {
        return -1;
    }
    return 0;
}

int ps_pcap_flush(struct ps_pcap *w) {
    return w->fd < 0 ? -1 : fsync(w->fd);
}

void ps_pcap_close(struct ps_pcap *w) {
    if (w && w->fd > STDOUT_FILENO) {
        close(w->fd);
    }
    if (w) {
        w->fd = -1;
    }
}
