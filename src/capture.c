/* capture.c - AF_PACKET capture, promiscuous mode, kernel BPF, drop accounting. */
#include "capture.h"

#include <errno.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "util.h"

#ifdef PS_HAVE_PCAP
#include <pcap/pcap.h>
#endif

#define RX_RING_MAX (64u * 1024u * 1024u)

static int attach_bpf(int fd, const char *expr, uint16_t linktype, char *err, size_t errsz) {
#ifdef PS_HAVE_PCAP
    struct bpf_program prog;
    struct sock_fprog fprog;
    pcap_t *dead;
    int rc = 0;

    dead = pcap_open_dead((int)linktype, PS_SNAPLEN_MAX);
    if (!dead) {
        snprintf(err, errsz, "pcap_open_dead failed");
        return -1;
    }
    if (pcap_compile(dead, &prog, expr, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        snprintf(err, errsz, "bad filter expression: %s", pcap_geterr(dead));
        pcap_close(dead);
        return -1;
    }
    fprog.len = (unsigned short)prog.bf_len;
    fprog.filter = (struct sock_filter *)prog.bf_insns;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) < 0) {
        snprintf(err, errsz, "SO_ATTACH_FILTER: %s", strerror(errno));
        rc = -1;
    }
    pcap_freecode(&prog);
    pcap_close(dead);
    return rc;
#else
    PS_UNUSED(fd);
    PS_UNUSED(linktype);
    snprintf(err, errsz,
             "this build has no libpcap, so \"%s\" cannot be compiled "
             "(rebuild with libpcap-dev installed, or use the client-side --filter)",
             expr);
    return -1;
#endif
}

int ps_capture_open(struct ps_capture *cap, const char *iface, uint32_t snaplen, int promisc,
                    enum ps_direction direction, const char *bpf_expr, char *err, size_t errsz) {
    struct sockaddr_ll sll;
    int fd;
    int opt;

    memset(cap, 0, sizeof(*cap));
    cap->fd = -1;
    cap->linktype = PS_LINKTYPE_ETHERNET;
    cap->snaplen = snaplen ? snaplen : PS_SNAPLEN_DEFAULT;
    cap->promisc = promisc;
    cap->direction = direction;

    if (!iface || !*iface || strcmp(iface, "any") == 0) {
        ps_strlcpy(cap->iface, "any", sizeof(cap->iface));
    } else {
        cap->ifindex = if_nametoindex(iface);
        if (cap->ifindex == 0) {
            snprintf(err, errsz, "no such interface '%s'", iface);
            return -1;
        }
        ps_strlcpy(cap->iface, iface, sizeof(cap->iface));
    }

    fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) {
        snprintf(err, errsz, "AF_PACKET socket: %s (are you root?)", strerror(errno));
        return -1;
    }

    /* Big socket buffer; the kernel doubles what we ask for. */
    opt = RX_RING_MAX;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &opt, sizeof(opt)) < 0) {
        opt = 8 * 1024 * 1024;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) < 0) {
            LOG_DEBUG("SO_RCVBUF: %s", strerror(errno));
        }
    }

    /* Kernel receive timestamps: nanosecond-accurate and taken at the driver,
     * not when we happen to get round to reading the socket. */
    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &opt, sizeof(opt)) < 0) {
        LOG_DEBUG("SO_TIMESTAMPNS: %s", strerror(errno));
    }

    if (cap->ifindex != 0) {
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = (int)cap->ifindex;
        if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            snprintf(err, errsz, "bind to %s: %s", cap->iface, strerror(errno));
            close(fd);
            return -1;
        }

        if (promisc) {
            struct packet_mreq mreq;
            memset(&mreq, 0, sizeof(mreq));
            mreq.mr_ifindex = (int)cap->ifindex;
            mreq.mr_type = PACKET_MR_PROMISC;
            if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
                snprintf(err, errsz, "promiscuous mode on %s: %s", cap->iface, strerror(errno));
                close(fd);
                return -1;
            }
        }
    } else {
        cap->promisc = 0; /* "any" is an aggregate of per-device taps */
    }

    if (bpf_expr && *bpf_expr) {
        if (attach_bpf(fd, bpf_expr, cap->linktype, err, errsz) != 0) {
            close(fd);
            return -1;
        }
    }

    cap->fd = fd;
    return 0;
}

int ps_capture_read(struct ps_capture *cap, uint8_t *buf, size_t bufsz, struct ps_record *rec,
                    int *outgoing) {
    struct sockaddr_ll from;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    union {
        char buf[CMSG_SPACE(sizeof(struct timespec))];
        struct cmsghdr align;
    } control;
    ssize_t n;

    memset(&from, 0, sizeof(from));
    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buf;
    iov.iov_len = bufsz;
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    n = recvmsg(cap->fd, &msg, MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        if (errno == EINTR) {
            return 0;
        }
        return -1;
    }
    if (n == 0) {
        return 0;
    }

    if (outgoing) {
        *outgoing = (from.sll_pkttype == PACKET_OUTGOING);
    }

    uint32_t sec = 0;
    uint32_t usec = 0;
    int have_ts = 0;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPNS) {
            struct timespec ts;
            memcpy(&ts, CMSG_DATA(cmsg), sizeof(ts));
            sec = (uint32_t)ts.tv_sec;
            usec = (uint32_t)(ts.tv_nsec / 1000);
            have_ts = 1;
            break;
        }
    }
    if (!have_ts) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        sec = (uint32_t)ts.tv_sec;
        usec = (uint32_t)(ts.tv_nsec / 1000);
    }

    rec->ts_sec = sec;
    rec->ts_usec = usec;
    rec->caplen = (uint32_t)n;
    rec->origlen = (uint32_t)n;
    rec->data = buf;

    /* The kernel gives us the wire length for outgoing/short captures only via
     * TPACKET headers, which we do not use; origlen == caplen is honest. */
    return (int)n;
}

void ps_capture_update_drops(struct ps_capture *cap) {
    struct tpacket_stats stats;
    socklen_t len = sizeof(stats);

    if (cap->fd < 0) {
        return;
    }
    memset(&stats, 0, sizeof(stats));
    if (getsockopt(cap->fd, SOL_PACKET, PACKET_STATISTICS, &stats, &len) == 0) {
        cap->drops_prev = stats.tp_drops;
        cap->drops_total += stats.tp_drops;
    }
}

void ps_capture_close(struct ps_capture *cap) {
    if (cap && cap->fd >= 0) {
        close(cap->fd);
        cap->fd = -1;
    }
}

void ps_capture_list_interfaces(FILE *out) {
    struct ifaddrs *addrs = NULL;

    if (getifaddrs(&addrs) != 0) {
        return;
    }
    for (struct ifaddrs *a = addrs; a; a = a->ifa_next) {
        if (!a->ifa_name || !(a->ifa_flags & IFF_UP)) {
            continue;
        }
        if (!(a->ifa_flags & (IFF_RUNNING | IFF_LOOPBACK))) {
            continue;
        }
        fprintf(out, "  %-16s %s%s\n", a->ifa_name, (a->ifa_flags & IFF_LOOPBACK) ? "loopback" : "",
                (a->ifa_flags & IFF_PROMISC) ? " (promisc)" : "");
    }
    freeifaddrs(addrs);
}
