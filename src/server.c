/* server.c - epoll event loop: capture fd -> N clients, buffered writes. */
#include "server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "capture.h"
#include "decode.h"
#include "log.h"
#include "outbuf.h"
#include "pcap.h"
#include "proto.h"
#include "util.h"

#define MAX_EVENTS 64
#define EPOLL_BATCH 256

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    PS_UNUSED(sig);
    g_stop = 1;
}

struct client {
    int fd;
    char peer[64];
    struct ps_outbuf q;
    int want_write;
};

struct server {
    struct ps_capture cap;
    struct ps_pcap pcap;
    int have_pcap;
    int listen_fd;
    int epoll_fd;
    struct client *clients;
    int max_clients;
    int nclients;
    struct ps_counters counters;
    struct ps_hello hello;
    unsigned stats_interval;
    size_t client_buffer;
    uint64_t last_kernel_drops;
    int quiet;
    uint8_t *frame_buf;
    size_t frame_buf_cap;
};

static void close_client(struct server *s, int idx) {
    struct client *c = &s->clients[idx];

    LOG_INFO("client %s disconnected (%llu frames dropped, %zu bytes still queued)", c->peer,
             (unsigned long long)c->q.dropped_frames, ps_outbuf_pending(&c->q));
    epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    ps_outbuf_free(&c->q);
    c->fd = -1;
    s->nclients--;
}

/* Returns 1 if the client's queue still holds data (so EPOLLOUT is wanted). */
static int flush_client(struct server *s, int idx) {
    struct client *c = &s->clients[idx];

    while (ps_outbuf_pending(&c->q) > 0) {
        ssize_t n = send(c->fd, ps_outbuf_head(&c->q), ps_outbuf_pending(&c->q), MSG_NOSIGNAL);

        if (n > 0) {
            ps_outbuf_consume(&c->q, (size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        close_client(s, idx);
        return 0;
    }
    return ps_outbuf_pending(&c->q) > 0;
}

static void update_epoll_out(struct server *s, int idx, int want) {
    struct client *c = &s->clients[idx];
    struct epoll_event ev;

    if (c->want_write == want) {
        return;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLRDHUP;
    if (want) {
        ev.events |= EPOLLOUT;
    }
    ev.data.u32 = (uint32_t)idx;
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, c->fd, &ev) == 0) {
        c->want_write = want;
    }
}

static void accept_clients(struct server *s) {
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        int fd = accept4(s->listen_fd, (struct sockaddr *)&ss, &sl, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            if (errno == EINTR) {
                continue;
            }
            LOG_WARN("accept: %s", strerror(errno));
            return;
        }

        int idx = -1;
        for (int i = 0; i < s->max_clients; i++) {
            if (s->clients[i].fd < 0) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            const char *msg = "server busy: no free client slot\n";
            uint8_t frame[256];
            size_t n = ps_frame_write(frame, sizeof(frame), PS_FRAME_ERR, (const uint8_t *)msg,
                                      (uint32_t)strlen(msg));
            if (n) {
                (void)!send(fd, frame, n, MSG_NOSIGNAL | MSG_DONTWAIT);
            }
            close(fd);
            LOG_WARN("rejected client: all %d slots busy", s->max_clients);
            continue;
        }

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &(int){1 << 20}, sizeof(int));

        struct client *c = &s->clients[idx];
        memset(c, 0, sizeof(*c));
        c->fd = fd;
        ps_outbuf_init(&c->q, s->client_buffer);

        char host[INET6_ADDRSTRLEN] = "?";
        uint16_t port = 0;
        if (ss.ss_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)&ss;
            inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
            port = ntohs(sin->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&ss;
            inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
            port = ntohs(sin6->sin6_port);
        }
        snprintf(c->peer, sizeof(c->peer), "%s:%u", host, port);

        /* Greet immediately so the client knows the link type and snap length
         * before the first packet arrives (needed for .pcap export). */
        uint8_t hello_payload[512];
        size_t hlen = ps_hello_encode(&s->hello, hello_payload, sizeof(hello_payload));
        uint8_t frame[600];
        size_t flen = ps_frame_write(frame, sizeof(frame), PS_FRAME_HELLO, hello_payload,
                                     (uint32_t)hlen);
        if (flen) {
            ps_outbuf_push(&c->q, frame, flen);
        }

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLOUT;
        ev.data.u32 = (uint32_t)idx;
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) != 0) {
            LOG_WARN("epoll_ctl add: %s", strerror(errno));
            close(fd);
            ps_outbuf_free(&c->q);
            c->fd = -1;
            continue;
        }
        c->want_write = 1;
        s->nclients++;
        LOG_INFO("client %s connected (%d/%d)", c->peer, s->nclients, s->max_clients);
    }
}

static void broadcast(struct server *s, const uint8_t *frame, size_t len) {
    if (s->nclients == 0) {
        return;
    }
    for (int i = 0; i < s->max_clients; i++) {
        struct client *c = &s->clients[i];

        if (c->fd < 0) {
            continue;
        }
        if (ps_outbuf_push(&c->q, frame, len) != 0) {
            s->counters.dropped_client++;
            continue;
        }
        if (flush_client(s, i) && c->fd >= 0) {
            update_epoll_out(s, i, 1);
        }
    }
}

static void handle_packet(struct server *s, struct ps_record *rec) {
    s->counters.seen++;
    s->counters.captured++;
    s->counters.bytes += rec->origlen;

    /* Cheap classification for the status line; full dissection is the
     * client's job. */
    struct ps_decoded d;
    if (ps_decode(rec->data, rec->caplen, rec->origlen, s->cap.linktype, &d) == 0) {
        switch (d.l4) {
        case PS_L4_TCP:
            s->counters.tcp++;
            break;
        case PS_L4_UDP:
            s->counters.udp++;
            break;
        case PS_L4_ICMP:
        case PS_L4_ICMPV6:
            s->counters.icmp++;
            break;
        default:
            if (d.ethertype == 0x0806) {
                s->counters.arp++;
            } else {
                s->counters.other++;
            }
            break;
        }
        if (d.ip_version == 6) {
            s->counters.ipv6++;
        }
        if (d.app_flags & PS_APP_DNS) {
            s->counters.dns++;
        }
        if (d.app_flags & PS_APP_TLS) {
            s->counters.tls++;
        }
    } else {
        s->counters.other++;
    }

    if (s->have_pcap) {
        if (ps_pcap_write(&s->pcap, rec) != 0) {
            LOG_WARN("pcap write failed: %s", strerror(errno));
        }
    }

    if (s->nclients == 0) {
        return;
    }

    /* Build the PACKET frame straight into a reusable buffer. */
    size_t need = PS_HEADER_LEN + PS_PKT_HDR_LEN + rec->caplen;
    if (need > s->frame_buf_cap) {
        s->frame_buf = ps_xrealloc(s->frame_buf, need);
        s->frame_buf_cap = need;
    }
    uint32_t plen = (uint32_t)ps_packet_encode(s->frame_buf + PS_HEADER_LEN,
                                               s->frame_buf_cap - PS_HEADER_LEN, rec);
    if (plen == 0) {
        return;
    }
    size_t total = ps_frame_write(s->frame_buf, s->frame_buf_cap, PS_FRAME_PACKET,
                                  s->frame_buf + PS_HEADER_LEN, plen);
    if (total) {
        broadcast(s, s->frame_buf, total);
    }
}

static void send_stats(struct server *s) {
    uint8_t payload[PS_COUNTER_WIRE_SIZE];
    uint8_t frame[PS_HEADER_LEN + PS_COUNTER_WIRE_SIZE];

    ps_capture_update_drops(&s->cap);
    s->counters.dropped_kernel = s->cap.drops_total;
    if (s->counters.dropped_kernel != s->last_kernel_drops) {
        LOG_DEBUG("kernel drops: +%llu",
                  (unsigned long long)(s->counters.dropped_kernel - s->last_kernel_drops));
        s->last_kernel_drops = s->counters.dropped_kernel;
    }

    size_t plen = ps_counters_encode(&s->counters, payload, sizeof(payload));
    size_t flen = ps_frame_write(frame, sizeof(frame), PS_FRAME_STATS, payload, (uint32_t)plen);
    if (flen) {
        broadcast(s, frame, flen);
    }

    if (!s->quiet) {
        char bytes[24];
        char line[512];

        ps_fmt_bytes(bytes, sizeof(bytes), s->counters.bytes);
        snprintf(line, sizeof(line),
                 "seen=%llu tcp=%llu udp=%llu icmp=%llu other=%llu bytes=%s clients=%d drops=%llu",
                 (unsigned long long)s->counters.seen, (unsigned long long)s->counters.tcp,
                 (unsigned long long)s->counters.udp, (unsigned long long)s->counters.icmp,
                 (unsigned long long)s->counters.other, bytes, s->nclients,
                 (unsigned long long)s->counters.dropped_kernel);
        LOG_INFO("%s", line);
    }
}

static int resolve_bind(const char *addr, uint16_t port, struct sockaddr_storage *ss,
                        socklen_t *slen) {
    memset(ss, 0, sizeof(*ss));
    if (!addr || !*addr) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ss;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(INADDR_ANY);
        sin->sin_port = htons(port);
        *slen = sizeof(*sin);
        return 0;
    }

    struct sockaddr_in *sin = (struct sockaddr_in *)ss;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &sin->sin_addr) == 1) {
        *slen = sizeof(*sin);
        return 0;
    }

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
    memset(sin6, 0, sizeof(*sin6));
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    if (inet_pton(AF_INET6, addr, &sin6->sin6_addr) == 1) {
        *slen = sizeof(*sin6);
        return 0;
    }
    return -1;
}

int ps_server_run(const struct ps_server_opts *opts) {
    struct server s;
    char err[256];
    int rc = 1;

    memset(&s, 0, sizeof(s));
    s.max_clients = opts->max_clients > 0 ? opts->max_clients : 8;
    s.client_buffer = opts->client_buffer ? opts->client_buffer : (4u << 20);
    s.stats_interval = opts->stats_interval ? opts->stats_interval : 5;
    s.quiet = opts->quiet;
    ps_counters_clear(&s.counters);

    enum ps_direction dir = PS_DIR_BOTH;
    if (opts->direction == PS_SERVER_DIR_IN) {
        dir = PS_DIR_IN;
    } else if (opts->direction == PS_SERVER_DIR_OUT) {
        dir = PS_DIR_OUT;
    }

    /* The stream itself runs over TCP on the same box and would be captured,
     * which turns a quiet link into a feedback loop. Exclude it by default. */
    char filter[320];

    filter[0] = '\0';
    if (!opts->capture_control) {
        if (opts->bpf && *opts->bpf) {
            snprintf(filter, sizeof(filter), "(%s) and not tcp port %u", opts->bpf,
                     (unsigned)opts->port);
        } else {
            snprintf(filter, sizeof(filter), "not tcp port %u", (unsigned)opts->port);
        }
    } else if (opts->bpf && *opts->bpf) {
        ps_strlcpy(filter, opts->bpf, sizeof(filter));
    }
    const char *bpf = filter[0] ? filter : NULL;

    if (ps_capture_open(&s.cap, opts->iface, opts->snaplen, opts->promisc, dir, bpf, err,
                        sizeof(err)) != 0) {
        LOG_ERROR("%s", err);
        return 1;
    }

    memset(&s.hello, 0, sizeof(s.hello));
    s.hello.linktype = s.cap.linktype;
    s.hello.snaplen = s.cap.snaplen;
    gethostname(s.hello.hostname, sizeof(s.hello.hostname) - 1);
    ps_strlcpy(s.hello.iface, s.cap.iface, sizeof(s.hello.iface));
    if (bpf) {
        ps_strlcpy(s.hello.filter, bpf, sizeof(s.hello.filter));
    }

    if (opts->pcap_path && *opts->pcap_path) {
        if (ps_pcap_open(&s.pcap, opts->pcap_path, s.cap.snaplen, s.cap.linktype,
                         opts->pcap_rotate_bytes, err, sizeof(err)) != 0) {
            LOG_ERROR("%s", err);
            ps_capture_close(&s.cap);
            return 1;
        }
        s.have_pcap = 1;
    }

    struct sockaddr_storage bind_ss;
    socklen_t bind_len;
    if (resolve_bind(opts->bind_addr, opts->port, &bind_ss, &bind_len) != 0) {
        LOG_ERROR("invalid bind address '%s'", opts->bind_addr);
        goto done;
    }

    s.listen_fd = socket(bind_ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s.listen_fd < 0) {
        LOG_ERROR("listen socket: %s", strerror(errno));
        goto done;
    }
    int one = 1;
    setsockopt(s.listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(s.listen_fd, (struct sockaddr *)&bind_ss, bind_len) != 0) {
        LOG_ERROR("bind port %u: %s", (unsigned)opts->port, strerror(errno));
        goto done;
    }
    if (listen(s.listen_fd, 16) != 0) {
        LOG_ERROR("listen: %s", strerror(errno));
        goto done;
    }

    s.clients = ps_xmalloc(sizeof(struct client) * (size_t)s.max_clients);
    for (int i = 0; i < s.max_clients; i++) {
        memset(&s.clients[i], 0, sizeof(struct client));
        s.clients[i].fd = -1;
    }

    s.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (s.epoll_fd < 0) {
        LOG_ERROR("epoll_create1: %s", strerror(errno));
        goto done;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.u32 = UINT32_MAX; /* listen socket marker */
    if (epoll_ctl(s.epoll_fd, EPOLL_CTL_ADD, s.listen_fd, &ev) != 0) {
        LOG_ERROR("epoll_ctl listen: %s", strerror(errno));
        goto done;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.u32 = UINT32_MAX - 1; /* capture socket marker */
    if (epoll_ctl(s.epoll_fd, EPOLL_CTL_ADD, s.cap.fd, &ev) != 0) {
        LOG_ERROR("epoll_ctl capture: %s", strerror(errno));
        goto done;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    LOG_INFO("%s %s capturing on %s (snap %u, promisc %s, filter \"%s\")",
             PS_NAME, PS_VERSION_STR, s.cap.iface, s.cap.snaplen,
             s.cap.promisc ? "on" : "off", s.hello.filter[0] ? s.hello.filter : "none");
    LOG_INFO("streaming on port %u (max %d clients)", (unsigned)opts->port, s.max_clients);
    if (s.have_pcap) {
        LOG_INFO("recording to %s", opts->pcap_path);
    }

    struct epoll_event events[MAX_EVENTS];
    time_t next_stats = time(NULL) + (time_t)s.stats_interval;
    uint8_t *pkt_buf = ps_xmalloc(PS_SNAPLEN_MAX);
    rc = 0;

    while (!g_stop) {
        int n = epoll_wait(s.epoll_fd, events, MAX_EVENTS, 500);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("epoll_wait: %s", strerror(errno));
            rc = 1;
            break;
        }

        for (int i = 0; i < n; i++) {
            uint32_t id = events[i].data.u32;

            if (id == UINT32_MAX) {
                accept_clients(&s);
            } else if (id == UINT32_MAX - 1) {
                int budget = EPOLL_BATCH;
                while (budget-- > 0) {
                    struct ps_record rec;
                    int outgoing = 0;
                    int got = ps_capture_read(&s.cap, pkt_buf, PS_SNAPLEN_MAX, &rec, &outgoing);
                    if (got <= 0) {
                        break;
                    }
                    if (outgoing && opts->direction == PS_SERVER_DIR_IN) {
                        continue;
                    }
                    if (!outgoing && opts->direction == PS_SERVER_DIR_OUT) {
                        continue;
                    }
                    handle_packet(&s, &rec);
                }
            } else if (id < (uint32_t)s.max_clients) {
                struct client *c = &s.clients[id];

                if (c->fd < 0) {
                    continue;
                }
                if (events[i].events & EPOLLERR) {
                    close_client(&s, (int)id);
                    continue;
                }
                if (events[i].events & EPOLLOUT) {
                    int still = flush_client(&s, (int)id);
                    if (c->fd >= 0) {
                        update_epoll_out(&s, (int)id, still);
                    }
                }
                if (events[i].events & EPOLLIN) {
                    char scratch[256];
                    ssize_t r = recv(c->fd, scratch, sizeof(scratch), MSG_DONTWAIT);
                    if (r == 0) {
                        close_client(&s, (int)id);
                    }
                }
            }
        }

        time_t now = time(NULL);
        if (now >= next_stats) {
            send_stats(&s);
            next_stats = now + (time_t)s.stats_interval;
        }
    }

    LOG_INFO("shutting down");
    {
        uint8_t frame[PS_HEADER_LEN];
        size_t n = ps_frame_write(frame, sizeof(frame), PS_FRAME_BYE, NULL, 0);

        for (int i = 0; i < s.max_clients; i++) {
            if (s.clients[i].fd >= 0) {
                if (n) {
                    (void)send(s.clients[i].fd, frame, n, MSG_NOSIGNAL | MSG_DONTWAIT);
                }
                epoll_ctl(s.epoll_fd, EPOLL_CTL_DEL, s.clients[i].fd, NULL);
                close(s.clients[i].fd);
                s.clients[i].fd = -1;
                ps_outbuf_free(&s.clients[i].q);
            }
        }
    }
    ps_capture_update_drops(&s.cap);
    free(pkt_buf);

    {
        char bytes[24];
        ps_fmt_bytes(bytes, sizeof(bytes), s.counters.bytes);
        LOG_INFO("captured %llu frames (%s), kernel drops %llu",
                 (unsigned long long)s.counters.captured, bytes,
                 (unsigned long long)s.cap.drops_total);
    }

done:
    if (s.have_pcap) {
        ps_pcap_close(&s.pcap);
    }
    if (s.clients) {
        for (int i = 0; i < s.max_clients; i++) {
            if (s.clients[i].fd >= 0) {
                close(s.clients[i].fd);
                ps_outbuf_free(&s.clients[i].q);
            }
        }
    }
    if (s.epoll_fd > 0) {
        close(s.epoll_fd);
    }
    if (s.listen_fd > 0) {
        close(s.listen_fd);
    }
    free(s.clients);
    free(s.frame_buf);
    ps_capture_close(&s.cap);
    return rc;
}
