/* client.c - connect, decode, filter, render, record. */
#include "client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "decode.h"
#include "filter.h"
#include "log.h"
#include "pcap.h"
#include "proto.h"
#include "stats.h"
#include "util.h"

#define CLIENT_RECV_CHUNK 65536
#define RECONNECT_MIN_MS 500
#define RECONNECT_MAX_MS 15000

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    PS_UNUSED(sig);
    g_stop = 1;
}

/* ---- ANSI ---- */
#define C_RESET "\033[0m"
#define C_DIM "\033[2m"
#define C_RED "\033[31m"
#define C_GREEN "\033[32m"
#define C_YELLOW "\033[33m"
#define C_BLUE "\033[34m"
#define C_MAGENTA "\033[35m"
#define C_CYAN "\033[36m"
#define C_BOLD "\033[1m"

static const char *proto_color(const struct ps_decoded *d, int color) {
    if (!color) {
        return "";
    }
    if (d->ethertype == 0x0806) {
        return C_MAGENTA;
    }
    switch (d->l4) {
    case PS_L4_TCP:
        return C_GREEN;
    case PS_L4_UDP:
        return C_BLUE;
    case PS_L4_ICMP:
    case PS_L4_ICMPV6:
        return C_YELLOW;
    default:
        return C_DIM;
    }
}

struct client_state {
    int fd;
    struct ps_reader reader;
    struct ps_filter filter;
    struct ps_pcap pcap;
    int have_pcap;
    uint16_t linktype;
    uint32_t snaplen;
    FILE *json;
    int json_owns_fp;
    uint64_t matched;
    uint64_t received;
    uint64_t ts_base_us; /* offset so client timestamps line up with capture time */
    struct ps_counters server_stats;
    int have_server_stats;
    const struct ps_client_opts *opts;
    int color; /* resolved once from the option and isatty() */
};

static void json_escape(const char *in, char *out, size_t cap) {
    size_t w = 0;

    for (; *in && w + 7 < cap; in++) {
        unsigned char c = (unsigned char)*in;
        switch (c) {
        case '"':
            out[w++] = '\\';
            out[w++] = '"';
            break;
        case '\\':
            out[w++] = '\\';
            out[w++] = '\\';
            break;
        case '\n':
            out[w++] = '\\';
            out[w++] = 'n';
            break;
        case '\r':
            out[w++] = '\\';
            out[w++] = 'r';
            break;
        case '\t':
            out[w++] = '\\';
            out[w++] = 't';
            break;
        default:
            if (c < 0x20) {
                snprintf(out + w, cap - w, "\\u%04x", c);
                w += 6;
            } else {
                out[w++] = (char)c;
            }
            break;
        }
    }
    out[w] = '\0';
}

static void emit_json(struct client_state *st, const struct ps_decoded *d,
                      const struct ps_record *rec) {
    char src[128];
    char dst[128];
    char app[400];
    char flags[64];
    char mac_s[24];
    char mac_d[24];

    json_escape(d->src, src, sizeof(src));
    json_escape(d->dst, dst, sizeof(dst));
    json_escape(d->app[0] ? d->app : d->info, app, sizeof(app));
    ps_tcp_flag_str(d->tcp_flags, flags, sizeof(flags));
    json_escape(d->src_mac, mac_s, sizeof(mac_s));
    json_escape(d->dst_mac, mac_d, sizeof(mac_d));

    fprintf(st->json,
            "{\"ts\":%u.%06u,\"caplen\":%u,\"len\":%u,\"proto\":\"%s\",\"ip_version\":%d,"
            "\"src\":\"%s\",\"dst\":\"%s\",\"sport\":%u,\"dport\":%u,\"ttl\":%u,"
            "\"tcp\":{\"seq\":%u,\"ack\":%u,\"flags\":\"%s\",\"win\":%u},"
            "\"vlan\":%u,\"src_mac\":\"%s\",\"dst_mac\":\"%s\",\"app\":\"%s\"}\n",
            rec->ts_sec, rec->ts_usec, rec->caplen, rec->origlen, ps_proto_label(d),
            d->ip_version, src, dst, d->sport, d->dport, d->ttl, d->seq, d->ack, flags, d->window,
            d->has_vlan ? d->vlan_id : 0, mac_s, mac_d, app);
    fflush(st->json);
}

static void print_line(struct client_state *st, const struct ps_decoded *d,
                       const struct ps_record *rec) {
    const struct ps_client_opts *o = st->opts;
    struct tm tm;
    char clock[16];
    char line[512];
    char hex[4096];
    time_t secs = (time_t)rec->ts_sec;

    localtime_r(&secs, &tm);
    snprintf(clock, sizeof(clock), "%02d:%02d:%02d.%06u", tm.tm_hour, tm.tm_min, tm.tm_sec,
             rec->ts_usec);

    ps_decoded_format_line(d, line, sizeof(line));

    if (st->color) {
        printf("%s%s" C_RESET " " C_DIM "#%06llu" C_RESET " %s%s" C_RESET "\n", C_DIM, clock,
               (unsigned long long)st->matched, proto_color(d, 1), line);
    } else {
        printf("%s #%06llu %s\n", clock, (unsigned long long)st->matched, line);
    }

    if (o->hex_bytes > 0 && rec->caplen > 0) {
        ps_hexdump(rec->data, rec->caplen, o->hex_bytes, hex, sizeof(hex));
        printf("%s\n", hex);
    }
}

static void print_stats_line(struct client_state *st, const struct ps_counters *c) {
    char line[512];

    ps_counters_format(c, line, sizeof(line));
    if (st->color) {
        fprintf(stderr, C_DIM "%s" C_RESET "\n", line);
    } else {
        fprintf(stderr, "%s\n", line);
    }
    fflush(stderr);
}

static void handle_packet(struct client_state *st, const struct ps_record *rec) {
    struct ps_decoded d;

    st->received++;
    if (ps_decode(rec->data, rec->caplen, rec->origlen, st->linktype, &d) != 0) {
        if (ps_log_enabled(PS_LOG_DEBUG)) {
            LOG_DEBUG("undecodable frame (%u bytes)", rec->caplen);
        }
        return;
    }
    if (!ps_filter_match(&st->filter, &d)) {
        return;
    }
    st->matched++;

    if (st->json) {
        emit_json(st, &d, rec);
    } else {
        print_line(st, &d, rec);
    }
    if (st->have_pcap && ps_pcap_write(&st->pcap, rec) != 0) {
        LOG_WARN("pcap write failed: %s", strerror(errno));
    }
}

static void handle_frame(struct client_state *st, const struct ps_frame *f) {
    switch (f->type) {
    case PS_FRAME_PACKET: {
        struct ps_record rec;
        if (ps_packet_decode(f->data, f->len, &rec) != 0) {
            LOG_WARN("malformed PACKET frame (%u bytes)", f->len);
            return;
        }
        handle_packet(st, &rec);
        break;
    }
    case PS_FRAME_HELLO: {
        struct ps_hello hello;

        if (ps_hello_decode(f->data, f->len, &hello) != 0) {
            LOG_WARN("malformed HELLO frame");
            return;
        }
        st->linktype = hello.linktype;
        st->snaplen = hello.snaplen;

        if (st->opts->pcap_path && *st->opts->pcap_path && !st->have_pcap) {
            char err[256];
            if (ps_pcap_open(&st->pcap, st->opts->pcap_path, hello.snaplen, hello.linktype,
                             st->opts->pcap_rotate_bytes, err, sizeof(err)) != 0) {
                LOG_ERROR("%s", err);
            } else {
                st->have_pcap = 1;
                LOG_INFO("recording to %s", st->opts->pcap_path);
            }
        }
        if (!st->opts->quiet) {
            LOG_INFO("connected to %s (%s%s%s, linktype %u, snap %u, filter \"%s\")",
                     hello.hostname[0] ? hello.hostname : "server", hello.iface[0] ? "iface " : "",
                     hello.iface, hello.iface[0] ? "" : "default", hello.linktype, hello.snaplen,
                     hello.filter[0] ? hello.filter : "none");
        }
        break;
    }
    case PS_FRAME_STATS: {
        if (ps_counters_decode(f->data, f->len, &st->server_stats) != 0) {
            LOG_WARN("malformed STATS frame");
            return;
        }
        st->have_server_stats = 1;
        break;
    }
    case PS_FRAME_BYE:
        g_stop = 1;
        LOG_INFO("server closed the stream");
        break;
    case PS_FRAME_ERR:
        LOG_ERROR("server: %s", f->len ? (const char *)f->data : "unspecified error");
        g_stop = 1;
        break;
    default:
        LOG_WARN("unknown frame type %u (%u bytes)", f->type, f->len);
        break;
    }
}

static int connect_to(const char *host, uint16_t port, char *err, size_t errsz) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char portstr[8];
    int fd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    int rc = getaddrinfo(host, portstr, &hints, &res);
    if (rc != 0) {
        snprintf(err, errsz, "resolve %s: %s", host, gai_strerror(rc));
        return -1;
    }

    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        snprintf(err, errsz, "connect %s:%u: %s", host, (unsigned)port, strerror(errno));
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    return fd;
}

int ps_client_run(const struct ps_client_opts *opts) {
    struct client_state st;
    char err[256];
    int rc = 0;
    time_t deadline = 0;
    time_t next_stats = 0;
    unsigned backoff = RECONNECT_MIN_MS;

    memset(&st, 0, sizeof(st));
    st.fd = -1;
    st.opts = opts;
    st.color = opts->color < 0 ? isatty(STDOUT_FILENO) : opts->color;
    ps_reader_init(&st.reader, CLIENT_RECV_CHUNK);

    if (ps_filter_parse(opts->filter, &st.filter, err, sizeof(err)) != 0) {
        LOG_ERROR("%s", err);
        rc = 2;
        goto cleanup;
    }

    if (opts->json_path && *opts->json_path) {
        if (strcmp(opts->json_path, "-") == 0) {
            st.json = stdout;
        } else {
            st.json = fopen(opts->json_path, "w");
            if (!st.json) {
                LOG_ERROR("cannot open %s: %s", opts->json_path, strerror(errno));
                rc = 2;
                goto cleanup;
            }
            st.json_owns_fp = 1;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (opts->duration) {
        deadline = time(NULL) + (time_t)opts->duration;
    }
    next_stats = time(NULL) + (time_t)(opts->stats_interval ? opts->stats_interval : 5);

    if (!opts->quiet && !st.json) {
        fprintf(stderr, "%s %s | %s:%u | filter: %s | hex: %zu B\n", PS_NAME, PS_VERSION_STR,
                opts->host, (unsigned)opts->port,
                ps_filter_is_empty(&st.filter) ? "none" : st.filter.source,
                opts->hex_bytes);
    }

    while (!g_stop) {
        if (st.fd < 0) {
            st.fd = connect_to(opts->host, opts->port, err, sizeof(err));
            if (st.fd < 0) {
                LOG_ERROR("%s", err);
                if (!opts->reconnect) {
                    rc = 1;
                    break;
                }
                ps_sleep_ms(backoff);
                backoff = MIN(backoff * 2, RECONNECT_MAX_MS);
                continue;
            }
            backoff = RECONNECT_MIN_MS;
            ps_reader_reset(&st.reader);
        }

        struct pollfd pfd;
        pfd.fd = st.fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int timeout = 500;
        int pr = poll(&pfd, 1, timeout);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("poll: %s", strerror(errno));
            rc = 1;
            break;
        }

        if (pr > 0) {
            if (pfd.revents & (POLLIN | POLLHUP | POLLERR)) {
                uint8_t chunk[CLIENT_RECV_CHUNK];
                ssize_t n = recv(st.fd, chunk, sizeof(chunk), 0);

                if (n > 0) {
                    if (ps_reader_feed(&st.reader, chunk, (size_t)n) != 0) {
                        LOG_ERROR("stream desynchronised, reconnecting");
                        close(st.fd);
                        st.fd = -1;
                        ps_reader_reset(&st.reader);
                        if (!opts->reconnect) {
                            rc = 1;
                            break;
                        }
                        continue;
                    }
                    struct ps_frame frame;
                    int got;
                    while ((got = ps_reader_next(&st.reader, &frame)) == 1) {
                        handle_frame(&st, &frame);
                        if (g_stop || (opts->count && st.matched >= opts->count)) {
                            break;
                        }
                    }
                    if (got < 0) {
                        LOG_ERROR("protocol error on stream after %llu frames, reconnecting",
                                  (unsigned long long)st.received);
                        if (ps_log_enabled(PS_LOG_DEBUG)) {
                            char hex[3 * 32 + 8];
                            size_t hn = MIN(st.reader.len, 24u);
                            for (size_t k = 0; k < hn; k++) {
                                snprintf(hex + k * 3, 4, "%02x ", st.reader.buf[k]);
                            }
                            hex[hn * 3] = 0;
                            LOG_DEBUG("reader len=%zu scratch_cap=%zu head: %s", st.reader.len,
                                      st.reader.frame_cap, hex);
                        }
                        close(st.fd);
                        st.fd = -1;
                        ps_reader_reset(&st.reader);
                        if (!opts->reconnect) {
                            rc = 1;
                            break;
                        }
                        continue;
                    }
                    fflush(stdout);
                } else if (n == 0) {
                    if (opts->reconnect && !g_stop) {
                        LOG_WARN("server closed the connection, reconnecting");
                        close(st.fd);
                        st.fd = -1;
                        ps_reader_reset(&st.reader);
                        ps_sleep_ms(backoff);
                        backoff = MIN(backoff * 2, RECONNECT_MAX_MS);
                        continue;
                    }
                    LOG_INFO("server closed the connection");
                    g_stop = 1;
                    break;
                } else if (errno != EAGAIN && errno != EINTR) {
                    LOG_ERROR("recv: %s", strerror(errno));
                    close(st.fd);
                    st.fd = -1;
                    if (!opts->reconnect) {
                        rc = 1;
                        break;
                    }
                    continue;
                }
            }
        }

        time_t now = time(NULL);
        if (opts->show_stats && now >= next_stats) {
            if (st.have_server_stats) {
                print_stats_line(&st, &st.server_stats);
            }
            next_stats = now + (time_t)(opts->stats_interval ? opts->stats_interval : 5);
        }
        if (deadline && now >= deadline) {
            break;
        }
        if (opts->count && st.matched >= opts->count) {
            break;
        }
    }

    /* Emit any complete frames still sitting in the read buffer, unless the
     * packet count already ended the run. */
    struct ps_frame frame;
    while ((!opts->count || st.matched < opts->count) && !g_stop &&
           ps_reader_next(&st.reader, &frame) == 1) {
        handle_frame(&st, &frame);
    }

    if (!opts->quiet) {
        fprintf(stderr, "matched %llu of %llu received frames\n",
                (unsigned long long)st.matched, (unsigned long long)st.received);
    }

cleanup:
    if (st.fd >= 0) {
        close(st.fd);
    }
    if (st.have_pcap) {
        if (ps_pcap_flush(&st.pcap) != 0) {
            LOG_WARN("pcap flush failed");
        }
        LOG_INFO("wrote %llu packets to pcap", (unsigned long long)st.pcap.packets_written);
        ps_pcap_close(&st.pcap);
    }
    if (st.json_owns_fp && st.json) {
        fclose(st.json);
    }
    ps_reader_free(&st.reader);
    return rc;
}
