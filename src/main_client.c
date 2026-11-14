/* main_client.c - pktsniff-client: receive, filter, render, record. */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client.h"
#include "log.h"
#include "util.h"

enum {
    OPT_NO_STATS = 1000,
    OPT_NO_COLOR,
    OPT_JSON,
    OPT_RECONNECT,
    OPT_STATS_INTERVAL,
    OPT_PCAP_ROTATE,
};

static const struct option long_opts[] = {
    {"host", required_argument, NULL, 'H'},
    {"port", required_argument, NULL, 'p'},
    {"filter", required_argument, NULL, 'F'},
    {"pcap", required_argument, NULL, 'w'},
    {"pcap-rotate-mb", required_argument, NULL, OPT_PCAP_ROTATE},
    {"json", required_argument, NULL, OPT_JSON},
    {"count", required_argument, NULL, 'c'},
    {"duration", required_argument, NULL, 'd'},
    {"hex", required_argument, NULL, 'x'},
    {"no-hex", no_argument, NULL, 'X'},
    {"no-stats", no_argument, NULL, OPT_NO_STATS},
    {"stats-interval", required_argument, NULL, OPT_STATS_INTERVAL},
    {"color", no_argument, NULL, 'C'},
    {"no-color", no_argument, NULL, OPT_NO_COLOR},
    {"quiet", no_argument, NULL, 'q'},
    {"reconnect", no_argument, NULL, OPT_RECONNECT},
    {"verbose", no_argument, NULL, 'v'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {NULL, 0, NULL, 0},
};

static void usage(FILE *out) {
    fprintf(out,
            "usage: " PS_NAME "-client [host] [options]\n"
            "\n"
            "Receive the live packet stream from a " PS_NAME "-server and make sense of it.\n"
            "\n"
            "Connection:\n"
            "  -H, --host HOST        server address (default 127.0.0.1)\n"
            "  -p, --port N           server port (default 8888)\n"
            "      --reconnect        retry forever instead of exiting on disconnect\n"
            "\n"
            "Selection:\n"
            "  -F, --filter EXPR      display filter, e.g. 'proto:tcp port:443 !src:10.0.0.5'\n"
            "                         keys: proto port sport dport host src dst contains bytes\n"
            "                         'or'/'|' between alternatives, '!' negates a term\n"
            "                         shorthand: tcp udp icmp arp dns tls http 443 10.0.0.0/8\n"
            "  -c, --count N          stop after N matching packets\n"
            "  -d, --duration N       stop after N seconds\n"
            "\n"
            "Output:\n"
            "  -x, --hex N            hexdump the first N bytes of each match (default 0)\n"
            "  -X, --no-hex           same as --hex 0\n"
            "      --json FILE        write newline-delimited JSON to FILE ('-' = stdout)\n"
            "      --no-stats         hide the periodic server counter line\n"
            "      --stats-interval N seconds between counter lines (default 5)\n"
            "  -C, --color            force ANSI colour (default: only on a tty)\n"
            "      --no-color         disable ANSI colour\n"
            "  -q, --quiet            no banner or summary (keeps stdout pipeable)\n"
            "  -v, --verbose          debug logging\n"
            "\n"
            "Recording:\n"
            "  -w, --pcap FILE        write matching packets to a .pcap for Wireshark\n"
            "      --pcap-rotate-mb N rotate the file every N MiB\n"
            "\n"
            "  -h, --help             this help\n"
            "  -V, --version          version\n"
            "\n"
            "Examples:\n"
            "  " PS_NAME "-client 203.0.113.10 -F 'proto:dns or proto:tls' --hex 64\n"
            "  " PS_NAME "-client 203.0.113.10 -F 'host:10.0.0.0/8 !tcp' -w subset.pcap\n"
            "  " PS_NAME "-client 203.0.113.10 --json - | jq '.app' | sort | uniq -c\n");
}

int main(int argc, char **argv) {
    struct ps_client_opts opts;
    int verbose = 0;
    int c;

    ps_set_prog_name(PS_NAME "-client");
    memset(&opts, 0, sizeof(opts));
    opts.host = "127.0.0.1";
    opts.port = 8888;
    opts.show_stats = 1;
    opts.color = -1;
    opts.stats_interval = 5;

    while ((c = getopt_long(argc, argv, "H:p:F:w:c:d:x:XqvhVC", long_opts, NULL)) != -1) {
        switch (c) {
        case 'H':
            opts.host = optarg;
            break;
        case 'p': {
            uint32_t v;
            if (ps_parse_u32(optarg, &v) != 0 || v == 0 || v > 65535) {
                LOG_ERROR("bad port '%s'", optarg);
                return 2;
            }
            opts.port = (uint16_t)v;
            break;
        }
        case 'F':
            opts.filter = optarg;
            break;
        case 'w':
            opts.pcap_path = optarg;
            break;
        case OPT_PCAP_ROTATE: {
            uint32_t mb;
            if (ps_parse_u32(optarg, &mb) != 0 || mb == 0) {
                LOG_ERROR("bad --pcap-rotate-mb '%s'", optarg);
                return 2;
            }
            opts.pcap_rotate_bytes = (uint64_t)mb * 1024 * 1024;
            break;
        }
        case OPT_JSON:
            opts.json_path = optarg;
            break;
        case 'c':
            if (ps_parse_u64(optarg, &opts.count) != 0 || opts.count == 0) {
                LOG_ERROR("bad --count '%s'", optarg);
                return 2;
            }
            break;
        case 'd': {
            uint32_t v;
            if (ps_parse_u32(optarg, &v) != 0 || v == 0) {
                LOG_ERROR("bad --duration '%s'", optarg);
                return 2;
            }
            opts.duration = v;
            break;
        }
        case 'x': {
            uint32_t v;
            if (ps_parse_u32(optarg, &v) != 0) {
                LOG_ERROR("bad --hex '%s'", optarg);
                return 2;
            }
            opts.hex_bytes = v;
            break;
        }
        case 'X':
            opts.hex_bytes = 0;
            break;
        case OPT_NO_STATS:
            opts.show_stats = 0;
            break;
        case OPT_STATS_INTERVAL:
            if (ps_parse_u32(optarg, &opts.stats_interval) != 0 || opts.stats_interval == 0) {
                LOG_ERROR("bad --stats-interval '%s'", optarg);
                return 2;
            }
            break;
        case 'C':
            opts.color = 1;
            break;
        case OPT_NO_COLOR:
            opts.color = 0;
            break;
        case OPT_RECONNECT:
            opts.reconnect = 1;
            break;
        case 'q':
            opts.quiet = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage(stdout);
            return 0;
        case 'V':
            printf("%s %s\n", PS_NAME, PS_VERSION_STR);
            return 0;
        default:
            usage(stderr);
            return 2;
        }
    }

    /* A single bare argument is the host: `pktsniff-client 1.2.3.4`. */
    if (optind < argc) {
        opts.host = argv[optind++];
    }
    if (optind < argc) {
        LOG_ERROR("unexpected argument '%s'", argv[optind]);
        return 2;
    }

    ps_log_init(verbose ? PS_LOG_DEBUG : PS_LOG_INFO, opts.color);

    return ps_client_run(&opts);
}
