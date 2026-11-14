/* main_server.c - pktsniff-server: capture on this box, stream to clients. */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "capture.h"
#include "log.h"
#include "server.h"
#include "util.h"

enum {
    OPT_NO_PROMISC = 1000,
    OPT_DIRECTION,
    OPT_CLIENT_BUFFER,
    OPT_PCAP_ROTATE,
    OPT_LIST_IFACES,
    OPT_CAPTURE_CONTROL,
};

static const struct option long_opts[] = {
    {"iface", required_argument, NULL, 'i'},
    {"filter", required_argument, NULL, 'f'},
    {"snaplen", required_argument, NULL, 's'},
    {"no-promisc", no_argument, NULL, OPT_NO_PROMISC},
    {"direction", required_argument, NULL, OPT_DIRECTION},
    {"port", required_argument, NULL, 'p'},
    {"bind", required_argument, NULL, 'b'},
    {"max-clients", required_argument, NULL, 'm'},
    {"client-buffer", required_argument, NULL, OPT_CLIENT_BUFFER},
    {"pcap", required_argument, NULL, 'w'},
    {"pcap-rotate-mb", required_argument, NULL, OPT_PCAP_ROTATE},
    {"stats-interval", required_argument, NULL, 't'},
    {"verbose", no_argument, NULL, 'v'},
    {"quiet", no_argument, NULL, 'q'},
    {"capture-control", no_argument, NULL, OPT_CAPTURE_CONTROL},
    {"list-interfaces", no_argument, NULL, OPT_LIST_IFACES},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {NULL, 0, NULL, 0},
};

static void usage(FILE *out) {
    fprintf(out,
            "usage: " PS_NAME "-server [options]\n"
            "\n"
            "Capture packets on this machine and stream them to " PS_NAME " clients.\n"
            "Requires root (CAP_NET_RAW) for the raw socket.\n"
            "\n"
            "Capture:\n"
            "  -i, --iface NAME          interface to capture on (default: any)\n"
            "  -f, --filter BPF          kernel filter in tcpdump syntax (needs libpcap)\n"
            "  -s, --snaplen N           bytes kept per packet (default %u)\n"
            "      --no-promisc          do not enable promiscuous mode\n"
            "      --direction in|out|both   drop our own sent / received traffic\n"
            "      --capture-control     also capture the stream's own TCP connection\n"
            "\n"
            "Streaming:\n"
            "  -p, --port N              TCP port to listen on (default 8888)\n"
            "  -b, --bind ADDR           bind address (default 0.0.0.0)\n"
            "  -m, --max-clients N       concurrent clients (default 8)\n"
            "      --client-buffer BYTES per-client queue before dropping (default 4 MiB)\n"
            "\n"
            "Recording:\n"
            "  -w, --pcap FILE           also record to a .pcap file\n"
            "      --pcap-rotate-mb N    rotate the file every N MiB\n"
            "\n"
            "Other:\n"
            "  -t, --stats-interval N    seconds between status lines (default 5)\n"
            "  -v, --verbose             debug logging\n"
            "  -q, --quiet               no periodic status lines\n"
            "      --list-interfaces     list interfaces and exit\n"
            "  -h, --help                this help\n"
            "  -V, --version             version and capabilities\n"
            "\n"
            "Examples:\n"
            "  sudo " PS_NAME "-server -i eth0 -f 'tcp port 443' -w cap.pcap\n"
            "  sudo " PS_NAME "-server -i any -f 'udp port 53' -p 9000\n",
            PS_SNAPLEN_DEFAULT);
}

int main(int argc, char **argv) {
    struct ps_server_opts opts;
    int verbose = 0;
    int c;

    ps_set_prog_name(PS_NAME "-server");
    memset(&opts, 0, sizeof(opts));
    opts.iface = "";
    opts.port = 8888;
    opts.snaplen = PS_SNAPLEN_DEFAULT;
    opts.promisc = 1;
    opts.max_clients = 8;
    opts.client_buffer = 4u << 20;
    opts.stats_interval = 5;
    opts.direction = PS_SERVER_DIR_BOTH;

    while ((c = getopt_long(argc, argv, "i:f:s:p:b:m:w:t:vqhV", long_opts, NULL)) != -1) {
        switch (c) {
        case 'i':
            opts.iface = optarg;
            break;
        case 'f':
            opts.bpf = optarg;
            break;
        case 's':
            if (ps_parse_u32(optarg, &opts.snaplen) != 0 || opts.snaplen < 64 ||
                opts.snaplen > PS_SNAPLEN_MAX) {
                LOG_ERROR("bad snaplen '%s' (64..%u)", optarg, PS_SNAPLEN_MAX);
                return 2;
            }
            break;
        case OPT_NO_PROMISC:
            opts.promisc = 0;
            break;
        case OPT_DIRECTION:
            if (!strcmp(optarg, "in")) {
                opts.direction = PS_SERVER_DIR_IN;
            } else if (!strcmp(optarg, "out")) {
                opts.direction = PS_SERVER_DIR_OUT;
            } else if (!strcmp(optarg, "both")) {
                opts.direction = PS_SERVER_DIR_BOTH;
            } else {
                LOG_ERROR("bad --direction '%s' (in|out|both)", optarg);
                return 2;
            }
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
        case 'b':
            opts.bind_addr = optarg;
            break;
        case 'm': {
            uint32_t v;
            if (ps_parse_u32(optarg, &v) != 0 || v < 1 || v > 512) {
                LOG_ERROR("bad --max-clients '%s' (1..512)", optarg);
                return 2;
            }
            opts.max_clients = (int)v;
            break;
        }
        case OPT_CLIENT_BUFFER: {
            uint32_t v;
            if (ps_parse_u32(optarg, &v) != 0 || v < 65536) {
                LOG_ERROR("bad --client-buffer '%s' (min 65536)", optarg);
                return 2;
            }
            opts.client_buffer = v;
            break;
        }
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
        case 't':
            if (ps_parse_u32(optarg, &opts.stats_interval) != 0 || opts.stats_interval == 0) {
                LOG_ERROR("bad --stats-interval '%s'", optarg);
                return 2;
            }
            break;
        case 'v':
            verbose = 1;
            break;
        case 'q':
            opts.quiet = 1;
            break;
        case OPT_CAPTURE_CONTROL:
            opts.capture_control = 1;
            break;
        case OPT_LIST_IFACES:
            printf("interfaces:\n");
            ps_capture_list_interfaces(stdout);
            return 0;
        case 'h':
            usage(stdout);
            return 0;
        case 'V':
            printf("%s %s\n", PS_NAME, PS_VERSION_STR);
#ifdef PS_HAVE_PCAP
            printf("libpcap filtering: yes\n");
#else
            printf("libpcap filtering: no (server-side --filter disabled)\n");
#endif
            return 0;
        default:
            usage(stderr);
            return 2;
        }
    }
    if (optind < argc) {
        LOG_ERROR("unexpected argument '%s'", argv[optind]);
        return 2;
    }

    ps_log_init(verbose ? PS_LOG_DEBUG : PS_LOG_INFO, 1);

    if (geteuid() != 0) {
        LOG_WARN("not running as root: opening the raw socket will probably fail");
    }

    return ps_server_run(&opts);
}
