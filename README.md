<div align="center">

<a href="https://ascii.rest/banner/pktsniff.svg?color=34d399,60a5fa&tagline=packets%20live%20from%20any%20server">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://ascii.rest/banner/pktsniff.dark.svg?color=34d399,60a5fa&tagline=packets%20live%20from%20any%20server">
    <img alt="pktsniff: packets live from any server" src="https://ascii.rest/banner/pktsniff.svg?color=34d399,60a5fa&tagline=packets%20live%20from%20any%20server">
  </picture>
</a>

<br>
<br>

Capture packets on a server, watch them on your laptop, keep the `.pcap`.<br>
Raw sockets, kernel BPF filters, and a stream that never sends you half a frame.

[install](#install) · [run it](#run-it) · [server](#server) · [client](#client) · [filters](#display-filters) · [recipes](#recipes) · [how it's built](#how-its-built) · [contributing](CONTRIBUTING.md)

[![by @bas3line](https://img.shields.io/badge/by-%40bas3line-181717?logo=github&logoColor=white)](https://github.com/bas3line)
[![CI](https://github.com/bas3line/packets/actions/workflows/ci.yml/badge.svg)](https://github.com/bas3line/packets/actions/workflows/ci.yml)
[![MIT](https://img.shields.io/badge/license-MIT-181717)](LICENSE)
[![C11](https://img.shields.io/badge/C-11-181717?logo=c&logoColor=white)](Makefile)
[![Linux](https://img.shields.io/badge/Linux-AF__PACKET-181717?logo=linux&logoColor=white)](src/capture.c)
[![libpcap](https://img.shields.io/badge/libpcap-optional-181717)](Makefile)

</div>

<br>

Written in C by [@bas3line](https://github.com/bas3line). Two programs: one captures on the machine you can't sit in front of, the other sits in front of you. The server hands out raw link-layer frames with their kernel timestamps over a length-prefixed binary stream; the client decodes them, filters them, prints them, and can write them straight into a `.pcap` that Wireshark opens. Nothing is lost in translation, and nothing gets lost when your laptop reads slower than the wire.

```
$ sudo pktsniff-server -i eth0 -f 'tcp port 443 or udp port 53' -w /var/cap/eth0.pcap
11:02:14 [inf] pktsniff 2.0.0 capturing on eth0 (snap 262144, promisc on, filter "(tcp port 443 or udp port 53) and not tcp port 8888")
11:02:14 [inf] streaming on port 8888 (max 8 clients)
11:02:14 [inf] recording to /var/cap/eth0.pcap
11:02:19 [inf] seen=48211 tcp=41992 udp=6123 icmp=6 other=90 bytes=58.4 MB clients=1 drops=0

$ pktsniff-client 203.0.113.10 -F 'proto:tls or proto:dns'
11:02:21.112321 #000001 TCP   10.0.0.5:53112 -> 1.1.1.1:443      74 B ttl=64 SYN | TLS SNI=cloudflare.com
11:02:21.112947 #000002 DNS   10.0.0.5:40233 -> 1.1.1.1:53     71 B ttl=64 | DNS A example.com
11:02:21.113402 #000003 TCP   1.1.1.1:443 -> 10.0.0.5:53112  1460 B ttl=57 ACK,PSH | TLS handshake
```

## Why

Every "remote sniffer" I'd used printed packet lines to a terminal and threw them away. The lines you actually wanted were the ones scrolled past, the hexdump was truncated into unreadable mush, and there was no way to hand a colleague the traffic afterwards. So: real capture, real filters, and a format that survives the trip. The stream is framed, so a slow reader loses whole packets and never the alignment; the output is either a text line you can grep, JSON you can pipe into `jq`, or a `.pcap` you can open in Wireshark. The server stays deliberately stupid — it captures, timestamps, and forwards bytes — because the interesting decisions belong where a person is looking.

## Install

```sh
git clone https://github.com/bas3line/packets
cd packets
make -j"$(nproc)"
sudo make install                    # /usr/local/bin/pktsniff-{server,client}
```

A C11 compiler and Linux headers. `libpcap-dev` is optional and only enables the server's `--filter`; `make print-config` tells you whether it was found. To run the server without full root:

```sh
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/pktsniff-server
```

## Run it

```sh
# on the box
sudo pktsniff-server -i eth0

# on your machine
pktsniff-client 203.0.113.10
```

Open TCP 8888 (or `-p` whatever you like) between them. Only that port; the client needs no privileges and no libpcap.

| script | |
| --- | --- |
| `make` | build both binaries into `bin/` |
| `make test` | unit tests: framing, dissection, filters, the send queue |
| `sudo tests/e2e.sh` | live checks on loopback: capture, drops, `.pcap`, JSON, limits |
| `make asan` | rebuild and rerun the unit tests under ASan + UBSan |
| `make install` | install to `$(PREFIX)/bin` |
| `sudo make install-service` | install the systemd unit in `packaging/` |

## Server

```sh
sudo pktsniff-server -i eth0 -f 'tcp port 443' -w cap.pcap --pcap-rotate-mb 100
```

| flag | |
| --- | --- |
| `-i, --iface NAME` | interface to capture on, default `any` (all of them at once) |
| `-f, --filter BPF` | kernel filter in tcpdump syntax; compiled by libpcap and attached with `SO_ATTACH_FILTER` |
| `-s, --snaplen N` | bytes kept per packet, default 262144 |
| `--no-promisc` | leave the interface out of promiscuous mode |
| `--direction in\|out\|both` | drop traffic this host sent, received, or neither |
| `--capture-control` | also capture the stream's own TCP connection |
| `-p, --port N` | TCP port to serve on, default 8888 |
| `-b, --bind ADDR` | bind address, default `0.0.0.0` |
| `-m, --max-clients N` | concurrent clients, default 8 |
| `--client-buffer BYTES` | queue per slow client before dropping, default 4 MiB |
| `-w, --pcap FILE` | record to a `.pcap` as well |
| `--pcap-rotate-mb N` | start a new file every N MiB |
| `-t, --stats-interval N` | seconds between status lines, default 5 |
| `-q, -v` | no status lines, or debug logging |

The server excludes its own control connection from the capture (`not tcp port <port>`) unless you ask for `--capture-control`: capturing `lo` while streaming over it is otherwise a loop that feeds itself.

## Client

```sh
pktsniff-client 203.0.113.10 -F 'proto:dns' -d 30 -x 64
```

| flag | |
| --- | --- |
| `[host]`, `-H, --host` | server address, default `127.0.0.1` |
| `-p, --port N` | server port, default 8888 |
| `-F, --filter EXPR` | display filter, see [filters](#display-filters) |
| `-c, --count N` | stop after exactly N matching packets |
| `-d, --duration N` | stop after N seconds |
| `-x, --hex N` | hexdump the first N bytes of each match |
| `--json FILE` | newline-delimited JSON, `-` for stdout |
| `-w, --pcap FILE` | write matching packets to a `.pcap` |
| `--pcap-rotate-mb N` | rotate that file every N MiB |
| `--stats-interval N`, `--no-stats` | the counter line, every 5 s by default |
| `-C, --color`, `--no-color` | force or disable colour (default: only on a tty) |
| `--reconnect` | survive a server restart instead of exiting |
| `-q, -v` | no banner or summary, or debug logging |

## Display filters

Terms are AND'ed, groups are joined with `or` (or `|`), and `!` negates a term. Single terms have shorthands.

```
proto:tcp   proto:udp   proto:icmp   proto:icmp6   proto:arp   proto:ip6
proto:dns   proto:tls   proto:http
port:443    sport:53    dport:53
host:10.0.0.1    host:10.0.0.0/8    src:…    dst:…
contains:GET     bytes:>1400
```

```sh
pktsniff-client 203.0.113.10 -F 'proto:tls or proto:dns'
pktsniff-client 203.0.113.10 -F 'host:10.0.0.0/8 !tcp'
pktsniff-client 203.0.113.10 -F 'bytes:>1400' -x 32
```

`-F` is a display filter and runs on your machine. `--filter` on the server is tcpdump syntax and runs in the kernel. Different tools, different grammar, and the second one is the one that saves bandwidth.

## Recipes

```sh
# Watch DNS on a busy box without drowning the terminal
sudo pktsniff-server -i eth0 -f 'udp port 53' &
pktsniff-client -F 'proto:dns' -d 30

# Export the HTTP traffic from the last minute as a shareable capture
pktsniff-client 203.0.113.10 -F 'proto:http or port:443' -w subset.pcap -d 60

# A day of rotating recordings on the server, nothing sent to anyone
sudo pktsniff-server -i eth0 -w /var/cap/eth0.pcap --pcap-rotate-mb 100

# Which hosts is this box talking TLS to?
pktsniff-client 203.0.113.10 --json - | jq -r 'select(.app|startswith("TLS SNI"))|.app'

# Everything on one port, as JSON, to a file, with no privileges at all
pktsniff-client 203.0.113.10 -F 'port:5432' --json pg.ndjson -d 120
```

## What it can see

Ethernet II, 802.1Q and QinQ VLAN stacks, Linux cooked capture, BSD loopback, bare IP; ARP, IPv4 with options and fragmentation, IPv6 with extension headers; TCP with flags, sequence numbers, window and MSS, UDP, ICMP and ICMPv6; and enough application awareness to answer "who is this talking to": DNS question names and record types, TLS ClientHello SNI, HTTP request lines.

No stream reassembly and no full protocol zoo — just the part that tells you what is going on.

## How it's built

```
  ┌────────┐  AF_PACKET   ┌─────────────────┐  framed TCP     ┌─────────────────┐
  │  NIC   │ ───────────► │ pktsniff-server │ ──────────────► │ pktsniff-client │
  └────────┘  kernel BPF  │ capture → queue │ HELLO PACKET    │ decode → filter │
                          │ → pcap on disk  │ STATS BYE ERR   │ → render / pcap │
                          └─────────────────┘                 └─────────────────┘
```

- **The stream is frames, not lines.** 12-byte header with magic, version, type and length, then the payload. The client buffers until a frame is whole, so a packet split across TCP segments cannot break it. Layout in [docs/PROTOCOL.md](docs/PROTOCOL.md).
- **Back pressure never desynchronises.** Each client has a bounded queue of whole frames. When it fills, only frames with no bytes on the wire yet are dropped — dropping a partly-sent frame is exactly how a client ends up reading garbage. That queue has its own test suite.
- **Kernel timestamps, kernel filters.** `SO_TIMESTAMPNS` for arrival times, `SO_ATTACH_FILTER` for libpcap-compiled BPF, `PACKET_STATISTICS` for the drop count you can see in the status line.
- **One epoll loop, nothing blocks.** Capture socket, listen socket and every client share it, so one slow reader cannot stall the capture.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the module map and the reasoning, [docs/SETUP.md](docs/SETUP.md) for firewall, capabilities, systemd and troubleshooting.

## Repo layout

| path | |
| --- | --- |
| `include/`, `src/` | one header per module: capture, dissector, protocol, queue, pcap, filter, stats |
| `tests/` | `test_*.c` unit suites and `e2e.sh`, the live one |
| `docs/` | protocol, architecture, setup |
| `scripts/` | build and server/client setup helpers |
| `packaging/` | systemd unit |

## Limits worth knowing

Linux only — it is `AF_PACKET` all the way down. The stream is plaintext and unauthenticated, so bind it to a private address, tunnel it or firewall the port. One capture socket and one thread: multiple gigabits need `-f` to trim in the kernel, and kernel drops are reported rather than hidden.

## Legal

Capture only traffic you own or have permission to monitor. Educational and testing use; see [LICENSE](LICENSE).
