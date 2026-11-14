# pktsniff

Capture packets on a server, watch them live on your laptop, and keep a
`.pcap` you can open in Wireshark.

A real packet sniffer, not a demo: raw `AF_PACKET` capture with kernel BPF
filters, a framed binary wire protocol, a bounds-checked dissector, per-client
back pressure that never desynchronises the stream, and `.pcap` output on both
ends.

```
$ sudo pktsniff-server -i eth0 -f 'tcp port 443 or udp port 53' -w /var/cap/eth0.pcap
06:51:00 [inf] pktsniff 2.0.0 capturing on eth0 (snap 262144, promisc on, filter "(tcp port 443 or udp port 53) and not tcp port 8888")
06:51:00 [inf] streaming on port 8888 (max 8 clients)
06:51:00 [inf] recording to /var/cap/eth0.pcap
06:51:05 [inf] seen=48211 tcp=41992 udp=6123 icmp=6 other=90 bytes=58.4 MB clients=1 drops=0
```

```
$ pktsniff-client 203.0.113.10 -F 'proto:tls or proto:dns'
Connected to box.example (iface eth0, linktype 1, snap 262144, filter "…")
06:51:07.112321 #000001 TCP   10.0.0.5:53112 -> 1.1.1.1:443      74 B ttl=64 SYN seq=…  | TLS SNI=cloudflare.com
06:51:07.112947 #000002 DNS   10.0.0.5:40233 -> 1.1.1.1:53     71 B ttl=64 | DNS A example.com
06:51:07.113402 #000003 TCP   1.1.1.1:443 -> 10.0.0.5:53112  1460 B ttl=57 ACK,PSH | TLS handshake
```

## Why it is useful

- **It outputs things you can act on.** `.pcap` on both sides, newline-delimited
  JSON for `jq`, one-line-per-packet text for `grep`.
- **It never sends you garbage.** The stream is length-prefixed binary frames.
  A slow reader gets whole frames dropped, never a half frame, so the client
  can't fall out of sync.
- **It filters twice.** Real tcpdump syntax in the kernel (`--filter`, needs
  libpcap) and a cheap structured filter in the client (`-F`).
- **It explains what it sees.** DNS query names, TLS SNI, HTTP request lines,
  TCP flags, ARP who-has, VLAN tags, IPv4/IPv6, ICMP.

## Build

```bash
make                 # bin/pktsniff-server, bin/pktsniff-client
make test            # unit tests, no root needed
sudo tests/e2e.sh    # live tests on loopback (needs root + python3 + tcpdump)
```

Requirements: a C11 compiler and Linux headers. `libpcap-dev` is optional and
only enables server-side `--filter` (`make print-config` says whether it is on).

## Install

```bash
sudo apt install build-essential libpcap-dev   # Debian/Ubuntu
make && sudo make install                      # -> /usr/local/bin
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/pktsniff-server
```

With those capabilities the server runs without full root. There is also a
systemd unit in `packaging/pktsniff.service`.

## Server

```
pktsniff-server [options]

  -i, --iface NAME          interface to capture on (default: any)
  -f, --filter BPF          kernel filter in tcpdump syntax (needs libpcap)
  -s, --snaplen N           bytes kept per packet (default 262144)
      --no-promisc          do not enable promiscuous mode
      --direction in|out|both   drop our own sent / received traffic
      --capture-control     also capture the stream's own TCP connection
  -p, --port N              TCP port to listen on (default 8888)
  -b, --bind ADDR           bind address (default 0.0.0.0)
  -m, --max-clients N       concurrent clients (default 8)
      --client-buffer BYTES per-client queue before dropping (default 4 MiB)
  -w, --pcap FILE           also record to a .pcap file
      --pcap-rotate-mb N    rotate the file every N MiB
  -t, --stats-interval N    seconds between status lines (default 5)
  -v, --verbose             debug logging
  -q, --quiet               no periodic status lines
      --list-interfaces     list interfaces and exit
```

The server excludes its own control connection from the capture by default
(`not tcp port <port>`); without that, capturing `lo` turns the stream into a
feedback loop. Use `--capture-control` if you really want it.

## Client

```
pktsniff-client [host] [options]

  -H, --host HOST           server address (default 127.0.0.1)
  -p, --port N              server port (default 8888)
      --reconnect           retry forever instead of exiting on disconnect

  -F, --filter EXPR         display filter, see below
  -c, --count N             stop after N matching packets
  -d, --duration N          stop after N seconds

  -x, --hex N               hexdump the first N bytes of each match
  -X, --no-hex              no hexdump
      --json FILE           newline-delimited JSON ('-' = stdout)
      --no-stats            hide the periodic counter line
      --stats-interval N    seconds between counter lines (default 5)
  -C, --color / --no-color  force or disable ANSI colour (default: tty only)
  -q, --quiet               no banner or summary
  -w, --pcap FILE           write matching packets to a .pcap
      --pcap-rotate-mb N    rotate the file every N MiB
```

### Display filters

Groups are joined by `or` (`|` also works); terms inside a group are AND'ed;
`!` negates a term.

```
proto:tcp proto:udp proto:icmp proto:icmp6 proto:arp proto:ip6
proto:dns proto:tls proto:http
port:443   sport:53   dport:53
host:10.0.0.1   host:10.0.0.0/8   src:…   dst:…
contains:GET   bytes:>500
```

Shorthand for single terms: `tcp`, `udp`, `icmp`, `arp`, `dns`, `tls`, `http`,
`443` (port), `10.0.0.1` (host).

```bash
pktsniff-client 203.0.113.10 -F 'proto:tls or proto:dns'
pktsniff-client 203.0.113.10 -F 'host:10.0.0.0/8 !tcp'
pktsniff-client 203.0.113.10 -F 'bytes:>1400' -x 32
pktsniff-client 203.0.113.10 --json - | jq -r '.app' | sort | uniq -c | sort -rn | head
```

### Recipes

```bash
# Watch DNS from a busy server without drowning the terminal
sudo pktsniff-server -i eth0 -f 'udp port 53' &
pktsniff-client -F 'proto:dns' -d 30

# Export just the HTTP traffic to a shareable capture
pktsniff-client 203.0.113.10 -F 'proto:http or port:443' -w subset.pcap -d 60

# Rotate 100 MiB recordings for a day
sudo pktsniff-server -i eth0 -w /var/cap/eth0.pcap --pcap-rotate-mb 100

# Which hosts is this box talking TLS to?
pktsniff-client 203.0.113.10 --json - | jq -r 'select(.app|startswith("TLS SNI"))|.app'
```

## How it fits together

```
  ┌─────────────┐   AF_PACKET/BFF   ┌──────────────┐   framed TCP    ┌──────────────┐
  │    NIC      │ ────────────────► │ pktsniff-    │ ──────────────► │ pktsniff-    │
  └─────────────┘                   │ server       │  HELLO/PACKET   │ client       │
                                    │  capture →   │  /STATS/BYE     │  decode →    │
                                    │  queue/clt   │                 │  filter →    │
                                    │  write pcap  │                 │  render/pcap │
                                    └──────────────┘                 └──────────────┘
```

The server deliberately understands almost nothing about packets: it hands the
client raw link-layer frames plus a timestamp, so the client can do the
interesting work (and write a valid `.pcap`). Details:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Repo layout

```
include/        headers, one per module
src/            server, client, capture, dissector, protocol, queue, pcap, util
tests/          unit tests (make test) + live e2e (sudo tests/e2e.sh)
docs/           protocol, architecture, setup and usage notes
scripts/        build / setup helpers
packaging/      systemd unit
```

## Limits worth knowing

- Linux only (raw `AF_PACKET` sockets). No capture on macOS/BSD yet.
- Plaintext stream, no authentication: bind to a private address, tunnel it, or
  firewall the port.
- One capture socket, one thread. ~700 MB/s of loopback traffic was fine in
  testing, but for multi-gigabit links use `-f` to trim in the kernel, and
  expect kernel drops (reported in the counter line) rather than silently
  losing data.
- TCP reassembly, stream following and deep protocol parsing stop at "identify
  the interesting bit" (SNI, DNS question, HTTP request line).

## Legal

Capture only traffic you own or have permission to monitor. Provided for
educational and testing purposes; see `LICENSE`.
