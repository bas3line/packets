# Architecture

Two small programs, one shared library of modules.

```
include/            src/
  common.h            endian helpers, link types, limits
  log.h               log.c        leveled logging to stderr
  util.h              util.c       allocation, string, number helpers
  proto.h             proto.c      framing, codecs, incremental reader
  decode.h            decode.c     bounds-checked dissection + rendering
  filter.h            filter.c     client-side display filter
  pcap.h              pcap.c       classic .pcap writer
  outbuf.h            outbuf.c     frame-atomic send queue
  stats.h             stats.c      counters + wire (de)serialisation
  capture.h           capture.c    AF_PACKET capture, BPF, timestamps  (server)
  server.h            server.c     epoll loop, client fan-out          (server)
  client.h            client.c     connect, decode, filter, render     (client)
                      main_server.c / main_client.c   argument parsing
```

Rules of the road:

- `decode.c` never trusts a length. Every field is bounds-checked, and every
  truncation of the input is handled (`tests/test_decode.c` cuts a valid frame
  at every possible offset).
- Modules below `server.c`/`client.c` know nothing about sockets or threads.
  `outbuf`, `proto` and `decode` are unit-testable in isolation, and they are.
- The wire format and the counters struct are defined once and validated at
  compile time, so they cannot drift.

## Server pipeline

```
epoll_wait
  ├─ listen fd  → accept4, greet with HELLO, register EPOLLOUT
  ├─ capture fd → ps_capture_read (recvmsg, SCM_TIMESTAMPNS)
  │                 → ps_decode (cheap classification for counters)
  │                 → ps_pcap_write (if recording)
  │                 → ps_packet_encode into a reusable staging buffer
  │                 → broadcast: ps_outbuf_push + opportunistic send per client
  └─ client fd  → flush queue; EPOLLERR → drop client
every --stats-interval → STATS frame + one summary log line
```

Design points:

- **The capture loop never blocks.** Capture socket, listen socket and client
  sockets are all non-blocking and multiplexed in one epoll loop, so no single
  slow reader stalls capture. Up to `EPOLL_BATCH` frames are drained per wakeup
  to amortise `epoll_wait`.
- **Kernel receive timestamps** (`SO_TIMESTAMPNS`) are used when present, so the
  timestamp reflects when the driver saw the packet, not when userspace got it.
  Timestamps survive the trip and end up in the `.pcap`, which is why a
  client-side capture is still useful evidence.
- **Kernel-space filtering.** `--filter` is compiled by libpcap
  (`pcap_open_dead` + `pcap_compile`) and attached with `SO_ATTACH_FILTER`, so
  the kernel discards uninteresting traffic before it costs us anything. If the
  build has no libpcap, the server fails fast at startup with a clear message
  instead of silently ignoring the filter.
- **The control connection is excluded** from capture by default. Streaming a
  capture over TCP while capturing TCP is a feedback loop; the default filter
  becomes `(user filter) and not tcp port <port>`.
- **Kernel drops are reported.** `PACKET_STATISTICS` is read-and-clear, so the
  counter is accumulated and surfaced as `dropped_kernel`.
- **`AF_PACKET` on "any"** captures on all interfaces at once (with
  `linktype = Ethernet`), which is what you want on a router or a busy box.

## Deliveries: `outbuf`

The interesting part of the server is per-client back pressure. `ps_outbuf` is
a byte ring with an explicit frame-boundary cursor:

```
data: [ sent ][ partially sent frame ][ queued frames ... ]
       ^      ^                        ^                 ^
       0      r                        frame_start       w
```

- `r` is the send cursor; anything before it is already on the wire.
- `frame_start` is the oldest frame that still owes bytes.
- On overflow, only frames at or after `r` may be dropped: dropping a partially
  sent frame would leave the peer mid-frame, which is exactly how the naive
  version of this tool desynchronised clients under load.

`tests/test_outbuf.c` drives this with a fake sink that accepts 0–40 bytes per
call and a producer that outruns it, then re-parses the delivered byte stream to
prove every frame arrives whole and in order.

## Client pipeline

```
poll(socket, 500 ms)
  → recv → ps_reader_feed → ps_reader_next (whole frames only)
      ├─ HELLO → remember linktype/snaplen, open the .pcap lazily
      ├─ PACKET → ps_decode → ps_filter_match → render | json → pcap
      ├─ STATS → counters for the periodic line
      └─ BYE/ERR → stop
```

- Output modes are mutually exclusive per stream: coloured text to stdout, or
  NDJSON to a file/stdout. `--quiet` removes the banner so stdout stays pipeable.
- Colour is auto-detected from `isatty(stdout)`; `-C` forces it, `--no-color`
  disables it. Status and warnings always go to stderr.
- `--reconnect` re-enters the connect path with capped exponential backoff and
  resets the reader, so a server restart is survivable.
- `--count` is exact: once N matching packets have been emitted the loop stops
  even if more frames are already buffered.

## Dissection

`ps_decode` fills `struct ps_decoded` from `(data, caplen, linktype)`:

- Link: Ethernet II, 802.1Q / QinQ / 0x9100 VLAN stacks, Linux SLL v1/v2, BSD
  loopback (`DLT_NULL`/`DLT_LOOP`), bare IP (`DLT_RAW`).
- Network: IPv4 (incl. options, fragmentation), IPv6 (hop-by-hop, routing,
  destination options, fragment headers), ARP.
- Transport: TCP (flags, seq/ack, window, MSS option), UDP, ICMP, ICMPv6.
- Application: DNS question names and types, TLS ClientHello SNI, HTTP request
  lines. Cheap heuristics, no stream reassembly — enough to answer "who is this
  box talking to and how".

Everything is bounded by `caplen`: the dissector can be handed any truncation of
any packet without reading out of bounds.

## Testing

| what | how |
| --- | --- |
| framing, reader, codecs | `tests/test_proto.c` (byte-at-a-time feed, garbage rejection) |
| dissection | `tests/test_decode.c` (built frames, every truncation offset, VLAN, ARP, v6, DNS, TLS SNI) |
| filter grammar | `tests/test_filter.c` (AND/OR/negation, CIDR, errors) |
| queue under pressure | `tests/test_outbuf.c` (partial writes, drops, stream re-parse) |
| end to end | `tests/e2e.sh` (root: capture, filter, pcap readability, drops, json, limits, signals) |

`make asan` rebuilds and reruns the unit tests with ASan + UBSan.
