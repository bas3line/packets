# pktsniff wire protocol (version 1)

One TCP connection, one direction of application data (server → client). The
server never reads anything but EOF; the client never writes. Everything is
big-endian and length-prefixed.

## Frame

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------+---------------+
|            magic (u32)        | version (u16) |  magic = 0x50534E46 "PSNF"
+-------------------------------+---------------+
|  type (u16)   |            length (u32)       |
+---------------+-------------------------------+
|                  payload[length]              |
+-----------------------------------------------+
```

12-byte header, then exactly `length` payload bytes. A frame is never split
across messages: the receiver must buffer until `length` bytes are available
(`ps_reader_*` in `src/proto.c` does this). Maximum payload accepted is 2 MiB;
anything larger is treated as stream corruption.

| type | name   | payload                                    |
|------|--------|--------------------------------------------|
| 1    | HELLO  | `ps_hello_encode`                          |
| 2    | PACKET | `ps_pkt_hdr` + link-layer bytes            |
| 3    | STATS  | 14 × u64 counters                          |
| 4    | BYE    | empty                                      |
| 5    | ERR    | NUL-terminated UTF-8 message                |

## HELLO (type 1)

Sent once, immediately after accept, before any PACKET frame.

```
u16 linktype      DLT value (1 = Ethernet, 113 = Linux SLL, …)
u32 snaplen       capture snapshot length
    hostname      NUL-terminated, server's name
    iface         NUL-terminated, interface or "any"
    filter        NUL-terminated, effective kernel BPF filter ("" if none)
```

The client uses `linktype` and `snaplen` to write a `.pcap` that matches the
capture exactly. A HELLO whose strings are not terminated is rejected.

## PACKET (type 2)

```
u32 ts_sec        capture timestamp, seconds since the epoch
u32 ts_usec       microseconds
u32 caplen        bytes of link-layer data present
u32 origlen       original wire length
u8  data[caplen]  raw frame, exactly as delivered by AF_PACKET
```

`data` is untouched link-layer bytes so it can be written straight into a
`.pcap` record. The server does not decode beyond a rough protocol counter.

## STATS (type 3)

Fourteen `u64` values, in this order (the order is defined once, by
`PS_COUNTER_FIELDS` in `include/stats.h`, and a `_Static_assert` in
`src/stats.c` keeps it in step with the struct):

```
seen captured bytes tcp udp icmp arp dns tls ipv6 fragmented other
dropped_kernel dropped_client
```

Sent every `--stats-interval` seconds and only when a client is connected.

## ERR / BYE (types 5 / 4)

`ERR` carries a human-readable NUL-terminated string (for example
`server busy: no free client slot` when `--max-clients` is exhausted) and ends
the session. `BYE` has an empty payload and means the server shut down cleanly.

## Delivery guarantees

The server queues whole frames per client in a bounded buffer
(`--client-buffer`, default 4 MiB).

- If the queue is full, only **wholly unsent** frames are discarded.
- A frame that has partly been written to the socket is never dropped, because
  the peer would then be left mid-frame.
- Drops are counted in `dropped_client` (and in the server's log line), so a
  client can always tell how much it missed from `seen - captured`.

Consequences: the byte stream is always a valid sequence of frames, and the
message shapes above are exactly what arrives. A client that reads slowly sees
gaps in its packet sequence, never a broken frame.

## Not in v1

- Client → server control channel (per-client filters, pause/resume).
- Compression, encryption or authentication.
- Multiple capture interfaces in one stream.
