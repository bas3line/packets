# Contributing

Small C11 project, no dependencies worth arguing about. `make test` and, if you can, `sudo tests/e2e.sh` are the whole gate.

## Get set up

```sh
git clone https://github.com/bas3line/packets
cd packets
sudo apt install build-essential libpcap-dev python3 tcpdump iputils-ping
make && make test
```

The end-to-end suite needs root (it opens a raw socket) and confines itself to loopback on port 8899:

```sh
sudo tests/e2e.sh
```

## What runs in CI

`.github/workflows/ci.yml` builds the tree with and without libpcap, at `-O2` and under ASan/UBSan, runs the unit tests in every combination, and runs `tests/e2e.sh` for the `-O2` build. A change that only works when libpcap is installed will fail there.

## Ground rules

- **Never trust a length.** Anything that reads a packet, a frame or a config string is handed hostile input in `tests/`. `ps_decode` must survive being given the first *n* bytes of any packet, for every *n* — that is what `test_every_truncation` checks, and it is the cheapest bug you will ever find.
- **The stream stays frame-atomic.** If you touch `src/outbuf.c`, keep the invariant: a frame with bytes on the wire is never dropped. `tests/test_outbuf.c` simulates short writes and a stuck reader; make it pass.
- **Server does little, client does the thinking.** Capture, timestamp, forward, optionally record. Dissection, filtering and rendering belong in the client, where a person is watching.
- **No new dependencies** unless they earn their place. libpcap is optional and stays optional.
- **Match the surrounding C**: `ps_` prefixes, `goto done` for cleanup, one header per module in `include/`, comments that explain *why* something is not obvious.
- Warnings are errors in spirit — the tree builds clean with `-Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wvla -Wpointer-arith` and `-Werror`.

## Adding something

| you want to | touch |
| --- | --- |
| dissect another protocol | `src/decode.c`, add a case in `tests/test_decode.c` with a hand-built frame |
| add a display filter key | `src/filter.c` (parse + match), `tests/test_filter.c`, the table in `README.md` |
| change the wire format | `include/proto.h`, bump `PS_PROTO_VERSION`, update `docs/PROTOCOL.md` |
| add a server or client flag | `src/main_server.c` / `src/main_client.c`, `--help` text, the option table in `README.md` |
| touch capture behaviour | `src/capture.c`; explain the change in the PR, it is the hard part to test |

## Commits and PRs

- Imperative subject, then a body that says what was wrong and what is now true. "Fix", "improve" and "refactor" on their own say nothing.
- One idea per PR. If it needs "and also", it is two PRs.
- Paste the relevant test output in the description — `make test` summary and, for anything involving capture or the stream, the `tests/e2e.sh` result.

## Reporting a bug

Include the server log lines around the failure, `pktsniff-server --version` (it prints whether libpcap is compiled in), and what `--filter`/`-F` you were using. If the client printed `protocol error on stream`, that is a framing bug and I would like the frames you were seeing: `-v` and the head of the server log usually settle it.
