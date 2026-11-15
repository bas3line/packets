#!/usr/bin/env bash
# e2e.sh - live end-to-end checks. Needs root (raw sockets), python3, tcpdump.
#
#   sudo tests/e2e.sh
#
# Everything is confined to the loopback interface and port 8899.
set -uo pipefail

cd "$(dirname "$0")/.."
BIN=./bin
PORT=8899
WORK=$(mktemp -d)
FAIL=0
SRV_PID=""
CLI_PID=""

cleanup() {
    [ -n "$CLI_PID" ] && kill "$CLI_PID" 2>/dev/null
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    pkill -f pktsniff-server 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

ok() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad() {
    printf '  \033[31mFAIL\033[0m %s\n' "$1"
    [ -n "${2:-}" ] && sed 's/^/         /' "$2" | tail -5
    FAIL=$((FAIL + 1))
}
note() { printf '\n\033[1m%s\033[0m\n' "$1"; }

expect() { # expect <description> <file-with-output-to-blame> <command...>
    local desc=$1 log=$2
    shift 2
    if "$@"; then ok "$desc"; else bad "$desc" "$log"; fi
}

start_server() { # start_server <logfile> [extra args...]
    local log=$1
    shift
    $BIN/pktsniff-server -i lo -p "$PORT" -q "$@" >"$log" 2>&1 &
    SRV_PID=$!
    sleep 0.7
}

stop_server() {
    [ -n "$SRV_PID" ] || return 0
    kill -TERM "$SRV_PID" 2>/dev/null
    wait "$SRV_PID" 2>/dev/null
    SRV_PID=""
}

traffic() { # background UDP noise
    python3 - <<'PY' &
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end = time.time() + 5
while time.time() < end:
    for _ in range(50):
        s.sendto(b'x' * 200, ('127.0.0.1', 5399))
    time.sleep(0.001)
PY
    TRAFFIC_PID=$!
}

json_ok() { # json_ok <file> [proto]
    python3 - "$1" "${2:-}" <<'PY'
import json, sys
lines = [json.loads(l) for l in open(sys.argv[1])]
assert lines, "no lines"
if len(sys.argv) > 2 and sys.argv[2]:
    assert all(l["proto"] == sys.argv[2] for l in lines), lines[0]
PY
}

[ "$(id -u)" -eq 0 ] || {
    echo "must run as root"
    exit 1
}

note "build"
if make -s -j4 >/dev/null 2>&1; then ok "make"; else bad "make"; fi

HAVE_PCAP=0
if $BIN/pktsniff-server --version 2>/dev/null | grep -q 'libpcap filtering: yes'; then
    HAVE_PCAP=1
fi
echo "  libpcap: $([ "$HAVE_PCAP" -eq 1 ] && echo yes || echo "no (kernel filters skipped)")"

note "basic streaming"
start_server "$WORK/srv1.log"
$BIN/pktsniff-client 127.0.0.1 -p $PORT -d 4 -F 'proto:udp' -w "$WORK/cli1.pcap" \
    >"$WORK/cli1.out" 2>"$WORK/cli1.err" &
CLI_PID=$!
sleep 0.4
ping -c 3 -i 0.1 127.0.0.1 >/dev/null 2>&1
traffic
wait "$CLI_PID"
CLI_PID=""
wait "$TRAFFIC_PID" 2>/dev/null

expect "client received matching packets" "$WORK/cli1.out" \
    test "$(wc -l <"$WORK/cli1.out")" -gt 3
expect "client never desynchronised" "$WORK/cli1.err" \
    bash -c '! grep -q "protocol error" "$1"' _ "$WORK/cli1.err"
expect "client wrote a readable pcap" "$WORK/cli1.err" \
    tcpdump -r "$WORK/cli1.pcap" -nn -c 1 -q
expect "no ANSI colour when stdout is a pipe" "$WORK/cli1.out" \
    bash -c '! grep -q $'"'"'\033'"'"' "$1"' _ "$WORK/cli1.out"
expect "server logged the client" "$WORK/srv1.log" \
    grep -q 'client 127.0.0.1' "$WORK/srv1.log"
stop_server

note "server-side BPF filter and recording"
if [ "$HAVE_PCAP" -eq 1 ]; then
    start_server "$WORK/srv2.log" -f 'icmp' -w "$WORK/srv2.pcap"
else
    start_server "$WORK/srv2.log" -w "$WORK/srv2.pcap"
fi
ping -c 3 -i 0.1 127.0.0.1 >/dev/null 2>&1
sleep 0.3
stop_server
if [ "$HAVE_PCAP" -eq 1 ]; then
    expect "filter compiled" "$WORK/srv2.log" \
        bash -c '! grep -q "bad filter" "$1"' _ "$WORK/srv2.log"
    expect "pcap holds ICMP only" "$WORK/srv2.log" bash -c '
        out=$(tcpdump -r "$1" -nn 2>/dev/null)
        grep -q ICMP <<<"$out" && ! grep -q UDP <<<"$out"' _ "$WORK/srv2.pcap"
fi
expect "server-side pcap holds our pings" "$WORK/srv2.log" \
    tcpdump -r "$WORK/srv2.pcap" -nn -q -c 1
expect "SIGTERM shut the server down cleanly" "$WORK/srv2.log" \
    grep -q 'shutting down' "$WORK/srv2.log"

note "slow consumer survives drops"
start_server "$WORK/srv3.log" --client-buffer 65536
$BIN/pktsniff-client 127.0.0.1 -p $PORT -d 4 -F 'proto:udp' -X >"$WORK/cli3.out" 2>"$WORK/cli3.err" &
CLI_PID=$!
sleep 0.4
traffic
wait "$CLI_PID"
CLI_PID=""
wait "$TRAFFIC_PID" 2>/dev/null
expect "no desync with a 64 KiB client buffer" "$WORK/cli3.err" \
    bash -c '! grep -q "protocol error" "$1"' _ "$WORK/cli3.err"
expect "frames still arrived" "$WORK/cli3.out" test -s "$WORK/cli3.out"
stop_server

note "json output and --count"
start_server "$WORK/srv4.log"
traffic
$BIN/pktsniff-client 127.0.0.1 -p $PORT -c 5 -d 8 -F 'proto:udp' --json "$WORK/out.json" -q \
    >/dev/null 2>"$WORK/cli4.err"
wait "$TRAFFIC_PID" 2>/dev/null
expect "exited after --count with output" "$WORK/cli4.err" test -s "$WORK/out.json"
expect "every line is valid json" "$WORK/cli4.err" json_ok "$WORK/out.json"
expect "--count stopped at exactly 5" "$WORK/cli4.err" \
    test "$(wc -l <"$WORK/out.json")" -eq 5
expect "json records carry the udp application view" "$WORK/cli4.err" \
    json_ok "$WORK/out.json" UDP
stop_server

note "direction filtering"
start_server "$WORK/srv7.log" --direction in
$BIN/pktsniff-client 127.0.0.1 -p $PORT -d 2 -q -F 'proto:udp' >"$WORK/in.out" 2>"$WORK/in.err" &
CLI_PID=$!
traffic
sleep 2
wait "$CLI_PID" 2>/dev/null
CLI_PID=""
wait "$TRAFFIC_PID" 2>/dev/null
expect "--direction in runs and stays synchronised" "$WORK/in.err" \
    bash -c '! grep -q "protocol error" "$1"' _ "$WORK/in.err"
stop_server

note "concurrency and limits"
start_server "$WORK/srv5.log" -m 2
$BIN/pktsniff-client 127.0.0.1 -p $PORT -d 2 -F 'icmp' >/dev/null 2>&1 &
A=$!
$BIN/pktsniff-client 127.0.0.1 -p $PORT -d 2 -F 'icmp' >/dev/null 2>&1 &
B=$!
sleep 0.5
$BIN/pktsniff-client 127.0.0.1 -p $PORT -d 1 -q >/dev/null 2>"$WORK/cli5.err"
wait $A $B 2>/dev/null
expect "third client rejected with a message" "$WORK/cli5.err" \
    grep -q 'no free client slot' "$WORK/cli5.err"
expect "server kept both slots" "$WORK/srv5.log" \
    test "$(grep -c 'client 127.0.0.1' "$WORK/srv5.log")" -ge 2
stop_server

note "argument handling"
if [ "$HAVE_PCAP" -eq 1 ]; then
    $BIN/pktsniff-server -i lo -p $PORT -f 'bogus filter here' >"$WORK/srv6.log" 2>&1
    expect "bad BPF rejected at startup" "$WORK/srv6.log" \
        grep -q 'bad filter' "$WORK/srv6.log"
fi
$BIN/pktsniff-client --bad-option >/dev/null 2>&1
expect "client bad option exits 2" "" test $? -eq 2
$BIN/pktsniff-client -F 'proto:nope' -c 1 127.0.0.1 >/dev/null 2>&1
expect "unknown proto in filter is rejected" "" test $? -eq 2
$BIN/pktsniff-server --list-interfaces >"$WORK/ifaces.txt" 2>&1
expect "--list-interfaces works" "$WORK/ifaces.txt" grep -q 'lo' "$WORK/ifaces.txt"

printf '\n'
if [ "$FAIL" -eq 0 ]; then
    printf '\033[32mall e2e checks passed\033[0m\n'
    exit 0
fi
printf '\033[31m%d e2e check(s) failed\033[0m\n' "$FAIL"
exit 1
