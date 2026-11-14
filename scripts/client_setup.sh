#!/usr/bin/env bash
# Build the client (no privileges or libpcap needed).
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v apt-get >/dev/null 2>&1 && ! command -v cc >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y build-essential
fi

make -j"$(nproc)"

cat <<MSG

client built. connect with:

  ./bin/pktsniff-client <server-ip> [-p PORT] [-F 'proto:tcp port:443']

MSG
