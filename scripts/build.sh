#!/usr/bin/env bash
# Thin wrapper around make so `./scripts/build.sh` keeps working.
set -euo pipefail
cd "$(dirname "$0")/.."
make "$@"
echo
echo "built:"
ls -1 bin/pktsniff-server bin/pktsniff-client 2>/dev/null || true
echo
echo "server: sudo ./bin/pktsniff-server --help"
echo "client: ./bin/pktsniff-client --help"
