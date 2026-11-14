#!/usr/bin/env bash
# Install build deps, build, install and open the firewall port.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=${PORT:-8888}
PREFIX=${PREFIX:-/usr/local}

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root (needed for apt, install and the firewall)" >&2
    exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y build-essential libpcap-dev
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc make libpcap-devel
fi

make -j"$(nproc)"
make install PREFIX="$PREFIX"

SERVER="$PREFIX/bin/pktsniff-server"
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=eip "$SERVER" && \
        echo "granted CAP_NET_RAW/CAP_NET_ADMIN to $SERVER (no root needed)"
fi

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q active; then
    ufw allow "$PORT"/tcp && echo "ufw: allowed $PORT/tcp"
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$PORT/tcp" && firewall-cmd --reload
fi

cat <<MSG

done. start capturing with:

  sudo $SERVER -i any -p $PORT

then connect from your workstation:

  ./bin/pktsniff-client <this-server-ip> -p $PORT

MSG
