# Setup

## Server (Debian / Ubuntu)

```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev git

git clone https://github.com/Bas3line/packets
cd packets
make -j"$(nproc)"
sudo make install                      # /usr/local/bin/pktsniff-{server,client}

# Optional: run without full root
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/pktsniff-server
```

`libpcap-dev` is only needed for server-side `--filter`. Without it,
`make print-config` reports `libpcap = no` and the server rejects `--filter`
with an explanatory error; the client's `-F` still works.

## Client (any Linux)

```bash
sudo apt install -y build-essential git
git clone https://github.com/Bas3line/packets && cd packets
make -j"$(nproc)"          # same tree, you only need bin/pktsniff-client
```

The client needs no privileges and no libpcap.

## Firewall

Only the one TCP port matters (default 8888):

```bash
sudo ufw allow 8888/tcp
# or restrict to your workstation
sudo ufw allow from 203.0.113.7 to any port 8888 proto tcp
sudo iptables -A INPUT -p tcp --dport 8888 -j ACCEPT
```

Remember cloud security groups: inbound TCP 8888 from your IP.

## First run

```bash
# server
sudo pktsniff-server --list-interfaces
sudo pktsniff-server -i eth0

# workstation
pktsniff-client 203.0.113.10 -F 'proto:dns or proto:tls'
```

## As a service

```bash
sudo cp packaging/pktsniff.service /etc/systemd/system/
sudo editor /etc/systemd/system/pktsniff.service   # set --iface / --filter / -w
sudo systemctl daemon-reload && sudo systemctl enable --now pktsniff
journalctl -u pktsniff -f
```

Or `sudo make install-service` after editing `packaging/pktsniff.service`.

## Troubleshooting

**`AF_PACKET socket: Operation not permitted`**
Run as root, or `setcap cap_net_raw,cap_net_admin=eip` on the binary.

**`no such interface 'eth0'`**
Names differ on modern systems (`ens5`, `enp0s3`). Use `--list-interfaces`.

**Client connects but stays silent**
Check the server's counter line — `seen=` should climb. If it does not, the
capture is filtered out: try `-f ''` and make sure there is traffic on that
interface (a NIC with no traffic is not the same as a broken sniffer). If you
capture on `any`, promiscuous mode is not applied.

**`bad filter expression: …`**
`--filter` uses libpcap syntax (`tcp port 443 and host 10.0.0.1`), not the
client's `-F` syntax (`proto:tcp port:443`). Different tools, different grammar.

**`server busy: no free client slot`**
More clients than `--max-clients`. Raise it, or kill stale clients.

**`drops=` climbs while `clients=1`**
The client cannot read as fast as the link produces, so whole frames are being
discarded for it (`--client-buffer` to give it more room, `-F` on the server to
send less, or `--no-color`/`--no-stats`/`-X` on the client to make it cheaper).

**`protocol error on stream`**
Should not happen in normal use; it means a frame header was unreadable. The
client reconnects if `--reconnect` is set. Please include the server log line
and the output of `pktsniff-server --version` in a report.

**Port already in use**
`bind port 8888: Address already in use` — another server (or an old one) is
running: `pgrep -a pktsniff-server`.

## Verifying a capture

```bash
tcpdump -r subset.pcap -nn | head
tshark -r subset.pcap -q -z io,phs
```

Both sides write the same classic format (microsecond resolution, Ethernet),
so anything that reads `.pcap` reads these.
