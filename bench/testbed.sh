#!/usr/bin/env bash
# Build the evaluation testbed: a veth pair with the far end in namespace "gen".
#   host side: veth0 10.0.0.1 (filters attach here)   namespace side: veth1 10.0.0.2
# A TLS server listens on port 443 in the namespace. Run as root.
set -euo pipefail
cd "$(dirname "$0")"
ip netns del gen 2>/dev/null || true
ip link del veth0 2>/dev/null || true
ip netns add gen
ip link add veth0 type veth peer name veth1
ip link set veth1 netns gen
ip addr add 10.0.0.1/24 dev veth0 && ip link set veth0 up
ip netns exec gen ip addr add 10.0.0.2/24 dev veth1
ip netns exec gen ip link set veth1 up && ip netns exec gen ip link set lo up
ip netns exec gen ip route add default via 10.0.0.1
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
gcc -O2 -o udpflood udpflood.c
[ -f /tmp/dpig-key.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj /CN=testbed \
  -keyout /tmp/dpig-key.pem -out /tmp/dpig-cert.pem 2>/dev/null
ip netns exec gen python3 tls_server.py /tmp/dpig-cert.pem /tmp/dpig-key.pem >/dev/null 2>&1 &
echo "testbed ready: veth0 (10.0.0.1) <-> gen/veth1 (10.0.0.2), TLS server pid $!"
