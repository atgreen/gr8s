#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 077

probe=${1:-}

prefix="g8s$$"; a="${prefix}a"; g1="${prefix}g1"; g2="${prefix}g2"; b="${prefix}b"
bridge="${prefix}br"; keydir=$(mktemp -d /tmp/gr8s-sparse-keys.XXXXXX)
capture="$keydir/underlay.txt"; received="$keydir/received.txt"
marker="GR8S-SPARSE-PLAINTEXT-MUST-NOT-REACH-UNDERLAY"
capture_pid=; listener_pid=

cleanup() {
  set +e
  [[ -n "$listener_pid" ]] && kill "$listener_pid" 2>/dev/null
  [[ -n "$capture_pid" ]] && kill "$capture_pid" 2>/dev/null
  for namespace in "$a" "$g1" "$g2" "$b"; do ip netns del "$namespace" 2>/dev/null; done
  ip link del "$bridge" 2>/dev/null
  rm -rf "$keydir"
}
trap cleanup EXIT

ip link add "$bridge" type bridge
ip link set "$bridge" up
attach_node() {
  local namespace=$1 address=$2 host_if=$3
  ip netns add "$namespace"
  ip link add "$host_if" type veth peer name eth0 netns "$namespace"
  ip link set "$host_if" master "$bridge"
  ip link set "$host_if" up
  ip -n "$namespace" link set lo up
  ip -n "$namespace" link set eth0 up
  ip -n "$namespace" address add "$address/24" dev eth0
}
attach_node "$a" 192.0.2.1 "${prefix}ha"
attach_node "$g1" 192.0.2.2 "${prefix}h1"
attach_node "$g2" 192.0.2.3 "${prefix}h2"
attach_node "$b" 192.0.2.4 "${prefix}hb"

for node in a g1 g2 b; do
  wg genkey >"$keydir/$node.key"
  wg pubkey <"$keydir/$node.key" >"$keydir/$node.pub"
done
for namespace in "$a" "$g1" "$g2" "$b"; do
  ip -n "$namespace" link add gr8s-wg type wireguard
  ip -n "$namespace" link set gr8s-wg up
done
ip -n "$a" address add 10.88.1.1/32 dev lo
ip -n "$g1" address add 10.88.101.1/32 dev lo
ip -n "$g2" address add 10.88.102.1/32 dev lo
ip -n "$g2" address add 10.88.102.0/32 dev gr8s-wg
ip -n "$b" address add 10.88.2.1/32 dev lo

# g1 owns destination CIDRs. g2 initially owns only its probe /32, allowing a
# fresh authenticated trial without stealing traffic from the last-known-good path.
ip netns exec "$a" wg set gr8s-wg private-key "$keydir/a.key" listen-port 51820 \
  peer "$(<"$keydir/g1.pub")" allowed-ips 10.88.2.0/24 endpoint 192.0.2.2:51820 \
  peer "$(<"$keydir/g2.pub")" allowed-ips 10.88.102.1/32 endpoint 192.0.2.3:51820
ip netns exec "$b" wg set gr8s-wg private-key "$keydir/b.key" listen-port 51820 \
  peer "$(<"$keydir/g1.pub")" allowed-ips 10.88.1.0/24 endpoint 192.0.2.2:51820 \
  peer "$(<"$keydir/g2.pub")" allowed-ips 10.88.102.1/32 endpoint 192.0.2.3:51820

configure_gateway() {
  local namespace=$1 key=$2
  ip netns exec "$namespace" wg set gr8s-wg private-key "$key" listen-port 51820 \
    peer "$(<"$keydir/a.pub")" allowed-ips 10.88.1.0/24 endpoint 192.0.2.1:51820 \
    peer "$(<"$keydir/b.pub")" allowed-ips 10.88.2.0/24 endpoint 192.0.2.4:51820
  ip -n "$namespace" route add 10.88.1.0/24 dev gr8s-wg
  ip -n "$namespace" route add 10.88.2.0/24 dev gr8s-wg
  ip netns exec "$namespace" sysctl -q -w net.ipv4.ip_forward=1
}
configure_gateway "$g1" "$keydir/g1.key"
configure_gateway "$g2" "$keydir/g2.key"
ip -n "$a" route add 10.88.2.0/24 dev gr8s-wg
ip -n "$a" route add 10.88.102.1/32 dev gr8s-wg
ip -n "$b" route add 10.88.1.0/24 dev gr8s-wg
ip -n "$b" route add 10.88.102.1/32 dev gr8s-wg

for namespace in "$a" "$g1" "$g2" "$b"; do
  [[ $(ip netns exec "$namespace" wg show gr8s-wg peers | wc -l) -eq 2 ]]
done
tcpdump -i "$bridge" -nn -l -A udp port 51820 >"$capture" 2>/dev/null &
capture_pid=$!
sleep 0.2

send_marker() {
  : >"$received"
  ip netns exec "$b" nc -u -l 10.88.2.1 19000 >"$received" &
  listener_pid=$!
  sleep 0.1
  printf '%s' "$marker" | ip netns exec "$a" nc -u -w 1 -s 10.88.1.1 10.88.2.1 19000
  for _ in $(seq 1 20); do grep -Fq "$marker" "$received" && break; sleep 0.1; done
  grep -Fq "$marker" "$received"
  kill "$listener_pid" 2>/dev/null || true
  wait "$listener_pid" 2>/dev/null || true
  listener_pid=
}

ip netns exec "$a" ping -q -c 2 -W 2 -I 10.88.1.1 10.88.2.1 >/dev/null
send_marker

# Verify g2 while g1 remains selected, then commit only after both fresh handshakes.
probe_target=10.88.102.1
if [[ -n "$probe" ]]; then
  ip netns exec "$a" "$probe" g2 "$(<"$keydir/g2.pub")" 192.0.2.3 51820 10.88.102.0/24
  ip netns exec "$b" "$probe" g2 "$(<"$keydir/g2.pub")" 192.0.2.3 51820 10.88.102.0/24
  probe_target=10.88.102.0
fi
ip netns exec "$a" ping -q -c 1 -W 2 -I 10.88.1.1 "$probe_target" >/dev/null
ip netns exec "$b" ping -q -c 1 -W 2 -I 10.88.2.1 "$probe_target" >/dev/null
for namespace in "$a" "$b"; do
  handshake=$(ip netns exec "$namespace" wg show gr8s-wg latest-handshakes |
    awk -v key="$(<"$keydir/g2.pub")" '$1 == key { print $2 }')
  [[ "$handshake" -gt 0 ]]
done

ip netns del "$g1"
ip netns exec "$a" wg set gr8s-wg \
  peer "$(<"$keydir/g2.pub")" allowed-ips "10.88.2.0/24,$probe_target/32" \
  peer "$(<"$keydir/g1.pub")" remove
ip netns exec "$b" wg set gr8s-wg \
  peer "$(<"$keydir/g2.pub")" allowed-ips "10.88.1.0/24,$probe_target/32" \
  peer "$(<"$keydir/g1.pub")" remove
[[ $(ip netns exec "$a" wg show gr8s-wg peers | wc -l) -eq 1 ]]
[[ $(ip netns exec "$b" wg show gr8s-wg peers | wc -l) -eq 1 ]]
ip netns exec "$a" ping -q -c 2 -W 2 -I 10.88.1.1 10.88.2.1 >/dev/null
ip netns exec "$b" ping -q -c 2 -W 2 -I 10.88.2.1 10.88.1.1 >/dev/null
send_marker

kill "$capture_pid" 2>/dev/null || true
wait "$capture_pid" 2>/dev/null || true
capture_pid=
if grep -Fq "$marker" "$capture"; then
  echo "plaintext marker was visible on the WireGuard underlay" >&2
  exit 1
fi
printf 'Sparse WireGuard resilience passed: bounded two-peer trial, authenticated g2 before g1 withdrawal, bidirectional failover, and no plaintext marker on underlay\n'
