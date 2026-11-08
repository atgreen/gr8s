#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
umask 077

probe=${1:?usage: test-wireguard-relay.sh RELAY-PROBE}
prefix="g8r$$"
bridge="${prefix}br"
namespaces=("${prefix}-a" "${prefix}-b" "${prefix}-na" "${prefix}-nb" "${prefix}-r")
keydir=$(mktemp -d /tmp/gr8s-relay-keys.XXXXXX)
relay_pid=

cleanup() {
  set +e
  [[ -n "$relay_pid" ]] && kill "$relay_pid" 2>/dev/null
  [[ -n "$relay_pid" ]] && wait "$relay_pid" 2>/dev/null
  for namespace in "${namespaces[@]}"; do ip netns del "$namespace" 2>/dev/null; done
  ip link del "$bridge" 2>/dev/null
  rm -rf "$keydir"
}
trap cleanup EXIT

for namespace in "${namespaces[@]}"; do ip netns add "$namespace"; done
ip link add "$bridge" type bridge
ip link set "$bridge" up

wire_pair() {
  local left=$1 left_if=$2 right=$3 right_if=$4
  ip link add "$left_if" type veth peer name "$right_if"
  ip link set "$left_if" netns "$left"
  ip link set "$right_if" netns "$right"
  ip -n "$left" link set "$left_if" up
  ip -n "$right" link set "$right_if" up
}

wire_public() {
  local namespace=$1 address=$2 host_if=$3 peer_if=$4
  ip link add "$host_if" type veth peer name "$peer_if"
  ip link set "$peer_if" netns "$namespace"
  ip link set "$host_if" master "$bridge"
  ip link set "$host_if" up
  ip -n "$namespace" link set "$peer_if" up
  ip -n "$namespace" address add "$address/24" dev "$peer_if"
}

wire_pair "${prefix}-a" eth0 "${prefix}-na" private
wire_pair "${prefix}-b" eth0 "${prefix}-nb" private
ip -n "${prefix}-a" address add 10.20.1.2/24 dev eth0
ip -n "${prefix}-na" address add 10.20.1.1/24 dev private
ip -n "${prefix}-b" address add 10.20.2.2/24 dev eth0
ip -n "${prefix}-nb" address add 10.20.2.1/24 dev private
ip -n "${prefix}-a" route add default via 10.20.1.1
ip -n "${prefix}-b" route add default via 10.20.2.1
wire_public "${prefix}-na" 198.18.1.2 "${prefix}-pa" public
wire_public "${prefix}-nb" 198.18.1.3 "${prefix}-pb" public
wire_public "${prefix}-r" 198.18.1.4 "${prefix}-pr" eth0

for side in a b; do
  nat="${prefix}-n${side}"
  if [[ "$side" == a ]]; then
    private_cidr=10.20.1.0/24; private_address=10.20.1.2; public_address=198.18.1.2
  else
    private_cidr=10.20.2.0/24; private_address=10.20.2.2; public_address=198.18.1.3
  fi
  ip netns exec "$nat" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "$nat" nft -f - <<EOF
table ip gr8s_relay_nat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "public" ip saddr 198.18.1.4 udp dport 51820 dnat to ${private_address}:51820
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr ${private_cidr} ip daddr 198.18.1.4 udp sport 51820 snat to ${public_address}:51820
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    ip daddr 198.18.1.4 meta l4proto udp accept
    ip saddr 198.18.1.4 meta l4proto udp accept
  }
}
EOF
done

for node in a b; do
  wg genkey >"$keydir/$node.key"
  wg pubkey <"$keydir/$node.key" >"$keydir/$node.pub"
  ip -n "${prefix}-${node}" link add wg0 type wireguard
  ip -n "${prefix}-${node}" link set wg0 up
done
ip -n "${prefix}-a" address add 10.210.0.1/24 dev wg0
ip -n "${prefix}-b" address add 10.210.0.2/24 dev wg0

# Endpoint-dependent filtering deliberately makes direct peer traffic impossible.
ip netns exec "${prefix}-a" wg set wg0 private-key "$keydir/a.key" listen-port 51820 \
  peer "$(<"$keydir/b.pub")" allowed-ips 10.210.0.2/32 endpoint 198.18.1.3:51820 persistent-keepalive 1
ip netns exec "${prefix}-b" wg set wg0 private-key "$keydir/b.key" listen-port 51820 \
  peer "$(<"$keydir/a.pub")" allowed-ips 10.210.0.1/32 endpoint 198.18.1.2:51820 persistent-keepalive 1
if ip netns exec "${prefix}-a" ping -q -c 1 -W 1 10.210.0.2 >/dev/null; then
  echo "direct path unexpectedly crossed endpoint-dependent NAT" >&2
  exit 1
fi

ip netns exec "${prefix}-r" "$probe" 198.18.1.4 42000 >"$keydir/relay.log" 2>&1 &
relay_pid=$!
for _ in $(seq 1 40); do
  grep -q '^relay-ready 42000 42001$' "$keydir/relay.log" && break
  kill -0 "$relay_pid"
  sleep 0.1
done
grep -q '^relay-ready 42000 42001$' "$keydir/relay.log"

# The relay owns no WireGuard interface or peer keys; it sees only opaque UDP.
[[ -z "$(ip -n "${prefix}-r" -o link show type wireguard)" ]]
ip netns exec "${prefix}-a" wg set wg0 peer "$(<"$keydir/b.pub")" endpoint 198.18.1.4:42000
ip netns exec "${prefix}-b" wg set wg0 peer "$(<"$keydir/a.pub")" endpoint 198.18.1.4:42001

for _ in $(seq 1 30); do
  ip netns exec "${prefix}-a" ping -q -c 1 -W 1 10.210.0.2 >/dev/null && break
  ip netns exec "${prefix}-b" ping -q -c 1 -W 1 10.210.0.1 >/dev/null || true
done
ip netns exec "${prefix}-a" ping -q -c 2 -W 2 10.210.0.2 >/dev/null
ip netns exec "${prefix}-b" ping -q -c 2 -W 2 10.210.0.1 >/dev/null

handshake_a=$(ip netns exec "${prefix}-a" wg show wg0 latest-handshakes | awk '{print $2}')
handshake_b=$(ip netns exec "${prefix}-b" wg show wg0 latest-handshakes | awk '{print $2}')
[[ "$handshake_a" -gt 0 && "$handshake_b" -gt 0 ]]
printf 'WireGuard relay passed: direct blocked; fresh handshakes A=%s B=%s; bidirectional encrypted ping through opaque relay\n' \
  "$handshake_a" "$handshake_b"
