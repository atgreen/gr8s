#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
umask 077

prefix="g8n$$"
bridge="${prefix}br"
namespaces=("${prefix}-a" "${prefix}-b" "${prefix}-na" "${prefix}-nb" "${prefix}-r")
keydir=$(mktemp -d /tmp/gr8s-nat-keys.XXXXXX)

cleanup() {
  set +e
  for namespace in "${namespaces[@]}"; do ip netns del "$namespace" 2>/dev/null; done
  ip link del "$bridge" 2>/dev/null
  rm -f "$keydir"/a.key "$keydir"/a.pub "$keydir"/b.key "$keydir"/b.pub \
        "$keydir"/r.key "$keydir"/r.pub
  rmdir "$keydir" 2>/dev/null
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
ip -n "${prefix}-a" address add 10.10.1.2/24 dev eth0
ip -n "${prefix}-na" address add 10.10.1.1/24 dev private
ip -n "${prefix}-b" address add 10.10.2.2/24 dev eth0
ip -n "${prefix}-nb" address add 10.10.2.1/24 dev private
ip -n "${prefix}-a" route add default via 10.10.1.1
ip -n "${prefix}-b" route add default via 10.10.2.1

wire_public "${prefix}-na" 198.18.0.2 "${prefix}-pa" public
wire_public "${prefix}-nb" 198.18.0.3 "${prefix}-pb" public
wire_public "${prefix}-r" 198.18.0.4 "${prefix}-pr" eth0

for side in a b; do
  nat="${prefix}-n${side}"
  if [[ "$side" == a ]]; then
    private_cidr=10.10.1.0/24
    private_address=10.10.1.2
    public_address=198.18.0.2
  else
    private_cidr=10.10.2.0/24
    private_address=10.10.2.2
    public_address=198.18.0.3
  fi
  ip netns exec "$nat" sysctl -q -w net.ipv4.ip_forward=1
  # Endpoint-independent UDP mapping (cone NAT): the common case where
  # rendezvous-assisted punching works. Symmetric NAT falls through to relay.
  ip netns exec "$nat" nft -f - <<EOF
table ip gr8s_nat {
  chain prerouting { type nat hook prerouting priority dstnat; policy accept; iifname "public" udp dport 51820 dnat to ${private_address}:51820; }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr ${private_cidr} udp sport 51820 snat to ${public_address}:51820;
    oifname "public" masquerade;
  }
  chain forward { type filter hook forward priority filter; policy accept; }
}
EOF
done

# Prove both private namespaces can reach the public rendezvous through NAT.
ip netns exec "${prefix}-a" ping -q -c 1 -W 2 198.18.0.4 >/dev/null
ip netns exec "${prefix}-b" ping -q -c 1 -W 2 198.18.0.4 >/dev/null

for node in a b r; do
  wg genkey >"$keydir/$node.key"
  wg pubkey <"$keydir/$node.key" >"$keydir/$node.pub"
done

for node in a b r; do
  namespace="${prefix}-${node}"
  ip -n "$namespace" link add wg0 type wireguard
  ip -n "$namespace" link set wg0 up
done
ip -n "${prefix}-a" address add 10.200.0.1/24 dev wg0
ip -n "${prefix}-b" address add 10.200.0.2/24 dev wg0
ip -n "${prefix}-r" address add 10.200.0.254/24 dev wg0

ip netns exec "${prefix}-a" wg set wg0 private-key "$keydir/a.key" listen-port 51820 \
  peer "$(<"$keydir/r.pub")" allowed-ips 10.200.0.254/32 endpoint 198.18.0.4:51820 persistent-keepalive 1 \
  peer "$(<"$keydir/b.pub")" allowed-ips 10.200.0.2/32
ip netns exec "${prefix}-b" wg set wg0 private-key "$keydir/b.key" listen-port 51820 \
  peer "$(<"$keydir/r.pub")" allowed-ips 10.200.0.254/32 endpoint 198.18.0.4:51820 persistent-keepalive 1 \
  peer "$(<"$keydir/a.pub")" allowed-ips 10.200.0.1/32
ip netns exec "${prefix}-r" wg set wg0 private-key "$keydir/r.key" listen-port 51820 \
  peer "$(<"$keydir/a.pub")" allowed-ips 10.200.0.1/32 \
  peer "$(<"$keydir/b.pub")" allowed-ips 10.200.0.2/32

# Trigger authenticated sessions to the rendezvous and wait for both reflexive endpoints.
ip netns exec "${prefix}-a" ping -q -c 1 -W 2 10.200.0.254 >/dev/null || true
ip netns exec "${prefix}-b" ping -q -c 1 -W 2 10.200.0.254 >/dev/null || true
for attempt in $(seq 1 20); do
  endpoint_a=$(ip netns exec "${prefix}-r" wg show wg0 endpoints | awk -v key="$(<"$keydir/a.pub")" '$1 == key {print $2}')
  endpoint_b=$(ip netns exec "${prefix}-r" wg show wg0 endpoints | awk -v key="$(<"$keydir/b.pub")" '$1 == key {print $2}')
  [[ "$endpoint_a" != "(none)" && "$endpoint_b" != "(none)" ]] && break
  sleep 0.2
done
[[ "${endpoint_a:-}" != "(none)" && "${endpoint_b:-}" != "(none)" ]]

# Exchange the authenticated observations and punch in both directions at once.
ip netns exec "${prefix}-a" wg set wg0 peer "$(<"$keydir/b.pub")" endpoint "$endpoint_b" persistent-keepalive 1
ip netns exec "${prefix}-b" wg set wg0 peer "$(<"$keydir/a.pub")" endpoint "$endpoint_a" persistent-keepalive 1
for attempt in $(seq 1 30); do
  ip netns exec "${prefix}-a" ping -q -c 1 -W 1 10.200.0.2 >/dev/null || true
  sleep 0.1
done &
ping_a=$!
for attempt in $(seq 1 30); do
  ip netns exec "${prefix}-b" ping -q -c 1 -W 1 10.200.0.1 >/dev/null || true
  sleep 0.1
done &
ping_b=$!
wait "$ping_a"
wait "$ping_b"
ip netns exec "${prefix}-a" wg show wg0
ip netns exec "${prefix}-b" wg show wg0
ip netns exec "${prefix}-a" ping -q -c 2 -W 2 10.200.0.2 >/dev/null
ip netns exec "${prefix}-b" ping -q -c 2 -W 2 10.200.0.1 >/dev/null

direct_a=$(ip netns exec "${prefix}-a" wg show wg0 endpoints | awk -v key="$(<"$keydir/b.pub")" '$1 == key {print $2}')
direct_b=$(ip netns exec "${prefix}-b" wg show wg0 endpoints | awk -v key="$(<"$keydir/a.pub")" '$1 == key {print $2}')
printf 'NAT traversal passed: rendezvous A=%s B=%s; direct A->B=%s B->A=%s\n' \
  "$endpoint_a" "$endpoint_b" "$direct_a" "$direct_b"
