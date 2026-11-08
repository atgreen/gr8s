#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
umask 077

probe=${1:?usage: test-wireguard-mtu.sh MTU-PROBE}
prefix="g8m$$"
a="${prefix}-a"
b="${prefix}-b"
r="${prefix}-r"
keydir=$(mktemp -d /tmp/gr8s-mtu-keys.XXXXXX)

cleanup() {
  set +e
  ip netns del "$a" 2>/dev/null
  ip netns del "$b" 2>/dev/null
  ip netns del "$r" 2>/dev/null
  rm -rf "$keydir"
}
trap cleanup EXIT

ip netns add "$a"
ip netns add "$b"
ip netns add "$r"
ip link add "${prefix}a" type veth peer name "${prefix}ra"
ip link set "${prefix}a" netns "$a"
ip link set "${prefix}ra" netns "$r"
ip link add "${prefix}b" mtu 1340 type veth peer name "${prefix}rb"
ip link set "${prefix}b" netns "$b"
ip link set "${prefix}rb" netns "$r"
ip -n "$a" link set "${prefix}a" name eth0
ip -n "$b" link set "${prefix}b" name eth0
ip -n "$a" address add 192.0.2.1/30 dev eth0
ip -n "$r" address add 192.0.2.2/30 dev "${prefix}ra"
ip -n "$r" address add 192.0.2.5/30 dev "${prefix}rb"
ip -n "$b" address add 192.0.2.6/30 dev eth0
ip -n "$a" link set eth0 up mtu 1500
ip -n "$b" link set eth0 up mtu 1340
ip -n "$r" link set "${prefix}ra" up mtu 1500
ip -n "$r" link set "${prefix}rb" up mtu 1340
ip -n "$a" route add 192.0.2.4/30 via 192.0.2.2
ip -n "$b" route add 192.0.2.0/30 via 192.0.2.5
ip netns exec "$r" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$r" nft -f - <<'EOF'
table ip gr8s_mtu_blackhole {
  chain output {
    type filter hook output priority filter; policy accept;
    icmp type destination-unreachable icmp code frag-needed drop
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    ip frag-off & 0x1fff != 0 drop
  }
}
EOF

for node in a b; do
  wg genkey >"$keydir/$node.key"
  wg pubkey <"$keydir/$node.key" >"$keydir/$node.pub"
done

ip -n "$a" link add gr8s-wg type wireguard
ip -n "$b" link add gr8s-wg type wireguard
ip -n "$a" address add 10.220.1.0/32 dev gr8s-wg
ip -n "$b" address add 10.220.2.0/32 dev gr8s-wg
ip netns exec "$a" wg set gr8s-wg private-key "$keydir/a.key" listen-port 51820 \
  peer "$(<"$keydir/b.pub")" allowed-ips 10.220.2.0/32 endpoint 192.0.2.6:51820
ip netns exec "$b" wg set gr8s-wg private-key "$keydir/b.key" listen-port 51820 \
  peer "$(<"$keydir/a.pub")" allowed-ips 10.220.1.0/32 endpoint 192.0.2.1:51820
ip -n "$a" link set gr8s-wg up mtu 1420
ip -n "$b" link set gr8s-wg up mtu 1420
ip -n "$a" route add 10.220.2.0/32 dev gr8s-wg
ip -n "$b" route add 10.220.1.0/32 dev gr8s-wg

ip netns exec "$a" ping -q -c 1 -W 2 10.220.2.0 >/dev/null
result=$(ip netns exec "$a" "$probe" 10.220.2.0/24 1420)
printf 'observed MTU probe result: %s\n' "$result"
[[ "$result" == "mtu=1280 reason=packet-size-black-hole" ]]
ip netns exec "$a" ping -q -c 1 -W 2 -M do -s 1252 10.220.2.0 >/dev/null
if ip netns exec "$a" ping -q -c 1 -W 1 -M do -s 1253 10.220.2.0 >/dev/null 2>&1; then
  echo "oversized inner packet unexpectedly crossed the constrained underlay" >&2
  exit 1
fi
printf 'WireGuard MTU discovery passed: %s; 1280-byte inner packet succeeds and 1281-byte packet black-holes\n' "$result"
