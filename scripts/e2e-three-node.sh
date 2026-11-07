#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
#
# e2e-three-node.sh -- stand up a THREE-control-plane HA gr8s cluster on local
# libvirt VMs (a 3-member Raft quorum, every member also a schedulable node) and
# run the Kubernetes conformance suite on it with Sonobuoy. Resilient and
# re-runnable: it does not assume a clean slate.
#
# Topology
#   vm1 (gr8s-ha-1) : founder  -- `serve --raft-init`. Wins the initial election,
#         performs the one-shot cluster bootstrap writes (namespaces, default
#         roles, the kubernetes Service), then leads the Raft group.
#   vm2,vm3         : joiners  -- `serve --raft-join vm1:RAFT_PORT` with a
#         control-plane join token minted on vm1. They receive the bootstrap
#         state by Raft replication (they do NOT re-run the bootstrap writes --
#         see podster-40i) and each brings up its own node agent + in-cluster API
#         listener on 10.96.0.1, so a Pod on any node reaches the API locally.
#   laptop          : operator -- runs NO gr8s. Forwards vm1's loopback API over
#         SSH and drives kubectl + Sonobuoy. kubectl always targets the founder;
#         if it is down, point TUNNEL at another member (all serve the same API).
#
# This requires the podster-40i fix (leadership-gated bootstrap writes); without
# it `serve --raft-init` crashes before election. Build the binary from a tree
# that has that fix.
#
# Usage: same verbs as e2e-two-node.sh
#   scripts/e2e-three-node.sh up | test | status | watch | results | down | destroy | run
#
# Test selection (GR8S_E2E_MODE): certified (default, certified-conformance),
#   conformance, all, quick, custom (GR8S_E2E_FOCUS / GR8S_E2E_SKIP).
set -euo pipefail

# ----------------------------------------------------------------------------- config
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="${GR8S_E2E_CACHE:-$HOME/.cache/gr8s-vm}"
IMAGES_DIR="${GR8S_E2E_IMAGES_DIR:-/var/lib/libvirt/images}"
BASE_IMG="$CACHE/fedora-44-base.qcow2"
FEDORA_URL="${GR8S_E2E_FEDORA_URL:-https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2}"
SSH_KEY="$CACHE/id_ed25519"
KNOWN="$CACHE/vm_known_hosts"
VIRSH=(sudo virsh -c qemu:///system)
NET="${GR8S_E2E_NET:-default}"
read -r -a NODES <<< "${GR8S_E2E_NODES:-gr8s-ha-1 gr8s-ha-2 gr8s-ha-3}"   # NODES[0] is the founder
VCPUS="${GR8S_E2E_VCPUS:-2}"; MEM="${GR8S_E2E_MEM:-4096}"; DISK="${GR8S_E2E_DISK:-20G}"
CP_API_PORT="${GR8S_E2E_CP_API_PORT:-8080}"      # each member's loopback API
CP_NODE_PORT="${GR8S_E2E_CP_NODE_PORT:-7443}"    # each member's node-server
RAFT_PORT="${GR8S_E2E_RAFT_PORT:-9443}"          # Raft inter-member transport
TUNNEL_PORT="${GR8S_E2E_TUNNEL_PORT:-18090}"     # laptop local port -> founder API
KUBECONFIG_FILE="$CACHE/e2e.kubeconfig"
RUNDIR="${GR8S_E2E_RUNDIR:-$CACHE/run3}"
GR8S_BIN="${GR8S_BIN:-$HERE/build/gr8s}"
SBCL="${SBCL:-/usr/bin/sbcl}"
SONOBUOY="$CACHE/sonobuoy"
SONOBUOY_VERSION="${GR8S_E2E_SONOBUOY_VERSION:-0.57.3}"
MODE="${GR8S_E2E_MODE:-certified}"
FOCUS="${GR8S_E2E_FOCUS:-}"; SKIP="${GR8S_E2E_SKIP:-}"
EXTRA_ARGS="${GR8S_E2E_EXTRA_ARGS:-}"
FIREWALLD="${GR8S_E2E_FIREWALLD:-on}"
DEBUG_SLYNK_PORT="${GR8S_E2E_DEBUG_SLYNK_PORT:-}"
KC=(kubectl --kubeconfig "$KUBECONFIG_FILE" --request-timeout=20s)
SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile="$KNOWN" -o ConnectTimeout=8 -o ServerAliveInterval=15)

# ----------------------------------------------------------------------------- helpers
c_blue=$'\033[34m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_rst=$'\033[0m'
log()  { printf '%s[e2e]%s %s\n'  "$c_blue" "$c_rst" "$*" >&2; }
ok()   { printf '%s[ok]%s  %s\n'  "$c_grn"  "$c_rst" "$*" >&2; }
warn() { printf '%s[warn]%s %s\n' "$c_yel"  "$c_rst" "$*" >&2; }
die()  { printf '%s[fail]%s %s\n' "$c_red"  "$c_rst" "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"; }
ssh_n()  { ssh -n "${SSH_OPTS[@]}" "root@$1" "${@:2}"; }
scp_to() { scp "${SSH_OPTS[@]}" "$2" "root@$1:$3"; }

preflight() {
  for c in qemu-img virt-install curl ssh scp kubectl jq python3 genisoimage; do need "$c"; done
  sudo -n true 2>/dev/null || sudo true || die "sudo is required (VMs, images)"
  [ -r /dev/kvm ] || warn "/dev/kvm not readable; VMs will be slow"
  "${VIRSH[@]}" net-info "$NET" >/dev/null 2>&1 || die "libvirt network '$NET' not found"
  "${VIRSH[@]}" net-info "$NET" 2>/dev/null | grep -qi 'active:.*yes' || "${VIRSH[@]}" net-start "$NET" 2>/dev/null || true
  mkdir -p "$RUNDIR"
  if [ -n "$DEBUG_SLYNK_PORT" ]; then
    [[ "$DEBUG_SLYNK_PORT" =~ ^[0-9]+$ ]] \
      || die "GR8S_E2E_DEBUG_SLYNK_PORT must be an integer from 1 through 65535"
    [ "$DEBUG_SLYNK_PORT" -ge 1 ] && [ "$DEBUG_SLYNK_PORT" -le 65535 ] \
      || die "GR8S_E2E_DEBUG_SLYNK_PORT must be an integer from 1 through 65535"
  fi
}

ensure_image_and_keys() {
  mkdir -p "$CACHE"
  if [ ! -f "$BASE_IMG" ]; then
    log "fetching Fedora base image (one-time, ~600MB)"
    curl -fsSL --retry 3 -o "$BASE_IMG.part" "$FEDORA_URL" && mv "$BASE_IMG.part" "$BASE_IMG"
  fi
  ok "base image: $BASE_IMG"
  [ -f "$SSH_KEY" ] || { log "generating SSH key"; ssh-keygen -t ed25519 -N '' -f "$SSH_KEY" -C gr8s-e2e >/dev/null; }
  local pub; pub="$(cat "$SSH_KEY.pub")"
  for i in "${!NODES[@]}"; do
    local d="$CACHE/seed-${NODES[$i]}"
    if [ ! -f "$d.iso" ]; then
      mkdir -p "$d"
      printf 'instance-id: %s\nlocal-hostname: %s\n' "${NODES[$i]}" "${NODES[$i]}" > "$d/meta-data"
      cat > "$d/user-data" <<EOF
#cloud-config
hostname: ${NODES[$i]}
disable_root: false
ssh_pwauth: true
chpasswd: { expire: false, list: "root:gr8s" }
users:
  - name: root
    lock_passwd: false
    ssh_authorized_keys: [ "$pub" ]
EOF
      genisoimage -quiet -output "$d.iso" -volid cidata -joliet -rock "$d/user-data" "$d/meta-data"
    fi
  done
}

ensure_vm() {  # create if absent, start if defined-but-off, else leave running
  local name="$1" seed="$2"
  if "${VIRSH[@]}" dominfo "$name" >/dev/null 2>&1; then
    "${VIRSH[@]}" domstate "$name" 2>/dev/null | grep -qi running || { log "starting existing VM $name"; "${VIRSH[@]}" start "$name" >/dev/null; }
    return
  fi
  log "creating VM $name"
  local overlay="$IMAGES_DIR/$name.qcow2" base="$IMAGES_DIR/gr8s-e2e-base.qcow2" seediso="$IMAGES_DIR/$name-seed.iso"
  sudo test -f "$base" || sudo cp "$BASE_IMG" "$base"
  sudo qemu-img create -f qcow2 -b "$base" -F qcow2 "$overlay" "$DISK" >/dev/null
  sudo cp "$seed" "$seediso"
  sudo restorecon -F "$base" "$overlay" "$seediso" 2>/dev/null || true
  sudo virt-install --connect qemu:///system --name "$name" \
    --memory "$MEM" --vcpus "$VCPUS" --cpu host-passthrough \
    --disk path="$overlay",format=qcow2,bus=virtio \
    --disk path="$seediso",device=cdrom \
    --osinfo fedora-unknown --network network="$NET",model=virtio \
    --graphics none --import --noautoconsole >/dev/null
}

vm_ip() { local name="$1" ip="" i; for i in $(seq 1 60); do
    ip="$("${VIRSH[@]}" domifaddr "$name" 2>/dev/null | awk '/ipv4/{print $4}' | cut -d/ -f1 | head -1)"
    [ -n "$ip" ] && { echo "$ip"; return 0; }; sleep 2; done; return 1; }

wait_ssh() { local ip="$1" i; for i in $(seq 1 40); do ssh_n "$ip" true 2>/dev/null && return 0; sleep 5; done; return 1; }

guest_prep() {  # deps, forwarding, firewalld + the Raft port. Idempotent.
  local ip="$1"
  ssh_n "$ip" 'set +e
    for p in libzstd bpftool tcpdump firewalld; do rpm -q "$p" >/dev/null 2>&1 || dnf install -y -q "$p" >/dev/null 2>&1; done
    sysctl -w net.ipv4.ip_forward=1 >/dev/null' 2>/dev/null || true
  if [ "$FIREWALLD" = on ]; then
    # gr8s opens its own node-port + overlay (podster-vwy); the Raft inter-member
    # transport port is ours to open so members can form the quorum.
    ssh_n "$ip" "systemctl enable --now firewalld >/dev/null 2>&1 || true
      firewall-cmd --add-port=$RAFT_PORT/tcp >/dev/null 2>&1 || true" 2>/dev/null || true
  else
    ssh_n "$ip" 'systemctl disable --now firewalld >/dev/null 2>&1 || true' 2>/dev/null || true
  fi
}

guest_gr8s_teardown() {  # stop gr8s and clear stale dataplane/network/state on a guest
  local ip="$1"
  ssh_n "$ip" 'set +e
    systemctl kill --kill-who=all --signal=SIGKILL gr8s gr8s-agent 2>/dev/null
    systemctl stop gr8s gr8s-agent 2>/dev/null; systemctl reset-failed gr8s gr8s-agent 2>/dev/null
    pkill -9 -x containerd 2>/dev/null
    pgrep -f "^/.*/containerd-shim-runc-v2( |$)" | xargs -r kill -9 2>/dev/null
    sleep 1
    for m in $(mount | awk "{print \$3}" | grep "/var/lib/gr8s" | sort -r); do umount -l "$m" 2>/dev/null; done
    for dev in $(ip -br link show | awk "{print \$1}" | sed "s/@.*//" | grep -iE "gr8s|vxlan|^gr[0-9a-f]"); do ip link del "$dev" 2>/dev/null; done
    for r in $(ip route show | awk "/10\.(80|96)\./{print \$1}"); do ip route del "$r" 2>/dev/null; done
    rm -rf /var/lib/gr8s' 2>/dev/null || true
}

build_binary() {
  if [ "${GR8S_E2E_BUILD:-}" = 1 ] || [ ! -x "$GR8S_BIN" ]; then
    log "building native gr8s with $SBCL"; ( cd "$HERE" && make native SBCL="$SBCL" ) || die "native build failed"
  fi
  readelf -l "$GR8S_BIN" 2>/dev/null | grep -q 'ld-linux-x86-64' \
    || warn "binary interpreter is not /lib64/ld-linux; rebuild with SBCL=/usr/bin/sbcl (GR8S_E2E_BUILD=1) so it runs on the guests"
  ok "gr8s binary: $GR8S_BIN ($(git -C "$HERE" describe --tags --always --dirty 2>/dev/null || echo unknown))"
}

deploy_binary() { local ip="$1"
  scp_to "$ip" "$GR8S_BIN" /usr/local/bin/gr8s.new
  ssh_n "$ip" 'mv /usr/local/bin/gr8s.new /usr/local/bin/gr8s; chmod 755 /usr/local/bin/gr8s; restorecon -F /usr/local/bin/gr8s'
}

wait_api() {  # ip -- wait for a member's loopback API to be ready
  local ip="$1" i code
  for i in $(seq 1 50); do
    code="$(ssh_n "$ip" "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$CP_API_PORT/readyz 2>/dev/null" 2>/dev/null || echo 000)"
    [ "$code" = 200 ] && return 0; sleep 3
  done
  ssh_n "$ip" "journalctl -u gr8s --no-pager -n 30" 2>/dev/null >&2 || true
  return 1
}

founder_up() {  # ip name -- start the --raft-init founder and wait for its API (=> it won election)
  local ip="$1" name="$2"
  log "starting HA founder on $name ($ip): serve --raft-init (raft $ip:$RAFT_PORT)"
  ssh_n "$ip" "systemctl reset-failed gr8s 2>/dev/null; sysctl -w net.ipv4.ip_forward=1 >/dev/null
    systemd-run --unit gr8s --collect /usr/local/bin/gr8s serve \
      --raft-init --raft-id $name --raft-node-name $name --raft-listen $ip --raft-port $RAFT_PORT \
      --listen 127.0.0.1 --port $CP_API_PORT \
      --node-listen $ip --node-port $CP_NODE_PORT --node-address $ip \
      --node-name $name --state-directory /var/lib/gr8s --kubeconfig /root/kubeconfig \
      ${DEBUG_SLYNK_PORT:+--debug-slynk-port $DEBUG_SLYNK_PORT} >/dev/null 2>&1"
  wait_api "$ip" || die "founder $name did not become ready (podster-40i? check journalctl -u gr8s on $ip)"
  ok "HA founder ready and leading on $name"
}

mint_cp_token() { ssh_n "$1" "/usr/local/bin/gr8s join-token --role control-plane --state-directory /var/lib/gr8s --node-name $2" 2>/dev/null \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["token"],d["caPin"])'; }

member_up() {  # ip name founder_ip -- join an existing quorum as a control-plane member
  local ip="$1" name="$2" founder="$3" tok capin
  read -r tok capin < <(mint_cp_token "$founder" "$name")
  [ -n "$tok" ] || die "could not mint a control-plane join token for $name"
  log "joining HA member $name ($ip) -> $founder:$RAFT_PORT"
  ssh_n "$ip" "systemctl reset-failed gr8s 2>/dev/null; sysctl -w net.ipv4.ip_forward=1 >/dev/null
    systemd-run --unit gr8s --collect /usr/local/bin/gr8s serve \
      --raft-join $founder:$RAFT_PORT --raft-id $name --raft-node-name $name \
      --raft-listen $ip --raft-port $RAFT_PORT --raft-token $tok --raft-ca-pin $capin \
      --listen 127.0.0.1 --port $CP_API_PORT \
      --node-listen $ip --node-port $CP_NODE_PORT --node-address $ip \
      --node-name $name --state-directory /var/lib/gr8s --kubeconfig /root/kubeconfig \
      ${DEBUG_SLYNK_PORT:+--debug-slynk-port $DEBUG_SLYNK_PORT} >/dev/null 2>&1"
  wait_api "$ip" || die "member $name did not become ready; check journalctl -u gr8s on $ip"
  ok "HA member $name joined"
}

tunnel_down() {  # set -e safe: always returns 0
  if [ -f "$RUNDIR/tunnel.pid" ]; then kill "$(cat "$RUNDIR/tunnel.pid" 2>/dev/null)" 2>/dev/null || true; rm -f "$RUNDIR/tunnel.pid"; fi
  local pid; pid="$(ss -ltnpH "sport = :$TUNNEL_PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2 || true)"
  [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null || true
  return 0
}
tunnel_up() {  # forward laptop:$TUNNEL_PORT -> founder loopback API, write a kubeconfig at that port
  local ip="$1"
  tunnel_down
  ssh "${SSH_OPTS[@]}" -fN -L "$TUNNEL_PORT:127.0.0.1:$CP_API_PORT" "root@$ip" || die "could not open the API tunnel"
  ss -ltnpH "sport = :$TUNNEL_PORT" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2 > "$RUNDIR/tunnel.pid" 2>/dev/null || true
  cat > "$KUBECONFIG_FILE" <<EOF
apiVersion: v1
kind: Config
clusters: [{name: e2e, cluster: {server: "http://127.0.0.1:$TUNNEL_PORT"}}]
contexts: [{name: e2e, context: {cluster: e2e}}]
current-context: e2e
EOF
  local i; for i in $(seq 1 20); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$TUNNEL_PORT/readyz" 2>/dev/null || echo 000)" = 200 ] && { ok "API tunnel up: 127.0.0.1:$TUNNEL_PORT -> $ip:$CP_API_PORT"; return 0; }
    sleep 1
  done
  die "API tunnel did not come up"
}

wait_nodes() { local want="${#NODES[@]}" i n=0
  for i in $(seq 1 60); do
    n="$("${KC[@]}" get nodes --no-headers 2>/dev/null | grep -c ' Ready' || true)"
    [ "$n" = "$want" ] && { ok "$want nodes Ready"; "${KC[@]}" get nodes -o wide 2>/dev/null >&2 || true; return 0; }
    sleep 3
  done
  "${KC[@]}" get nodes -o wide 2>/dev/null >&2 || true
  die "nodes did not all become Ready ($n/$want); see '$0 status'"
}

sonobuoy_ensure() {
  if [ ! -x "$SONOBUOY" ]; then
    log "downloading Sonobuoy $SONOBUOY_VERSION"
    curl -fsSL "https://github.com/vmware-tanzu/sonobuoy/releases/download/v${SONOBUOY_VERSION}/sonobuoy_${SONOBUOY_VERSION}_linux_amd64.tar.gz" \
      | tar -xz -C "$CACHE" sonobuoy && chmod +x "$SONOBUOY"
  fi
  ok "sonobuoy: $("$SONOBUOY" version --short 2>/dev/null || echo "$SONOBUOY")"
}

sonobuoy_run_args() {
  case "$MODE" in
    certified)   printf -- '--mode=certified-conformance\n' ;;
    conformance) printf -- '--mode=conformance\n' ;;
    all)         printf -- '--e2e-focus=.\n--e2e-skip=\n' ;;
    quick)       printf -- '--e2e-focus=%s\n--e2e-skip=\n' 'should serve a basic endpoint from pods' ;;
    custom)      printf -- '--e2e-focus=%s\n--e2e-skip=%s\n' "$FOCUS" "$SKIP" ;;
    *) die "unknown GR8S_E2E_MODE: $MODE" ;;
  esac
}

# ----------------------------------------------------------------------------- commands
cmd_up() {
  preflight; ensure_image_and_keys; build_binary
  local ips=() i
  for i in "${!NODES[@]}"; do ensure_vm "${NODES[$i]}" "$CACHE/seed-${NODES[$i]}.iso"; done
  for i in "${!NODES[@]}"; do
    local ip; ip="$(vm_ip "${NODES[$i]}")" || die "no DHCP address for ${NODES[$i]}"
    ips+=("$ip"); log "${NODES[$i]} -> $ip"
    wait_ssh "$ip" || die "SSH to ${NODES[$i]} ($ip) never came up"
    guest_prep "$ip"; guest_gr8s_teardown "$ip"; deploy_binary "$ip"
  done
  printf '%s\n' "${ips[@]}" > "$RUNDIR/vm-ips"
  founder_up "${ips[0]}" "${NODES[0]}"       # vm1 = Raft founder + node
  tunnel_up "${ips[0]}"
  for i in "${!NODES[@]}"; do [ "$i" = 0 ] && continue; member_up "${ips[$i]}" "${NODES[$i]}" "${ips[0]}"; done
  wait_nodes
  ok "HA cluster up (3-member quorum). KUBECONFIG=$KUBECONFIG_FILE ; drive it with: ${KC[*]} get nodes"
}

cmd_test() {
  [ -f "$KUBECONFIG_FILE" ] || die "no cluster; run '$0 up' first"
  sonobuoy_ensure
  mapfile -t runargs < <(sonobuoy_run_args)
  [ -z "$EXTRA_ARGS" ] || runargs+=("--plugin-env=e2e.E2E_EXTRA_ARGS=$EXTRA_ARGS")
  log "submitting conformance suite (mode=$MODE): sonobuoy run ${runargs[*]}"
  "$SONOBUOY" run --kubeconfig "$KUBECONFIG_FILE" --dns-pod-labels= --plugin=e2e "${runargs[@]}" \
    > "$RUNDIR/sonobuoy-run.log" 2>&1 || { tail -20 "$RUNDIR/sonobuoy-run.log" >&2; die "sonobuoy submission failed"; }
  ok "conformance suite submitted."
  cat >&2 <<EOF

Watch progress:
    $0 status     # one-shot: nodes, Sonobuoy status, e2e pods
    $0 watch      # live until the run finishes
When finished:
    $0 results    # retrieve + summarize pass/fail
EOF
}

cmd_status() {
  [ -f "$KUBECONFIG_FILE" ] || die "no cluster; run '$0 up' first"
  echo "== nodes =="; "${KC[@]}" get nodes -o wide 2>/dev/null || true
  echo "== sonobuoy =="; "$SONOBUOY" status --kubeconfig "$KUBECONFIG_FILE" 2>/dev/null || echo "(no run submitted yet)"
  echo "== sonobuoy pods =="; "${KC[@]}" get pods -n sonobuoy -o wide 2>/dev/null || true
}

cmd_watch() {
  [ -f "$KUBECONFIG_FILE" ] || die "no cluster; run '$0 up' first"
  local phase
  while :; do
    phase="$("$SONOBUOY" status --kubeconfig "$KUBECONFIG_FILE" --json 2>/dev/null | jq -r '.status // "unknown"' 2>/dev/null || echo unknown)"
    printf '\n== %s  sonobuoy: %s ==\n' "$(date '+%H:%M:%S')" "$phase"
    "$SONOBUOY" status --kubeconfig "$KUBECONFIG_FILE" 2>/dev/null || true
    case "$phase" in complete) ok "run complete -- '$0 results' to summarize"; break ;;
                     failed) warn "run reported failed -- '$0 results' for detail"; break ;; esac
    sleep 15
  done
}

retrieve_results_via_websocket() {
  local outer="$RUNDIR/sonobuoy-splat.tar.gz"
  local member archive
  local -a members
  warn "Sonobuoy retrieve needs SPDY exec; falling back to kubectl WebSocket exec"
  kubectl --kubeconfig "$KUBECONFIG_FILE" --request-timeout=5m \
    exec -n sonobuoy sonobuoy -c kube-sonobuoy -- \
    /sonobuoy splat /tmp/sonobuoy > "$outer" || return 1

  mapfile -t members < <(tar -tzf "$outer") || return 1
  [ "${#members[@]}" -eq 1 ] || { warn "unexpected Sonobuoy splat archive contents"; return 1; }
  member="${members[0]}"
  case "$member" in
    */*|.|..|*[!A-Za-z0-9._-]*) warn "unsafe Sonobuoy result path: $member"; return 1 ;;
    *.tar.gz) ;;
    *) warn "unexpected Sonobuoy result filename: $member"; return 1 ;;
  esac

  archive="$RUNDIR/$member"
  tar -xOzf "$outer" "$member" > "$archive.part" || return 1
  tar -tzf "$archive.part" >/dev/null || return 1
  mv -f "$archive.part" "$archive"
  printf '%s\n' "$archive"
}

cmd_results() {
  [ -f "$KUBECONFIG_FILE" ] || die "no cluster; run '$0 up' first"
  local out
  if ! out="$("$SONOBUOY" retrieve --kubeconfig "$KUBECONFIG_FILE" "$RUNDIR" 2>"$RUNDIR/sonobuoy-retrieve.log")"; then
    out="$(retrieve_results_via_websocket)" || die "retrieve failed (run may be unfinished)"
  fi
  ok "results archive: $out"
  "$SONOBUOY" results "$out"
}

cmd_down() {
  log "stopping cluster (VMs kept)"
  tunnel_down
  if [ -f "$RUNDIR/vm-ips" ]; then while read -r ip; do [ -n "$ip" ] && guest_gr8s_teardown "$ip"; done < "$RUNDIR/vm-ips"; fi
  ok "cluster stopped. '$0 destroy' to remove the VMs."
}

cmd_destroy() {
  cmd_down
  for name in "${NODES[@]}"; do
    "${VIRSH[@]}" destroy "$name" 2>/dev/null || true
    "${VIRSH[@]}" undefine "$name" --remove-all-storage 2>/dev/null || true
  done
  ok "VMs destroyed."
}

cmd_run() { cmd_up; cmd_test; }

case "${1:-run}" in
  up) cmd_up ;; test) cmd_test ;; status) cmd_status ;; watch) cmd_watch ;;
  results) cmd_results ;; down) cmd_down ;; destroy) cmd_destroy ;; run) cmd_run ;;
  -h|--help|help) sed -n '2,33p' "$0" ;;
  *) die "unknown command '$1'; try: up test status watch results down destroy run" ;;
esac
