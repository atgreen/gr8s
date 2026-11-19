#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0

set -eu

root=${GR8S_ROOT:-}
root=${root%/}
systemctl=${GR8S_SYSTEMCTL:-systemctl}
findmnt=${GR8S_FINDMNT:-findmnt}
umount=${GR8S_UMOUNT:-umount}
systemctl_timeout=${GR8S_SYSTEMCTL_TIMEOUT:-45}
state_root=$root/var/lib/gr8s
runtime_root=$root/run/gr8s
cgroup_root=${GR8S_CGROUP_ROOT:-/sys/fs/cgroup}
proc_root=${GR8S_PROC_ROOT:-/proc}

case "$systemctl_timeout" in
  *[!0-9]*|''|0)
    echo "gr8s-killall: GR8S_SYSTEMCTL_TIMEOUT must be a positive integer" >&2
    exit 2
    ;;
esac

failed=false
unit_has_processes() {
  control_group=$(timeout "$systemctl_timeout" "$systemctl" show -p ControlGroup --value "$1" 2>/dev/null) || {
    failed=true
    return 0
  }
  case "$control_group" in
    /*) [ -s "$cgroup_root$control_group/cgroup.procs" ] ;;
    *) return 1 ;;
  esac
}
# Containers run in cgroups of their own, outside the service units, and outlive
# their shims. Find them through the shims gr8s started -- those run from its
# state tree -- while the shims are still their parents.
workload_cgroups=
for cmdline in "$proc_root"/[0-9]*/cmdline; do
  [ -r "$cmdline" ] || continue
  command=$(tr '\0' '\n' <"$cmdline" 2>/dev/null | sed -n 1p) || continue
  case "$command" in
    "$state_root"/*/containerd-shim-*) ;;
    *) continue ;;
  esac
  shim=${cmdline%/cmdline}
  for child in $(cat "$shim"/task/*/children 2>/dev/null); do
    group=$(sed -n 's/^0:://p' "$proc_root/$child/cgroup" 2>/dev/null) || continue
    case "$group" in
      ''|/) continue ;;
    esac
    workload_cgroups="$workload_cgroups
$group"
  done
done

for service in gr8s-server.service gr8s-agent.service; do
  if load_state=$(timeout "$systemctl_timeout" "$systemctl" show -p LoadState --value "$service" 2>/dev/null); then
    if [ "$load_state" != not-found ]; then
      timeout "$systemctl_timeout" "$systemctl" stop "$service" >/dev/null 2>&1 || true
      timeout "$systemctl_timeout" "$systemctl" kill --signal=KILL --kill-who=all "$service" >/dev/null 2>&1 || true
      if unit_has_processes "$service"; then failed=true; fi
    fi
  else
    failed=true
  fi
done

# The shims are gone; end the containers they left behind, which would otherwise
# keep running under init and hold their host ports against the next start.
while IFS= read -r group; do
  [ -n "$group" ] || continue
  [ -d "$cgroup_root$group" ] || continue
  if [ -e "$cgroup_root$group/cgroup.kill" ]; then
    echo 1 >"$cgroup_root$group/cgroup.kill" 2>/dev/null || failed=true
  else
    while IFS= read -r pid; do
      kill -KILL "$pid" 2>/dev/null || true
    done <"$cgroup_root$group/cgroup.procs"
  fi
done <<EOF
$workload_cgroups
EOF

# Detach only mounts rooted in gr8s's persistent tree, deepest first. The tree
# itself is data and is deliberately never removed here.
mounts_raw=
mounts_owned=
cleanup_mount_lists() { rm -f "$mounts_raw" "$mounts_owned"; }
trap cleanup_mount_lists EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
mounts_raw=$(mktemp "${TMPDIR:-/tmp}/gr8s-mounts.XXXXXX")
mounts_owned=$(mktemp "${TMPDIR:-/tmp}/gr8s-owned-mounts.XXXXXX")
if ! "$findmnt" -rn -o TARGET >"$mounts_raw" 2>/dev/null; then failed=true; fi
awk -v prefix="$state_root/" 'index($0, prefix) == 1 { print length($0) "\t" $0 }' "$mounts_raw" \
  | sort -k1,1nr -k2,2r | cut -f2- >"$mounts_owned"
while IFS= read -r target; do
  [ -n "$target" ] || continue
  if ! "$umount" -l -- "$target" >/dev/null 2>&1; then failed=true; fi
done <"$mounts_owned"

rm -rf -- "$runtime_root"
cleanup_mount_lists
trap - EXIT HUP INT TERM
[ "$failed" = false ]
