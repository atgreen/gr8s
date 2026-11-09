#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0

set -eu

purge=false
case ${1:-} in
  '') ;;
  --purge) purge=true ;;
  *)
    echo "usage: gr8s-uninstall.sh [--purge]" >&2
    exit 2
    ;;
esac
[ "$#" -le 1 ] || { echo "usage: gr8s-uninstall.sh [--purge]" >&2; exit 2; }

root=${GR8S_ROOT:-}
root=${root%/}
systemctl=${GR8S_SYSTEMCTL:-systemctl}
systemctl_timeout=${GR8S_SYSTEMCTL_TIMEOUT:-45}
killall_script=${GR8S_KILLALL_SCRIPT:-$root/usr/local/bin/gr8s-killall.sh}
findmnt=${GR8S_FINDMNT:-findmnt}
umount=${GR8S_UMOUNT:-umount}
state_root=$root/var/lib/gr8s
runtime_root=$root/run/gr8s
cgroup_root=${GR8S_CGROUP_ROOT:-/sys/fs/cgroup}

case "$systemctl_timeout" in
  *[!0-9]*|''|0)
    echo "gr8s-uninstall: GR8S_SYSTEMCTL_TIMEOUT must be a positive integer" >&2
    exit 2
    ;;
esac

fallback_cleanup() {
  cleanup_failed=false
  fallback_unit_has_processes() {
    fallback_control_group=$(timeout "$systemctl_timeout" "$systemctl" show -p ControlGroup --value "$1" 2>/dev/null) || {
      cleanup_failed=true
      return 0
    }
    case "$fallback_control_group" in
      /*) [ -s "$cgroup_root$fallback_control_group/cgroup.procs" ] ;;
      *) return 1 ;;
    esac
  }
  for service in gr8s-server.service gr8s-agent.service; do
    if load_state=$(timeout "$systemctl_timeout" "$systemctl" show -p LoadState --value "$service" 2>/dev/null); then
      if [ "$load_state" != not-found ]; then
        timeout "$systemctl_timeout" "$systemctl" stop "$service" >/dev/null 2>&1 || true
        timeout "$systemctl_timeout" "$systemctl" kill --signal=KILL --kill-who=all "$service" >/dev/null 2>&1 || true
        if fallback_unit_has_processes "$service"; then cleanup_failed=true; fi
      fi
    else
      cleanup_failed=true
    fi
  done

  mounts_raw=
  mounts_owned=
  cleanup_fallback_mount_lists() { rm -f "$mounts_raw" "$mounts_owned"; }
  trap cleanup_fallback_mount_lists EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  mounts_raw=$(mktemp "${TMPDIR:-/tmp}/gr8s-uninstall-mounts.XXXXXX")
  mounts_owned=$(mktemp "${TMPDIR:-/tmp}/gr8s-uninstall-owned.XXXXXX")
  if ! "$findmnt" -rn -o TARGET >"$mounts_raw" 2>/dev/null; then cleanup_failed=true; fi
  awk -v prefix="$state_root/" 'index($0, prefix) == 1 { print length($0) "\t" $0 }' "$mounts_raw" \
    | sort -k1,1nr -k2,2r | cut -f2- >"$mounts_owned"
  while IFS= read -r target; do
    [ -n "$target" ] || continue
    "$umount" -l -- "$target" >/dev/null 2>&1 || cleanup_failed=true
  done <"$mounts_owned"
  rm -f "$mounts_raw" "$mounts_owned"
  trap - EXIT HUP INT TERM
  rm -rf -- "$runtime_root"
  [ "$cleanup_failed" = false ]
}

if [ -e "$killall_script" ]; then
  if ! "$killall_script"; then
    echo "gr8s-uninstall: killall cleanup failed; installed artifacts were preserved" >&2
    exit 1
  fi
elif ! fallback_cleanup; then
  echo "gr8s-uninstall: fallback cleanup failed; installed artifacts were preserved" >&2
  exit 1
fi

systemctl_call() {
  if ! timeout "$systemctl_timeout" "$systemctl" "$@" >/dev/null 2>&1; then
    failed=true
  fi
}
failed=false
for service in gr8s-server.service gr8s-agent.service; do
  enablement=$root/etc/systemd/system/multi-user.target.wants/$service
  if load_state=$(timeout "$systemctl_timeout" "$systemctl" show -p LoadState --value "$service" 2>/dev/null); then
    if [ "$load_state" != not-found ] || [ -e "$enablement" ] || [ -L "$enablement" ]; then
      systemctl_call disable "$service"
    fi
  else
    failed=true
  fi
  rm -f -- "$enablement"
done
rmdir "$root/etc/systemd/system/multi-user.target.wants" 2>/dev/null || true

rm -f -- \
  "$root/etc/systemd/system/gr8s-server.service" \
  "$root/etc/systemd/system/gr8s-agent.service" \
  "$root/usr/local/bin/gr8s" \
  "$root/usr/local/bin/gr8s.previous" \
  "$root/usr/local/bin/gr8s-killall.sh" \
  "$root/usr/local/bin/gr8s-uninstall.sh"
rm -rf -- "$root/etc/gr8s"
systemctl_call daemon-reload

if [ "$purge" = true ]; then
  rm -rf -- "$root/var/lib/gr8s"
fi
[ "$failed" = false ]
