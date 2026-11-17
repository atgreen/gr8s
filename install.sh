#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0

set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
asset_root=${INSTALL_GR8S_ASSET_ROOT:-$script_directory}
killall_source=$asset_root/gr8s-killall.sh
uninstall_source=$asset_root/gr8s-uninstall.sh
if [ ! -f "$killall_source" ] || [ ! -f "$uninstall_source" ]; then
  echo "install-gr8s: lifecycle tools are missing from INSTALL_GR8S_ASSET_ROOT" >&2
  exit 2
fi

mode=${INSTALL_GR8S_MODE:-server}
case "$mode" in
  server) command=serve ;;
  agent) command=agent ;;
  *)
    echo "install-gr8s: INSTALL_GR8S_MODE must be server or agent" >&2
    exit 2
    ;;
esac

expected_sha256=${INSTALL_GR8S_SHA256:-}
if [ -n "$expected_sha256" ]; then
  case "$expected_sha256" in
    *[!0123456789abcdefABCDEF]*|'')
      echo "install-gr8s: INSTALL_GR8S_SHA256 must be a 64-character hexadecimal SHA-256" >&2
      exit 2
      ;;
  esac
  if [ "${#expected_sha256}" -ne 64 ]; then
    echo "install-gr8s: INSTALL_GR8S_SHA256 must be a 64-character hexadecimal SHA-256" >&2
    exit 2
  fi
  expected_sha256=$(printf '%s' "$expected_sha256" | tr 'ABCDEF' 'abcdef')
fi

source_binary=${INSTALL_GR8S_BINARY:-}
download_temporary=
cleanup_acquisition() {
  [ -z "$download_temporary" ] || rm -f "$download_temporary"
}
if [ -n "$source_binary" ]; then
  if [ ! -f "$source_binary" ] || [ ! -x "$source_binary" ]; then
    echo "install-gr8s: INSTALL_GR8S_BINARY must name an executable gr8s binary" >&2
    exit 2
  fi
else
  if [ -z "$expected_sha256" ]; then
    echo "install-gr8s: INSTALL_GR8S_SHA256 is required for release downloads" >&2
    exit 2
  fi
  download_url=${INSTALL_GR8S_URL:-}
  if [ -z "$download_url" ]; then
    version=${INSTALL_GR8S_VERSION:-}
    if [ -z "$version" ]; then
      echo "install-gr8s: set INSTALL_GR8S_URL or INSTALL_GR8S_VERSION for release downloads" >&2
      exit 2
    fi
    architecture=${INSTALL_GR8S_ARCH:-$(uname -m)}
    case "$architecture" in
      x86_64|amd64) release_architecture=amd64 ;;
      aarch64|arm64) release_architecture=arm64 ;;
      *)
        echo "install-gr8s: unsupported release architecture: $architecture" >&2
        exit 2
        ;;
    esac
    release_base=${INSTALL_GR8S_RELEASE_BASE:-https://github.com/atgreen/gr8s/releases/download}
    release_base=${release_base%/}
    download_url=$release_base/$version/gr8s-linux-$release_architecture
  fi
  curl_command=${INSTALL_GR8S_CURL:-curl}
  trap cleanup_acquisition EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  download_temporary=$(mktemp "${TMPDIR:-/tmp}/install-gr8s.download.XXXXXX")
  if ! "$curl_command" --fail --location --retry 3 --output "$download_temporary" "$download_url"; then
    echo "install-gr8s: failed to download $download_url" >&2
    exit 1
  fi
  source_binary=$download_temporary
fi

exec_args=${INSTALL_GR8S_EXEC_ARGS:-}
if [ -z "$exec_args" ]; then
  echo "install-gr8s: INSTALL_GR8S_EXEC_ARGS must not be empty" >&2
  exit 2
fi

carriage_return=$(printf '\r')
tab=$(printf '\t')
newline='
'
case "$exec_args" in
  *"'"*|*'"'*|*\\*|*"$carriage_return"*|*"$tab"*|*"$newline"*)
    echo "install-gr8s: INSTALL_GR8S_EXEC_ARGS contains quoting or control characters that cannot be persisted safely" >&2
    exit 2
    ;;
esac

case "$exec_args" in
  "$command"|"$command "*) ;;
  *)
    echo "install-gr8s: INSTALL_GR8S_EXEC_ARGS must begin with $command" >&2
    exit 2
    ;;
esac

root=${INSTALL_GR8S_ROOT:-}
root=${root%/}
systemctl=${INSTALL_GR8S_SYSTEMCTL:-systemctl}
stage_copy=${INSTALL_GR8S_STAGE_COPY:-cp}
ready_timeout=${INSTALL_GR8S_READY_TIMEOUT:-30}
stability_window=${INSTALL_GR8S_STABILITY_WINDOW:-2}
systemctl_timeout=${INSTALL_GR8S_SYSTEMCTL_TIMEOUT:-45}
case "$ready_timeout" in
  *[!0-9]*|'')
    echo "install-gr8s: INSTALL_GR8S_READY_TIMEOUT must be a non-negative integer" >&2
    exit 2
    ;;
esac
case "$systemctl_timeout" in
  *[!0-9]*|''|0)
    echo "install-gr8s: INSTALL_GR8S_SYSTEMCTL_TIMEOUT must be a positive integer" >&2
    exit 2
    ;;
esac
case "$stability_window" in
  *[!0-9]*|'')
    echo "install-gr8s: INSTALL_GR8S_STABILITY_WINDOW must be a non-negative integer" >&2
    exit 2
    ;;
esac
systemctl_call() {
  timeout "$systemctl_timeout" "$systemctl" "$@"
}
activation_deadline=0
start_activation_deadline() {
  window=$ready_timeout
  [ "$window" -gt 0 ] || window=1
  activation_deadline=$(($(date +%s) + window))
}
systemctl_before_deadline() {
  now=$(date +%s)
  remaining=$((activation_deadline - now))
  [ "$remaining" -gt 0 ] || return 124
  timeout "$remaining" "$systemctl" "$@"
}
service_stable_within() {
  checked_service=$1
  checked_window=$2
  checked_deadline=$(($(date +%s) + checked_window))
  checked_stable_since=
  while :; do
    checked_now=$(date +%s)
    checked_remaining=$((checked_deadline - checked_now))
    [ "$checked_remaining" -gt 0 ] || return 1
    if timeout "$checked_remaining" "$systemctl" is-active --quiet "$checked_service"; then
      [ -n "$checked_stable_since" ] || checked_stable_since=$checked_now
      if [ $((checked_now - checked_stable_since)) -ge "$stability_window" ]; then
        return 0
      fi
    else
      checked_stable_since=
    fi
    sleep 1
  done
}
binary_directory=$root/usr/local/bin
config_directory=$root/etc/gr8s
unit_directory=$root/etc/systemd/system
binary_path=$binary_directory/gr8s
killall_path=$binary_directory/gr8s-killall.sh
uninstall_path=$binary_directory/gr8s-uninstall.sh
environment_path=$config_directory/$mode.env
unit_path=$unit_directory/gr8s-$mode.service
service=gr8s-$mode.service
previous_binary_path=$binary_path.previous
if [ "$mode" = server ]; then
  other_mode=agent
else
  other_mode=server
fi
other_environment_path=$config_directory/$other_mode.env
other_unit_path=$unit_directory/gr8s-$other_mode.service
other_service=gr8s-$other_mode.service

if [ ! -e "$binary_path" ] && {
  [ -e "$killall_path" ] || [ -e "$uninstall_path" ] ||
  [ -e "$environment_path" ] || [ -e "$unit_path" ] ||
  [ -e "$other_environment_path" ] || [ -e "$other_unit_path" ];
}; then
  echo "install-gr8s: existing lifecycle artifacts without gr8s form an incomplete installation" >&2
  exit 1
fi

root_created=false
usr_created=false
usr_local_created=false
binary_directory_created=false
etc_created=false
config_directory_created=false
etc_systemd_created=false
unit_directory_created=false
[ -d "$root" ] || root_created=true
[ -d "$root/usr" ] || usr_created=true
[ -d "$root/usr/local" ] || usr_local_created=true
[ -d "$binary_directory" ] || binary_directory_created=true
[ -d "$root/etc" ] || etc_created=true
[ -d "$config_directory" ] || config_directory_created=true
[ -d "$root/etc/systemd" ] || etc_systemd_created=true
[ -d "$unit_directory" ] || unit_directory_created=true
cleanup_new_directories() {
  [ "$unit_directory_created" = false ] || rmdir "$unit_directory" 2>/dev/null || true
  [ "$etc_systemd_created" = false ] || rmdir "$root/etc/systemd" 2>/dev/null || true
  [ "$config_directory_created" = false ] || rmdir "$config_directory" 2>/dev/null || true
  [ "$etc_created" = false ] || rmdir "$root/etc" 2>/dev/null || true
  [ "$binary_directory_created" = false ] || rmdir "$binary_directory" 2>/dev/null || true
  [ "$usr_local_created" = false ] || rmdir "$root/usr/local" 2>/dev/null || true
  [ "$usr_created" = false ] || rmdir "$root/usr" 2>/dev/null || true
  [ "$root_created" = false ] || rmdir "$root" 2>/dev/null || true
}
cleanup_before_directories() {
  cleanup_new_directories
  cleanup_acquisition
}
trap cleanup_before_directories EXIT
mkdir -p "$binary_directory" "$config_directory" "$unit_directory"

binary_temporary=$binary_path.tmp.$$
killall_temporary=$killall_path.tmp.$$
uninstall_temporary=$uninstall_path.tmp.$$
environment_temporary=$environment_path.tmp.$$
unit_temporary=$unit_path.tmp.$$
rollback_environment=$environment_path.rollback.$$
rollback_unit=$unit_path.rollback.$$
rollback_other_environment=$other_environment_path.rollback.$$
rollback_other_unit=$other_unit_path.rollback.$$
rollback_previous=$previous_binary_path.rollback.$$
rollback_killall=$killall_path.rollback.$$
rollback_uninstall=$uninstall_path.rollback.$$
previous_binary_temporary=$previous_binary_path.tmp.$$
cleanup_temporaries() {
  rm -f "$binary_temporary" "$killall_temporary" "$uninstall_temporary" \
    "$environment_temporary" "$unit_temporary" \
    "$rollback_environment" "$rollback_unit" "$rollback_other_environment" \
    "$rollback_other_unit" "$rollback_previous" "$rollback_killall" \
    "$rollback_uninstall" "$previous_binary_temporary"
}
cleanup_before_publish() {
  cleanup_temporaries
  cleanup_new_directories
  cleanup_acquisition
}
trap cleanup_before_publish EXIT

"$stage_copy" -f "$source_binary" "$binary_temporary"
chmod 0755 "$binary_temporary"
"$stage_copy" -f "$killall_source" "$killall_temporary"
chmod 0755 "$killall_temporary"
"$stage_copy" -f "$uninstall_source" "$uninstall_temporary"
chmod 0755 "$uninstall_temporary"
if [ -n "$expected_sha256" ]; then
  actual_sha256=$(sha256sum "$binary_temporary" | awk '{print $1}')
  if [ "$actual_sha256" != "$expected_sha256" ]; then
    echo "install-gr8s: SHA-256 mismatch for staged gr8s binary" >&2
    exit 1
  fi
fi

umask 077
printf 'GR8S_EXEC_ARGS=%s\n' "$exec_args" >"$environment_temporary"
chmod 0600 "$environment_temporary"

cat >"$unit_temporary" <<EOF
[Unit]
Description=gr8s Kubernetes $mode
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=notify
EnvironmentFile=/etc/gr8s/$mode.env
ExecStart=/usr/local/bin/gr8s \$GR8S_EXEC_ARGS
Restart=always
RestartSec=5s
KillMode=mixed
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$unit_temporary"

upgrading=false
transitioning=false
previous_existed=false
killall_existed=false
uninstall_existed=false
if [ -e "$binary_path" ]; then
  if [ -f "$environment_path" ] && [ -f "$unit_path" ]; then
    upgrading=true
    cp -f "$environment_path" "$rollback_environment"
    cp -f "$unit_path" "$rollback_unit"
  elif [ -f "$other_environment_path" ] && [ -f "$other_unit_path" ]; then
    transitioning=true
    cp -f "$other_environment_path" "$rollback_other_environment"
    cp -f "$other_unit_path" "$rollback_other_unit"
  else
    echo "install-gr8s: existing installation is incomplete; refusing an unsafe upgrade" >&2
    exit 1
  fi
  if [ -f "$previous_binary_path" ]; then
    previous_existed=true
    cp -f "$previous_binary_path" "$rollback_previous"
  fi
  if [ -f "$killall_path" ]; then
    killall_existed=true
    cp -f "$killall_path" "$rollback_killall"
  fi
  if [ -f "$uninstall_path" ]; then
    uninstall_existed=true
    cp -f "$uninstall_path" "$rollback_uninstall"
  fi
  cp -f "$binary_path" "$previous_binary_temporary"
  chmod 0755 "$previous_binary_temporary"
  mv -f "$previous_binary_temporary" "$previous_binary_path"
fi

rollback_upgrade() {
  echo "install-gr8s: upgraded service activation failed; rolling back" >&2
  rollback_failed=false
  cp -f "$previous_binary_path" "$binary_temporary"
  chmod 0755 "$binary_temporary"
  mv -f "$binary_temporary" "$binary_path"
  if [ "$killall_existed" = true ]; then
    cp -f "$rollback_killall" "$killall_temporary"
    chmod 0755 "$killall_temporary"
    mv -f "$killall_temporary" "$killall_path"
  else
    rm -f "$killall_path"
  fi
  if [ "$uninstall_existed" = true ]; then
    cp -f "$rollback_uninstall" "$uninstall_temporary"
    chmod 0755 "$uninstall_temporary"
    mv -f "$uninstall_temporary" "$uninstall_path"
  else
    rm -f "$uninstall_path"
  fi
  if [ "$transitioning" = true ]; then
    systemctl_call stop "$service" || rollback_failed=true
    systemctl_call disable "$service" || rollback_failed=true
    rm -f "$environment_path" "$unit_path"
    cp -f "$rollback_other_environment" "$other_environment_path"
    chmod 0600 "$other_environment_path"
    cp -f "$rollback_other_unit" "$other_unit_path"
    chmod 0644 "$other_unit_path"
  else
    cp -f "$rollback_environment" "$environment_temporary"
    chmod 0600 "$environment_temporary"
    mv -f "$environment_temporary" "$environment_path"
    cp -f "$rollback_unit" "$unit_temporary"
    chmod 0644 "$unit_temporary"
    mv -f "$unit_temporary" "$unit_path"
  fi
  if [ "$previous_existed" = true ]; then
    cp -f "$rollback_previous" "$previous_binary_temporary"
    chmod 0755 "$previous_binary_temporary"
    mv -f "$previous_binary_temporary" "$previous_binary_path"
  else
    rm -f "$previous_binary_path"
  fi
  systemctl_call daemon-reload || rollback_failed=true
  if [ "$transitioning" = true ]; then
    systemctl_call enable "$other_service" || rollback_failed=true
    systemctl_call restart "$other_service" || rollback_failed=true
    recovery_service=$other_service
  else
    systemctl_call restart "$service" || rollback_failed=true
    recovery_service=$service
  fi
  if ! service_stable_within "$recovery_service" "$systemctl_timeout"; then
    rollback_failed=true
  fi
  if [ "$rollback_failed" = true ]; then
    echo "install-gr8s: rollback incomplete; restored files require operator recovery" >&2
  fi
  published=false
}

remove_failed_fresh_install() {
  systemctl_call stop "$service" || true
  systemctl_call disable "$service" || true
  rm -f "$binary_path" "$environment_path" "$unit_path" "$previous_binary_path"
  rm -f "$killall_path" "$uninstall_path"
  systemctl_call daemon-reload || true
  published=false
}

fail_after_publish() {
  if [ "$upgrading" = true ] || [ "$transitioning" = true ]; then
    rollback_upgrade
  else
    remove_failed_fresh_install
  fi
}

published=false
transaction_exit() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$status" -ne 0 ] && [ "$published" = true ]; then
    fail_after_publish
  fi
  cleanup_temporaries
  cleanup_acquisition
  if [ "$status" -ne 0 ]; then cleanup_new_directories; fi
  exit "$status"
}
trap transaction_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

published=true
mv -f "$binary_temporary" "$binary_path"
mv -f "$killall_temporary" "$killall_path"
mv -f "$uninstall_temporary" "$uninstall_path"
mv -f "$environment_temporary" "$environment_path"
mv -f "$unit_temporary" "$unit_path"
start_activation_deadline

if [ -e "$other_unit_path" ] || [ -e "$other_environment_path" ]; then
  if ! systemctl_before_deadline stop "$other_service"; then
    fail_after_publish
    exit 1
  fi
  if ! systemctl_before_deadline disable "$other_service"; then
    fail_after_publish
    exit 1
  fi
  rm -f "$other_unit_path" "$other_environment_path"
fi

if ! systemctl_before_deadline daemon-reload; then
  fail_after_publish
  exit 1
fi
if ! systemctl_before_deadline enable "$service"; then
  fail_after_publish
  exit 1
fi
if ! systemctl_before_deadline restart "$service"; then
  fail_after_publish
  exit 1
fi

stable_since=
while :; do
  if systemctl_before_deadline is-active --quiet "$service"; then
    now=$(date +%s)
    [ -n "$stable_since" ] || stable_since=$now
    if [ $((now - stable_since)) -ge "$stability_window" ]; then
      break
    fi
  else
    stable_since=
  fi
  if [ "$(date +%s)" -ge "$activation_deadline" ]; then
    fail_after_publish
    exit 1
  fi
  sleep 1
done

trap - EXIT HUP INT TERM
published=false
cleanup_temporaries
cleanup_acquisition
exit 0
