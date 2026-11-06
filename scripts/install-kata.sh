#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
#
# Stage a Kata Containers (microVM) runtime addon for a gr8s node: download the
# pinned kata-static release bundle, verify it against a pinned SHA-256, extract
# it into <state-directory>/runtime-addons/kata/, rewrite the bundle's absolute
# /opt/kata paths to the install location, and write the addon.json descriptor
# that gr8s's load-installed-runtime-addons checks at startup. gr8s then
# registers the io.containerd.kata.v2 CRI handler with a ConfigPath option and
# puts the shim on containerd's PATH. Pair with a RuntimeClass whose handler is
# "kata".
#
# Unlike gVisor, Kata does NOT publish a per-asset checksum next to the release,
# so the download is verified against a SHA-256 you pin here (trust-on-first-use):
# run once without KATA_STATIC_SHA256 set, the script prints the downloaded
# bundle's SHA-256 and stops; re-run with that value pinned to install.
#
# Usage: install-kata.sh STATE_DIRECTORY [version] [hypervisor]
#   STATE_DIRECTORY  the node's --state-directory (e.g. /var/lib/gr8s-helm)
#   version          a kata-containers release (default: 4.3.1)
#   hypervisor       qemu | clh | fc | dragonball (default: qemu)
# Environment:
#   KATA_STATIC_SHA256  pinned lowercase hex SHA-256 of the kata-static bundle;
#                       when unset the script runs in trust-on-first-use mode.
#   KATA_STATIC_BUNDLE  path to an already-downloaded kata-static bundle; when
#                       set the download is skipped and this file is used (still
#                       SHA-256 verified). Useful for air-gapped or cached runs.
set -eu

state_directory=${1:?usage: install-kata.sh STATE_DIRECTORY [version] [hypervisor]}
version=${2:-4.3.1}
hypervisor=${3:-qemu}

for tool in curl sha256sum sha512sum zstd tar sed; do
  command -v "$tool" >/dev/null 2>&1 || { echo "install-kata: missing required tool: $tool" >&2; exit 1; }
done

[ -e /dev/kvm ] || echo "install-kata: WARNING /dev/kvm is absent; Kata needs KVM (hardware or nested virt)" >&2

case $(uname -m) in
  x86_64)  arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) echo "install-kata: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

# Kata 4.x ships the Rust runtime (runtime-rs): the shim and its per-hypervisor
# configs live under runtime-rs/, and config basenames carry a -runtime-rs tag.
# Paths here are relative to <prefix>/share/defaults/kata-containers.
case $hypervisor in
  qemu)       config_rel_name=runtime-rs/configuration-qemu-runtime-rs.toml ;;
  clh)        config_rel_name=runtime-rs/configuration-clh-runtime-rs.toml ;;
  fc)         config_rel_name=runtime-rs/configuration-rs-fc.toml ;;
  dragonball) config_rel_name=runtime-rs/configuration-dragonball.toml ;;
  *) echo "install-kata: unsupported hypervisor: $hypervisor" >&2; exit 1 ;;
esac

bundle="kata-static-$version-$arch.tar.zst"
url="https://github.com/kata-containers/kata-containers/releases/download/$version/$bundle"
addon_directory="$state_directory/runtime-addons/kata"
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/gr8s-kata.XXXXXX")
trap 'rm -rf -- "$temporary_directory"' EXIT INT TERM

if [ -n "${KATA_STATIC_BUNDLE:-}" ]; then
  [ -f "$KATA_STATIC_BUNDLE" ] || { echo "install-kata: KATA_STATIC_BUNDLE not a file: $KATA_STATIC_BUNDLE" >&2; exit 1; }
  echo "install-kata: using pre-downloaded bundle $KATA_STATIC_BUNDLE"
  bundle_path=$KATA_STATIC_BUNDLE
else
  echo "install-kata: downloading Kata $version ($arch, ~1GB)"
  curl -fSL "$url" -o "$temporary_directory/$bundle"
  bundle_path="$temporary_directory/$bundle"
fi

actual_sha256=$(sha256sum "$bundle_path" | cut -d' ' -f1)
if [ -z "${KATA_STATIC_SHA256:-}" ]; then
  echo "install-kata: no KATA_STATIC_SHA256 pinned (trust-on-first-use)." >&2
  echo "install-kata: downloaded $bundle sha256 = $actual_sha256" >&2
  echo "install-kata: verify this out-of-band, then re-run with:" >&2
  echo "              KATA_STATIC_SHA256=$actual_sha256 $0 $state_directory $version $hypervisor" >&2
  exit 2
fi
if [ "$actual_sha256" != "$KATA_STATIC_SHA256" ]; then
  echo "install-kata: SHA-256 MISMATCH" >&2
  echo "  expected $KATA_STATIC_SHA256" >&2
  echo "  actual   $actual_sha256" >&2
  exit 1
fi
echo "install-kata: SHA-256 verified"

echo "install-kata: extracting into $addon_directory"
rm -rf -- "$addon_directory"
mkdir -p -- "$addon_directory"
zstd -dc "$bundle_path" | tar -x -C "$addon_directory"

# The bundle unpacks to <addon>/opt/kata/...; its configuration .toml files carry
# absolute /opt/kata paths. Rewrite them to the real install prefix so the shim,
# hypervisor, kernel and rootfs resolve from the relocatable addon directory.
# Rewrite every real config file (recurse into runtime-rs/, skip symlinks).
prefix="$addon_directory/opt/kata"
[ -d "$prefix" ] || { echo "install-kata: bundle did not contain opt/kata" >&2; exit 1; }
defaults_dir="$prefix/share/defaults/kata-containers"
find "$defaults_dir" -type f -name 'configuration*.toml' -exec sed -i "s|/opt/kata|$prefix|g" {} +

config_path="$defaults_dir/$config_rel_name"
[ -f "$config_path" ] || { echo "install-kata: missing $config_rel_name in bundle" >&2; exit 1; }

shim="$prefix/runtime-rs/bin/containerd-shim-kata-v2"
[ -f "$shim" ] || { echo "install-kata: bundle missing runtime-rs/bin/containerd-shim-kata-v2" >&2; exit 1; }
chmod +x "$shim"
# containerd execs the shim by name off the PATH that gr8s builds from the addon
# root (:bin-dir), so expose the shim there. It locates the hypervisor, kernel
# and rootfs from the rewritten ConfigPath, not from PATH.
ln -sf "opt/kata/runtime-rs/bin/containerd-shim-kata-v2" "$addon_directory/containerd-shim-kata-v2"

# Resolve the kernel and rootfs the chosen config actually references, so the
# addon re-verifies exactly what boots. Values look like: kernel = "<prefix>/..."
read_config_path() {
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"\\(.*\\)\".*/\\1/p" "$config_path" | head -n1
}
kernel=$(read_config_path kernel)
image=$(read_config_path image)
initrd=$(read_config_path initrd)

sha512_of() { sha512sum "$1" | cut -d' ' -f1; }

# binaries: the shim symlink at the addon root (what containerd execs).
# assets: the chosen config plus the kernel and whichever of image/initrd it uses
# (all re-checksum-verified by gr8s on every startup).
shim_sha=$(sha512_of "$addon_directory/containerd-shim-kata-v2")
config_rel="opt/kata/share/defaults/kata-containers/$config_rel_name"
config_sha=$(sha512_of "$config_path")

assets_json="{ \"path\": \"$config_rel\", \"sha512\": \"$config_sha\" }"
add_asset() {  # $1 absolute file path
  [ -n "$1" ] && [ -f "$1" ] || return 0
  rel=${1#"$addon_directory/"}
  assets_json="$assets_json,
    { \"path\": \"$rel\", \"sha512\": \"$(sha512_of "$1")\" }"
}
add_asset "$kernel"
add_asset "$image"
add_asset "$initrd"

cat > "$addon_directory/addon.json" <<JSON
{
  "name": "kata",
  "runtimeType": "io.containerd.kata.v2",
  "runtimeClass": "kata",
  "binaries": [
    { "path": "containerd-shim-kata-v2", "sha512": "$shim_sha" }
  ],
  "assets": [
    $assets_json
  ],
  "options": {
    "ConfigPath": "$config_path"
  }
}
JSON

# kata-static's qemu has a compiled-in firmware search path of /opt/kata/share
# (it is not expressible in configuration.toml, so the path rewrite above cannot
# reach it). The bundle must therefore be reachable at /opt/kata. Point it at
# this addon unless something else already owns that path. This makes /opt/kata
# a host-global pointer, so one node hosts one kata addon at a time.
if [ -e /opt/kata ] && [ ! -L /opt/kata ]; then
  echo "install-kata: WARNING /opt/kata exists and is not a symlink; leaving it as is." >&2
  echo "              qemu firmware will load only if /opt/kata already provides it." >&2
elif [ -L /opt/kata ] && [ "$(readlink /opt/kata)" != "$prefix" ]; then
  echo "install-kata: WARNING /opt/kata -> $(readlink /opt/kata) (a different kata install); leaving it." >&2
else
  ln -sfn "$prefix" /opt/kata
  echo "install-kata: linked /opt/kata -> $prefix (qemu firmware search path)"
fi

echo "install-kata: staged Kata ($hypervisor) runtime addon at $addon_directory"
echo "install-kata: restart gr8s and create a RuntimeClass with handler 'kata'"
