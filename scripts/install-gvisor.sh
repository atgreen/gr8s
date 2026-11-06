#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
#
# Stage a gVisor (runsc) runtime addon for a gr8s node: download the pinned
# release tarball, verify it against gVisor's published SHA-512, extract it into
# <state-directory>/runtime-addons/gvisor/, and write the addon.json descriptor
# that gr8s's load-installed-runtime-addons checks at startup. gr8s then
# registers the runsc CRI handler and puts this directory on containerd's shim
# PATH. Pair with a RuntimeClass whose handler is "runsc".
#
# Usage: install-gvisor.sh STATE_DIRECTORY [release]
#   STATE_DIRECTORY  the node's --state-directory (e.g. /var/lib/gr8s-helm)
#   release          a gVisor release id (default: latest)
set -eu

state_directory=${1:?usage: install-gvisor.sh STATE_DIRECTORY [release]}
release=${2:-latest}

for tool in curl sha512sum zstd tar; do
  command -v "$tool" >/dev/null 2>&1 || { echo "install-gvisor: missing required tool: $tool" >&2; exit 1; }
done

case $(uname -m) in
  x86_64)  arch=x86_64 ;;
  aarch64) arch=aarch64 ;;
  *) echo "install-gvisor: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

base_url="https://storage.googleapis.com/gvisor/releases/release/$release/$arch"
addon_directory="$state_directory/runtime-addons/gvisor"
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/gr8s-gvisor.XXXXXX")
trap 'rm -rf -- "$temporary_directory"' EXIT INT TERM

echo "install-gvisor: downloading gVisor ($release, $arch)"
curl -fsSL "$base_url/gvisor.tar.zstd"        -o "$temporary_directory/gvisor.tar.zstd"
curl -fsSL "$base_url/gvisor.tar.zstd.sha512" -o "$temporary_directory/gvisor.tar.zstd.sha512"

# gVisor publishes "<sha512>  gvisor.tar.zstd"; verify against it in place.
echo "install-gvisor: verifying SHA-512"
( cd "$temporary_directory" && sha512sum -c gvisor.tar.zstd.sha512 ) \
  || { echo "install-gvisor: SHA-512 verification FAILED" >&2; exit 1; }

echo "install-gvisor: extracting into $addon_directory"
rm -rf -- "$addon_directory"
mkdir -p -- "$addon_directory"
zstd -dc "$temporary_directory/gvisor.tar.zstd" | tar -x -C "$addon_directory"

for binary in runsc containerd-shim-runsc-v1; do
  [ -f "$addon_directory/$binary" ] || { echo "install-gvisor: tarball missing $binary" >&2; exit 1; }
  chmod +x "$addon_directory/$binary"
done

# The descriptor lists the binaries gr8s re-verifies on every startup. Only the
# runtime entrypoints are listed; the rest of the bundle (the sentry etc.) was
# covered by the tarball SHA-512 already checked above and is loaded by runsc.
shim_sha=$(sha512sum "$addon_directory/containerd-shim-runsc-v1" | cut -d' ' -f1)
runsc_sha=$(sha512sum "$addon_directory/runsc" | cut -d' ' -f1)
cat > "$addon_directory/addon.json" <<JSON
{
  "name": "runsc",
  "runtimeType": "io.containerd.runsc.v1",
  "runtimeClass": "gvisor",
  "binaries": [
    { "path": "containerd-shim-runsc-v1", "sha512": "$shim_sha" },
    { "path": "runsc", "sha512": "$runsc_sha" }
  ]
}
JSON

echo "install-gvisor: staged gVisor runsc addon at $addon_directory"
echo "install-gvisor: restart gr8s and create a RuntimeClass with handler 'runsc'"
