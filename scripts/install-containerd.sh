#!/bin/sh
set -eu

containerd_version=2.4.2
containerd_revision=b7a25261e029d68978bbf290df0a62fc819b3c51
runc_version=1.5.2
cni_plugins_version=1.9.1
destination=${1:-build/containerd}
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(dirname -- "$script_directory")

case $(uname -m) in
  x86_64)
    architecture=amd64
    runc_checksum=599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488
    ;;
  aarch64)
    architecture=arm64
    runc_checksum=d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0
    ;;
  *)
    echo "unsupported containerd architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

runc_asset="runc.$architecture"
runc_url="https://github.com/opencontainers/runc/releases/download/v$runc_version/$runc_asset"
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/gr8s-containerd.XXXXXX")
trap 'rm -rf -- "$temporary_directory"' EXIT INT TERM

for command in curl sha256sum awk grep install go readelf sbcl; do
  if ! command -v "$command" >/dev/null; then
    echo "missing required build command: $command" >&2
    exit 1
  fi
done

mkdir -p "$destination/bin"

static_binary_p() {
  [ -x "$1" ] || return 1
  if readelf -l "$1" | grep -q 'INTERP'; then
    return 1
  fi
  if readelf -d "$1" 2>/dev/null | grep -q '(NEEDED)'; then
    return 1
  fi
  return 0
}

cni_plugin_p() {
  static_binary_p "$1" &&
    go version -m "$1" | grep -Fq "github.com/containernetworking/plugins" &&
    go version -m "$1" | grep -Fq "v$cni_plugins_version"
}

if ! { static_binary_p "$destination/bin/containerd" &&
       static_binary_p "$destination/bin/containerd-shim-runc-v2" &&
       "$destination/bin/containerd" --version | grep -q "$containerd_version" &&
       "$destination/bin/containerd-shim-runc-v2" --version 2>&1 |
         grep -q "Version:  $containerd_version"; }; then
  go_bin="$temporary_directory/go-bin"
  mkdir -p "$go_bin"
  package=github.com/containerd/containerd/v2
  ldflags="-s -w -X $package/version.Version=$containerd_version -X $package/version.Revision=$containerd_revision -X $package/version.Package=$package"
  CGO_ENABLED=0 GOBIN="$go_bin" go install -trimpath \
    -tags 'urfave_cli_no_docs osusergo netgo static_build' \
    -ldflags "$ldflags" \
    "$package/cmd/containerd@v$containerd_version"
  CGO_ENABLED=0 GOBIN="$go_bin" go install -trimpath \
    -tags 'urfave_cli_no_docs osusergo netgo static_build no_grpc' \
    -ldflags "$ldflags" \
    "$package/cmd/containerd-shim-runc-v2@v$containerd_version"
  install -m 0755 "$go_bin/containerd" "$destination/bin/containerd"
  install -m 0755 "$go_bin/containerd-shim-runc-v2" \
    "$destination/bin/containerd-shim-runc-v2"
fi

if ! { [ -x "$destination/bin/runc" ] &&
       "$destination/bin/runc" --version | grep -q "runc version $runc_version"; }; then
  curl --fail --location --output "$temporary_directory/$runc_asset" "$runc_url"
  actual_checksum=$(sha256sum "$temporary_directory/$runc_asset" | awk '{print $1}')
  if [ "$actual_checksum" != "$runc_checksum" ]; then
    echo "runc checksum mismatch: expected $runc_checksum, got $actual_checksum" >&2
    exit 1
  fi
  install -m 0755 "$temporary_directory/$runc_asset" "$destination/bin/runc"
fi

if ! { cni_plugin_p "$destination/bin/bridge" &&
       cni_plugin_p "$destination/bin/host-local" &&
       cni_plugin_p "$destination/bin/loopback" &&
       cni_plugin_p "$destination/bin/firewall"; }; then
  go_bin="$temporary_directory/cni-bin"
  mkdir -p "$go_bin"
  cni_module=github.com/containernetworking/plugins
  CGO_ENABLED=0 GOBIN="$go_bin" go install -trimpath \
    "$cni_module/plugins/main/bridge@v$cni_plugins_version" \
    "$cni_module/plugins/ipam/host-local@v$cni_plugins_version" \
    "$cni_module/plugins/main/loopback@v$cni_plugins_version" \
    "$cni_module/plugins/meta/firewall@v$cni_plugins_version"
  install -m 0755 "$go_bin/bridge" "$destination/bin/bridge"
  install -m 0755 "$go_bin/host-local" "$destination/bin/host-local"
  install -m 0755 "$go_bin/loopback" "$destination/bin/loopback"
  install -m 0755 "$go_bin/firewall" "$destination/bin/firewall"
fi

# The egress guard is JIT-compiled in-process by the agent; no eBPF ELF object
# is built or installed into the runtime payload.

"$destination/bin/containerd" --version
"$destination/bin/containerd-shim-runc-v2" --version
"$destination/bin/runc" --version
CNI_COMMAND=VERSION "$destination/bin/bridge"
CNI_COMMAND=VERSION "$destination/bin/host-local"
CNI_COMMAND=VERSION "$destination/bin/loopback"
CNI_COMMAND=VERSION "$destination/bin/firewall"
"$(dirname "$0")/verify-static-runtime.sh" "$destination"
