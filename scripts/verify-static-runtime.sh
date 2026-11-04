#!/bin/sh
set -eu

runtime_directory=${1:?usage: verify-static-runtime.sh RUNTIME_DIRECTORY}

for command in readelf grep; do
  command -v "$command" >/dev/null
done

for executable in containerd containerd-shim-runc-v2 runc \
                  bridge host-local loopback firewall; do
  path="$runtime_directory/bin/$executable"
  if [ ! -x "$path" ]; then
    echo "missing runtime executable: $path" >&2
    exit 1
  fi
  if readelf -l "$path" | grep -q 'INTERP'; then
    echo "$executable has a dynamic program interpreter" >&2
    exit 1
  fi
  if readelf -d "$path" 2>/dev/null | grep -q '(NEEDED)'; then
    echo "$executable has shared-library dependencies" >&2
    exit 1
  fi
done

# The egress guard is JIT-compiled in-process by the agent, not shipped as an
# eBPF ELF object, so there is no Whistler object to verify here.

echo "gr8s runtime payload is statically linked"
