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

whistler_object="$runtime_directory/bin/gr8s-whistler.bpf.o"
if [ ! -r "$whistler_object" ]; then
  echo "missing Whistler program: $whistler_object" >&2
  exit 1
fi
if ! readelf -h "$whistler_object" | grep -q 'Machine:.*Linux BPF'; then
  echo "Whistler program is not an eBPF ELF object" >&2
  exit 1
fi
if ! readelf -S "$whistler_object" | grep -q 'classifier'; then
  echo "Whistler program has no classifier section" >&2
  exit 1
fi
if ! readelf -S "$whistler_object" | grep -q '\.maps'; then
  echo "Whistler program has no eBPF maps section" >&2
  exit 1
fi

echo "gr8s runtime payload is statically linked"
