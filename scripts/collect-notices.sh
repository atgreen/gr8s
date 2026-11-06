#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
#
# Collect every third-party license/notice text gr8s ships into one NOTICES
# document: gr8s's own NOTICE, the embedded/linked/optional native components
# (which are not Common Lisp systems), and ocicl's collection of every vendored
# Common Lisp dependency's license. Regenerate with `make notices`; the native
# build embeds a gzip of this file, and `gr8s notices` prints it.
#
# Usage: collect-notices.sh [OUTPUT]   (default: NOTICES)
set -eu

output=${1:-NOTICES}
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"
command -v ocicl >/dev/null 2>&1 || { echo "collect-notices: ocicl not found" >&2; exit 1; }

{
  cat NOTICE
  printf '\n\n'
  printf '================================================================================\n'
  printf 'EMBEDDED, LINKED, AND OPTIONAL NATIVE COMPONENTS\n'
  printf '================================================================================\n'
  printf '\nNot Common Lisp systems, so listed here rather than by ocicl below.\n\n'
  cat <<'COMPONENTS'
containerd, containerd-shim-runc-v2  (embedded)  -  Apache-2.0
    Copyright The containerd Authors
    https://github.com/containerd/containerd

runc  (embedded)  -  Apache-2.0
    Copyright The runc / Open Container Initiative Authors
    https://github.com/opencontainers/runc

CNI plugins: bridge, host-local, loopback, firewall  (embedded)  -  Apache-2.0
    Copyright The CNI Authors
    https://github.com/containernetworking/plugins

libzstd  (linked at runtime)  -  BSD-3-Clause
    Copyright Meta Platforms, Inc.
    https://github.com/facebook/zstd

gVisor runsc  (optional, fetched by 'gr8s runtime install gvisor')  -  Apache-2.0
    Copyright The gVisor Authors
    https://github.com/google/gvisor

Kata Containers  (optional, fetched by 'gr8s runtime install kata')  -  Apache-2.0
    Copyright The Kata Containers Authors
    https://github.com/kata-containers/kata-containers
COMPONENTS
  printf '\n\n'
  ocicl collect-licenses
} > "$output"

echo "collect-notices: wrote $output ($(wc -l < "$output") lines, $(wc -c < "$output") bytes)"
