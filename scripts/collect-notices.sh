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
project_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
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

Headlamp  (embedded web UI, served by 'gr8s dashboard')  -  Apache-2.0
    Copyright The Headlamp Authors
    https://github.com/kubernetes-sigs/headlamp
    The frontend bundles third-party JavaScript whose own license texts
    are reproduced in the EMBEDDED WEB UI section below.

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

  # Third-party license texts the Headlamp webpack build emits next to the
  # bundled JavaScript (one *.LICENSE.txt per chunk; many are byte-identical,
  # so reproduce each distinct text once). Collected from the embedded frontend
  # tree -- the exact bytes `gr8s dashboard` serves -- so the attribution
  # matches what ships. Absent when the dashboard assets are not vendored.
  assets_dir="$project_root/assets/dashboard"
  license_text() {
    case "$1" in
      *.gz) gzip -cd -- "$1" ;;
      *) cat -- "$1" ;;
    esac
  }
  if [ -n "$(find "$assets_dir" -type f \( -name '*.LICENSE.txt' -o -name '*.LICENSE.txt.gz' \) -print -quit 2>/dev/null)" ]; then
    printf '================================================================================\n'
    printf 'EMBEDDED WEB UI (HEADLAMP DASHBOARD) THIRD-PARTY LICENSES\n'
    printf '================================================================================\n\n'
    printf 'License texts emitted by the Headlamp frontend build for the JavaScript it\n'
    printf 'bundles. Each distinct text is reproduced once, labeled by an emitting bundle.\n\n'
    seen=$(mktemp)
    find "$assets_dir" -type f \( -name '*.LICENSE.txt' -o -name '*.LICENSE.txt.gz' \) | sort | while IFS= read -r license; do
      case "$license" in *.gz) gzip -t -- "$license" ;; esac
      digest=$(license_text "$license" | sha256sum | cut -d' ' -f1)
      if ! grep -qx "$digest" "$seen" 2>/dev/null; then
        printf '%s\n' "$digest" >> "$seen"
        printf -- '-------- %s --------\n' "${license#"$assets_dir"/}"
        license_text "$license"
        printf '\n'
      fi
    done
    rm -f "$seen"
    printf '\n\n'
  else
    echo "collect-notices: no vendored dashboard assets; skipping web UI licenses" >&2
  fi

  ocicl collect-licenses
} > "$output"

echo "collect-notices: wrote $output ($(wc -l < "$output") lines, $(wc -c < "$output") bytes)"
