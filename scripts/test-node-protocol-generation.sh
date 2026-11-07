#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=$(mktemp "${TMPDIR:-/tmp}/gr8s-node-protocol.XXXXXX.lisp")
trap 'rm -f "$output"' EXIT HUP INT TERM

cd "$root"
GR8S_NODE_PROTOCOL_OUTPUT="$output" \
  "${SBCL:-sbcl}" --noinform --non-interactive \
  --load scripts/generate-node-protocol.lisp

grep -q '(in-package "GR8S.NODE.V1")' "$output"
