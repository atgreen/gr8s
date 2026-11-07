#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

mkdir -p "$scratch/bin" "$scratch/cache"
touch "$scratch/cache/e2e.kubeconfig" "$scratch/isolated.kubeconfig"

cat > "$scratch/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$GR8S_TEST_KUBECTL_ARGS"
EOF
chmod +x "$scratch/bin/kubectl"

cat > "$scratch/cache/sonobuoy" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$scratch/cache/sonobuoy"

GR8S_TEST_KUBECTL_ARGS="$scratch/kubectl.args" \
GR8S_E2E_CACHE="$scratch/cache" \
GR8S_E2E_KUBECONFIG_FILE="$scratch/isolated.kubeconfig" \
PATH="$scratch/bin:$PATH" \
  "$root/scripts/e2e-three-node.sh" status >/dev/null

if ! grep -Fq -- "--kubeconfig $scratch/isolated.kubeconfig" "$scratch/kubectl.args"; then
  printf 'e2e-three-node ignored GR8S_E2E_KUBECONFIG_FILE\n' >&2
  cat "$scratch/kubectl.args" >&2
  exit 1
fi
