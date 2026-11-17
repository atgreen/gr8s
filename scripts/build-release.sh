#!/bin/bash
# Build the same assets locally and in GitHub Actions. Toolchains and the
# Headlamp checkout are installed by release.yml; HEADLAMP must point to it.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${HEADLAMP:?Set HEADLAMP to the pinned Headlamp checkout}"
case $(uname -m) in
  x86_64) architecture=amd64 ;;
  aarch64) architecture=arm64 ;;
  *) echo 'Release builds require Linux amd64 or arm64' >&2; exit 1 ;;
esac
test "$(uname -s)" = Linux
output="$PWD/build/release"
mkdir -p "$output"
ocicl install
touch ocicl/.ocicl-installed

# A recursive registry can discover old versions left by `ocicl latest`.
# Use only the directories named by the lockfile, in lockfile order.
CL_SOURCE_REGISTRY=$(python3 - <<'PY'
import csv
from pathlib import Path
root = Path.cwd()
directories = [str(root) + '/']
with open('ocicl.csv') as lockfile:
    for row in csv.reader(lockfile, skipinitialspace=True):
        system = root / 'ocicl' / row[2].strip()
        if not system.is_file():
            raise SystemExit(f'Missing pinned system: {system}')
        directory = str(system.parent) + '/'
        if directory not in directories:
            directories.append(directory)
print(':'.join(directories))
PY
)
export CL_SOURCE_REGISTRY
make dashboard-assets
test -s assets/dashboard/index.html
scripts/collect-notices.sh "$output/NOTICES"
export GR8S_NOTICES_FILE="$output/NOTICES"
# Notices and dashboard assets are generated inputs, outside the normal source
# prerequisites. Always dump a new image after generating them.
make -W scripts/build-native.lisp native
scripts/verify-static-runtime.sh build/containerd
version=$(build/gr8s version)
version=${version#gr8s }
if [[ -n ${RELEASE_TAG:-} && "$version" != "$RELEASE_TAG" ]]; then
  echo "Built version '$version' differs from release tag '$RELEASE_TAG'" >&2
  exit 1
fi
build/gr8s --help > "$output/help.txt"
build/gr8s notices > "$output/embedded-notices.txt"
cmp "$output/NOTICES" "$output/embedded-notices.txt"
python3 scripts/package-release.py --root . --binary build/gr8s \
  --notices "$output/NOTICES" --output-dir "$output" \
  --version "$version" --arch "$architecture" --epoch "$(git log -1 --format=%ct)"
ocicl create-sbom cyclonedx "$output/gr8s-linux-$architecture-lisp-sbom.cdx.json"
ocicl create-sbom spdx "$output/gr8s-linux-$architecture-lisp-sbom.spdx.json"
(cd "$output" && sha256sum -c "gr8s-linux-$architecture.sha256")
