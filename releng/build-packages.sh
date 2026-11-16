#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
#
# Build RPM and DEB packages from already-built release binaries.
#
# A tag v<k8s>-gr8s.<n> maps to the same upstream version in both formats:
# <k8s>+gr8s.<n>, with "+" joining the suffix because RPM forbids "-" in
# Version (both rpmvercmp and dpkg sort "+" as a separator, k3s-style).
# The revision is the packaging revision alone — 1, bumped only for a
# packaging-only respin — never part of the upstream version:
#   RPM:  gr8s-<k8s>+gr8s.<n>-1.<arch>.rpm
#   DEB:  gr8s_<k8s>+gr8s.<n>-1_<arch>.deb

set -eu

tag=${RELEASE_TAG:-v0.0.0-gr8s.0}
binary_directory=${PKG_BINARY_DIRECTORY:-build/release}
output_directory=${PKG_OUTPUT_DIRECTORY:-build/release}
nfpm=${PKG_NFPM:-nfpm}

case $tag in
  v*-gr8s.*) ;;
  *)
    echo "build-packages: RELEASE_TAG must look like v1.37.2-gr8s.0, got: $tag" >&2
    exit 2
    ;;
esac
kubernetes_version=${tag#v}
kubernetes_version=${kubernetes_version%-gr8s.*}
gr8s_suffix=gr8s.${tag##*-gr8s.}
case $kubernetes_version in
  *[!0-9.]*|''|.*|*.)
    echo "build-packages: malformed Kubernetes version in tag: $tag" >&2
    exit 2
    ;;
esac
case ${gr8s_suffix#gr8s.} in
  *[!0-9]*|'')
    echo "build-packages: malformed gr8s suffix in tag: $tag" >&2
    exit 2
    ;;
esac

# nfpm expands environment variables in scalar fields but not in content
# sources, so each architecture's binary is staged at the fixed path the
# configuration names.
stage_directory=build/package-stage
mkdir -p "$output_directory" "$stage_directory"
for architecture in amd64 arm64; do
  source_binary=$binary_directory/gr8s-linux-$architecture
  if [ ! -f "$source_binary" ]; then
    echo "build-packages: missing release binary: $source_binary" >&2
    exit 2
  fi
  cp -f "$source_binary" "$stage_directory/gr8s"
  export PKG_ARCH=$architecture
  export PKG_VERSION="$kubernetes_version+$gr8s_suffix"
  export PKG_RELEASE="${PKG_REVISION:-1}"

  "$nfpm" package -f releng/nfpm.yaml -p rpm -t "$output_directory"
  "$nfpm" package -f releng/nfpm.yaml -p deb -t "$output_directory"
done
