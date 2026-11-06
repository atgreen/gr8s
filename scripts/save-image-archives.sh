#!/bin/bash
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
#
# Save images as OCI archives that a gr8s agent imports at startup from
# <state>/agent/images/ (or <agent state>/images/). Each archive keeps the image's
# full reference, so Pods find it by the name they ask for.
#
# Usage: save-image-archives.sh OUTPUT_DIRECTORY [--arch ARCH] [IMAGE...]
# With no IMAGE, saves the images the upstream certified conformance selection
# pulls on a native gr8s node, Sonobuoy's own included.
# Needs skopeo.
set -euo pipefail
output=$1; shift
arch=amd64
if [ "${1:-}" = "--arch" ]; then arch=$2; shift 2; fi
images=("$@")
if [ ${#images[@]} -eq 0 ]; then
  images=(
    registry.k8s.io/conformance:v1.36.0
    docker.io/sonobuoy/sonobuoy:v0.57.5
    registry.k8s.io/e2e-test-images/agnhost:2.63.0
    registry.k8s.io/e2e-test-images/agnhost:2.55
    registry.k8s.io/e2e-test-images/busybox:1.37.0-1
    registry.k8s.io/e2e-test-images/nginx:1.15-4
    registry.k8s.io/e2e-test-images/nonewprivs:1.4
    registry.k8s.io/e2e-test-images/glibc-dns-testing:2.0.0
  )
fi
mkdir -p "$output"
for image in "${images[@]}"; do
  name=$(printf '%s' "$image" | tr '/:@' '___').tar
  if [ -s "$output/$name" ]; then echo "have $name"; continue; fi
  skopeo copy --quiet --override-os linux --override-arch "$arch" \
    "docker://$image" "oci-archive:$output/$name.partial:$image"
  mv -f "$output/$name.partial" "$output/$name"
  echo "saved $name"
done
