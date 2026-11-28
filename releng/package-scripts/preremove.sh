#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
set -eu

# rpm passes the remaining install count (0 = erase, 1+ = upgrade);
# dpkg passes a word ("remove", "upgrade", ...). Act only on removal.
case ${1:-0} in
  0|remove) ;;
  *) exit 0 ;;
esac

[ -d /run/systemd/system ] || exit 0
for service in gr8s-server.service gr8s-agent.service gr8s-kms.service; do
  systemctl stop "$service" >/dev/null 2>&1 || true
  systemctl disable "$service" >/dev/null 2>&1 || true
done
