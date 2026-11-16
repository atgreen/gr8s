#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
set -eu

if [ -x /usr/local/bin/gr8s ]; then
  echo "gr8s: /usr/local/bin/gr8s from install.sh is also present; its units in" >&2
  echo "gr8s: /etc/systemd/system override this package's. Run gr8s-uninstall.sh" >&2
  echo "gr8s: from that installation before using the packaged services." >&2
fi

[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload || true
for service in gr8s-server.service gr8s-agent.service; do
  if systemctl is-active --quiet "$service"; then
    systemctl restart "$service" || true
  fi
done
