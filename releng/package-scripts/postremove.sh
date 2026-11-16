#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
set -eu

[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload || true
