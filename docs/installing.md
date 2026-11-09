<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Installing and operating gr8s with systemd

The supported installation lifecycle is Linux with systemd. The installer must
run as root and requires `install.sh`, `gr8s-killall.sh`, and
`gr8s-uninstall.sh` in the same directory. It installs one role per machine:
`gr8s-server.service` for a combined control plane and node, or
`gr8s-agent.service` for an agent joining an existing server.

The installer writes the binary and lifecycle tools to `/usr/local/bin`, the
selected role's arguments to `/etc/gr8s/server.env` or `/etc/gr8s/agent.env`,
and its unit to `/etc/systemd/system`. Runtime and cluster data belong under
`/var/lib/gr8s`; uninstall preserves that directory unless purge is explicit.

## Install from a local binary

Build or obtain an executable gr8s binary, then run the installer with the full
command line that systemd should preserve:

```sh
sudo env \
  INSTALL_GR8S_BINARY="$PWD/build/gr8s" \
  INSTALL_GR8S_MODE=server \
  INSTALL_GR8S_EXEC_ARGS='serve --state-directory /var/lib/gr8s/server --kubeconfig /etc/gr8s/kubeconfig' \
  ./install.sh
```

An agent uses `INSTALL_GR8S_MODE=agent` and arguments beginning with `agent`:

```sh
sudo env \
  INSTALL_GR8S_BINARY="$PWD/build/gr8s" \
  INSTALL_GR8S_MODE=agent \
  INSTALL_GR8S_EXEC_ARGS='agent --server 192.0.2.10:18090 --node-name worker-1 --state-directory /var/lib/gr8s/agent' \
  ./install.sh
```

`INSTALL_GR8S_EXEC_ARGS` is stored in a systemd environment file. Quotes,
backslashes, tabs, and newlines are rejected instead of being reinterpreted.

## Install a checksum-pinned release

Without `INSTALL_GR8S_BINARY`, a SHA-256 digest is mandatory. Supply either an
explicit asset URL:

```sh
sudo env \
  INSTALL_GR8S_URL=https://downloads.example/gr8s \
  INSTALL_GR8S_SHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  INSTALL_GR8S_MODE=server \
  INSTALL_GR8S_EXEC_ARGS='serve --state-directory /var/lib/gr8s/server --kubeconfig /etc/gr8s/kubeconfig' \
  ./install.sh
```

or a release tag through `INSTALL_GR8S_VERSION`. Version downloads resolve to
`https://github.com/atgreen/gr8s/releases/download/VERSION/gr8s-linux-ARCH`,
where x86-64 maps to `amd64` and AArch64 maps to `arm64`. Curl follows
redirects, treats HTTP failures as errors, and retries transient failures. The
download is copied to destination-local staging and its digest is checked
before any installed file is published.

## Upgrade and recovery

Re-run `install.sh` with the replacement binary or release digest and the
desired persisted arguments. The installer retains exactly one prior binary as
`/usr/local/bin/gr8s.previous`, atomically publishes the new files, restarts the
service, and waits for systemd readiness. A failed systemd operation or service
readiness check restores the binary, configuration, unit, role, and lifecycle
tools from the previous installation. A first installation that never becomes
ready is removed rather than left half-installed.

The default readiness deadline is 30 seconds and the service must remain active
continuously for two seconds before publication succeeds. The default bound for
rollback systemctl calls is 45 seconds, longer than the generated unit's
30-second stop timeout. `INSTALL_GR8S_READY_TIMEOUT`,
`INSTALL_GR8S_STABILITY_WINDOW`, and `INSTALL_GR8S_SYSTEMCTL_TIMEOUT` tune these
limits. After a failed upgrade, inspect the service before retrying:

```sh
systemctl status gr8s-server.service
journalctl -u gr8s-server.service
sha256sum /usr/local/bin/gr8s /usr/local/bin/gr8s.previous
```

## Stop, clean up, and uninstall

`gr8s-killall.sh` stops only the two known gr8s services, kills processes in
those units, unmounts paths owned beneath `/var/lib/gr8s`, and removes
`/run/gr8s`. It preserves configuration, installed binaries, persistent data,
and unrelated host services and mounts.

```sh
sudo /usr/local/bin/gr8s-killall.sh
sudo /usr/local/bin/gr8s-uninstall.sh
```

Uninstall disables and removes the units, binary, lifecycle tools, and
`/etc/gr8s`, but preserves `/var/lib/gr8s`. Destructive data removal requires
the explicit purge form:

```sh
sudo /usr/local/bin/gr8s-uninstall.sh --purge
```

Both cleanup commands are idempotent and report a nonzero status when a scoped
systemd or mount operation genuinely fails. Resolve that failure and rerun the
same command; uninstall refuses to delete the installation when its preliminary
cleanup fails.

## Validation

The rootless contract suites are:

```sh
python3 scripts/test_install_lifecycle.py
python3 scripts/test_uninstall_lifecycle.py
```

Real service acceptance is intentionally destructive and only for a disposable
systemd VM. Copy the repository lifecycle scripts and a native binary into the
VM, then run:

```sh
sudo python3 scripts/test-install-lifecycle-systemd.py \
  --binary /root/gr8s \
  --output /root/install-lifecycle.json \
  --i-understand-this-is-a-disposable-vm
```

The script refuses non-root and non-systemd hosts. It emits machine-readable
evidence for installation, enablement, successful upgrade, failed-upgrade
rollback, killall, data-preserving uninstall, and explicit purge.
