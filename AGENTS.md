# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd prime` for full workflow context.

> **Architecture in one line:** Issues live in a local Dolt database
> (`.beads/dolt/`); cross-machine sync uses `bd dolt push/pull` (a
> git-compatible protocol), stored under `refs/dolt/data` on your git
> remote — separate from `refs/heads/*` where your code lives.
> `.beads/issues.jsonl` is a passive export, not the wire protocol.
>
> See [sync-concepts](https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md)
> for the one-screen overview and anti-patterns (don't treat JSONL as the
> source of truth; don't `bd import` during normal operation; don't
> reach for third-party Dolt hosting before trying the default).

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
```

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

## Testing eBPF and the native runtime as root

Anything that loads BPF programs, attaches to cgroups, creates veths or runs
containers needs real root, so we run it in disposable VMs rather than on the
shared development host. Unprivileged user namespaces can't load a
`cgroup/connect4` program, and the host's bpffs has denied us before. `make test`
and the `unshare -Urn` targets don't need any of this, and they don't exercise
the real BPF path either.

### The test VMs

Fedora 44 cloud images under QEMU/KVM, with SSH as root forwarded to a local port.
These are nested VMs on a host shared with other CPU-heavy work, so timing is slow
and variable: treat a timeout as unproven until it reproduces in isolation.

| SSH port | `known_hosts` file | Disk | RAM |
|---|---|---|---|
| 22291 | `events_known_hosts` | 20G | 4G |
| 22292 | `grace_known_hosts` | 20G | 3G |
| 22293 | `restart_known_hosts` | 5G | 2G |

Everything lives in `~/.cache/gr8s-vm/` on the development host, not in this repo:
the base image `fedora-44-base.qcow2`, the `seed.iso` cloud-init seed (it enables
root SSH with `id_ed25519.pub`), each VM's `overlay.qcow2` and `launch.json`, and
the shared tools below. A VM runs:

```bash
qemu-system-x86_64 -enable-kvm -cpu host -m 4096 -smp 2 \
  -drive file=$VM/overlay.qcow2,if=virtio,format=qcow2 \
  -drive file=~/.cache/gr8s-vm/seed.iso,media=cdrom,readonly=on \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:22291-:22 \
  -device virtio-net-pci,netdev=net0 -display none \
  -monitor unix:$VM/monitor.sock,server=on,wait=off \
  -serial file:$VM/serial.log -pidfile $VM/qemu.pid -daemonize
```

An overlay is `qemu-img create -f qcow2 -F qcow2 -b ~/.cache/gr8s-vm/fedora-44-base.qcow2 overlay.qcow2 20G`.
The guests have `kubectl` in `/usr/local/bin` and `sonobuoy` in `/root`, but no
SBCL or compiler, so copy in a native binary rather than building there. The
scripts run under `sudo sbcl` (`make test-service-lb`, `scripts/probe-*.lisp`)
need a root environment with SBCL and aren't what these VMs run.

The guests have what the dataplane needs: kernel BTF (`/sys/kernel/btf/vmlinux`),
cgroup2, a host bpffs at `/sys/fs/bpf`, and SELinux enforcing. gr8s also mounts a
private bpffs at `<state>/agent/containerd/bpf`, where its pins live.

### Running gr8s by hand

Build on the host, copy the binary in, and run it as root. It starts its own
containerd, so no system container runtime is involved.

```bash
sbcl --noinform --non-interactive --load scripts/build-native.lisp   # build/gr8s.bin
K=~/.cache/gr8s-vm
SSH="ssh -i $K/id_ed25519 -o BatchMode=yes -o UserKnownHostsFile=$K/grace_known_hosts"
scp -i $K/id_ed25519 -o UserKnownHostsFile=$K/grace_known_hosts -P 22292 build/gr8s.bin root@127.0.0.1:/root/gr8s.bin
$SSH -p 22292 root@127.0.0.1 'pgrep -af "/root/[t]est-|[.]bin serve"'   # must print nothing
$SSH -p 22292 root@127.0.0.1 \
  '/root/gr8s.bin serve --runtime containerd --state-directory /var/tmp/gr8s-manual/state \
     --port 18191 --node-port 17448 --containerd-log-root /var/tmp/gr8s-manual/pods \
     --kubeconfig /var/tmp/gr8s-manual/kubeconfig'
```

Stop it with SIGTERM so it joins its runtime work. To debug, add
`--debug-slynk-port 4017` and inspect the running server from the VM with
`gr8s-debug.py --port 4017 --state-directory /var/tmp/gr8s-manual/state '(debug-threads)'`,
copying `scripts/gr8s-debug.py` in first.

The native build needs the containerd bundle at `build/containerd`. In a new
worktree, symlink it from a worktree that already has it.

### Running tests

Prefer the disposable test scripts, which start and clean up their own cluster and
report what they observed from inside real containers: for example
`scripts/test-pod-confinement.py`, `scripts/smoke-two-node.py` and
`scripts/test-storage-native.py`. Copy the script and binary to the VM and run it
there.

For upstream specs use `scripts/test-podtemplates-sonobuoy.py`, with `--focus` and
`--expected-specs`, or `--certified-conformance` for the full suite. A certified
run refuses the debug server and `--hold-on-failure`, so its binary is unmodified.

### Shared tools

These are in `~/.cache/gr8s-vm/tools/`. Use them whenever several agents are working:

- `gr8s-slot COMMAND...` limits builds and host test suites to two at once. It runs
  `make test` one at a time, because the suite binds fixed port 18089.
- `gr8s-upstream BINARY RUNNER FOCUS EXPECTED RESULT_DIR [ARGS...]` waits for a free
  VM in first-come order, copies the evidence to `RESULT_DIR`, and removes the run.
  It skips any VM under 1500 MB free on `/var`.
- `gr8s-reap` is piped to a VM over SSH (`ssh ... 'bash -s' < gr8s-reap`) to clear
  what an abnormal exit leaves behind: processes, mounts, shims, `alias gr8s` links
  and network namespaces. Without it gr8s can refuse to start with `Pod pool overlaps
  host route`.

Replace these scripts atomically, because a running bash reads its script as it goes.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:1105d646 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->
