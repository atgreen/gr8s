<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# gr8: run a command in a sandbox

`gr8 COMMAND` runs a command as if you had run it yourself, but inside a
sandboxed Pod on your machine's gr8s node. The command has your terminal, the
directory you started it in, and the system's programs and libraries. It can write
only that directory and what you grant, and it reaches the
network only through the node egress proxy, which allows just the hostnames a
policy names. Real credentials stay in the cluster. The command holds stand-ins,
and the proxy swaps in the real value only for the host the credential belongs
to.

gr8 is built for AI coding agents such as Claude Code, but it works for any
command-line program.

```console
$ gr8 --allow example.com curl -s -o /dev/null -w '%{http_code}\n' https://example.com
200
$ gr8 curl -s https://example.com; echo "exit $?"
exit 6
```

The second run fails because no policy allows `example.com`: curl's exit code 6
means "could not resolve host".

## Requirements

- A gr8s node running on this host (`gr8s serve`, or `gr8s agent` joined to a
  cluster). gr8 runs the Pod on the node whose address belongs to this machine;
  `--node` names another.
- A kubeconfig that can create Pods in the `gr8` namespace. `--allow` also needs
  permission to create ClusterNetworkPolicies, and `gr8 --login` needs permission
  to create Secrets and SecurityProfiles.
- Linux with Landlock (kernel 5.13 or later). gr8 refuses to run a command
  unconfined on a kernel without it.

The RPM and DEB packages install `/usr/bin/gr8` next to `gr8s`. From a source
tree, `make gr8` builds `build/gr8`.

## Running a command

```text
gr8 [flags] COMMAND [ARG...]
```

| Flag | Meaning |
|---|---|
| `--allow HOSTNAME` | Let this run reach HOSTNAME. Repeatable; `*.example.com` matches subdomains. |
| `--ro PATH` | Also allow reading PATH. Repeatable. |
| `--rw PATH` | Also allow writing PATH. Repeatable. |
| `--env NAME` | Pass environment variable NAME through. Repeatable. |
| `--namespace NAME` | Namespace for the Pod (default `gr8`). |
| `--node NAME` | Node to run on (default: the one with this host's address). |
| `--kubeconfig FILE` | Kubeconfig (default: `$KUBECONFIG`, then `~/.kube/config`). |
| `--keep` | Keep the Pod, and any `--allow` policy, after the command exits. |
| `--policy NAME\|FILE` | Use this policy instead of the command's own. |
| `--login NAME` | Move a tool's login into the cluster (see Logins). |
| `--logout NAME` | Remove a stored login. |
| `--logins` | List the logins gr8 knows, and which are stored. |
| `--cpu N` | The command's CPUs, request and limit (`4`, `500m`). |
| `--memory N` | The command's memory, request and limit (`8Gi`). |
| `--no-display` | Withhold the Wayland display. |
| `--no-audio` | Withhold audio, and with it the microphone. |
| `--no-gpu` | Withhold the GPU. |
| `-v` | Report the Pod and policy gr8 creates. |

gr8 exits with the command's own exit status. Status 126 means gr8 could not
run the command at all, for example because the Pod did not start; 127 means the
command was not found.

Each run's Pod is named `gr8-COMMAND-SUFFIX`. It is labelled
`gr8s.io/gr8-command` with the command's name, `gr8s.io/gr8-user` with your
user name, and `gr8s.io/gr8-run` with the Pod's own name, so a policy can
select a command, a user, or a single run. The command starts only once the
node enforces the Pod's network policy (its `gr8s.io/NetworkReady` readiness
gate), so its first connection is already under policy.

## What the command sees

The command runs as you, with your user ID and groups, but in its own view of
the host:

- **Files.** Landlock allows reading the system's paths (`/usr`, `/bin`, `/lib`,
  `/etc`, `/opt`, and the like) and whatever is granted; writing the working
  directory, `/tmp`, `/var/tmp` and what `--rw` names; and nothing else, so other
  users' homes, `/var` and `/srv` are out of reach. `/proc`, `/dev` and `/sys` are
  the Pod's own, so it can't see your other processes. `/run` and `/tmp` are
  fresh: your host's sockets, such as your SSH agent, are not there, only the
  display and audio sockets the sandbox is given (see below).
- **Home.** `$HOME` is private. It holds only what `--ro`, `--rw` and the
  command's SandboxProfile grant, and git's configuration (`~/.gitconfig`,
  `~/.config/git`). A granted file the command saves is copied back when it
  exits. Started in `$HOME` itself, or in a directory holding it, the command
  gets no private home, since it may write there anyway.
- **Environment.** `TERM`, `COLORTERM`, `LANG`, `LANGUAGE`, `LC_*`, `TZ`, `PATH`,
  `HOME`, `USER`, `LOGNAME`, `SHELL`, `EDITOR`, `VISUAL`, `PAGER` and `NO_COLOR`
  pass through. Anything else, such as `SSH_AUTH_SOCK`, `*_TOKEN` or `AWS_*`,
  passes only when named with `--env`; the profile can add stand-ins.

## CPU and memory

The command runs in its Pod's cgroup, under the same enforcement as any Pod. By
default it requests 1 CPU and 1Gi and may use up to half the node's CPU and memory:
a runaway build or a hungry agent can't take the whole machine, and the Pod is
Burstable, so the kernel and the kubelet weigh what it asked for before choosing it
under memory pressure. `--cpu` and `--memory` give it exactly that much, as both
request and limit.

## The desktop

gr8 is for desktop work, so a command gets your session's display, audio and GPU
unless you say otherwise:

- **Display.** Your Wayland socket, at the same path in the sandbox's own
  `/run/user/UID` (`WAYLAND_DISPLAY` and `XDG_RUNTIME_DIR` set), so `gr8 firefox`
  opens a window. Never X11.
- **Audio.** PipeWire's `pipewire-0` and PulseAudio's `pulse/native` (`PULSE_SERVER`
  set). An audio socket also lets the command record from the microphone;
  `--no-audio` refuses both.
- **GPU.** The node's render nodes (`/dev/dri/renderD*`), and the proprietary
  NVIDIA driver's `/dev/nvidia*` when it is installed, through a device plugin
  built into the gr8s agent that offers them as the shared resource `gr8s.io/dri`.
  The display nodes (`card*`) are not handed out.

The sandbox's runtime directory is its own and writable, so apps that keep state
there (dconf, for one) work. A browser trusts the egress proxy too: gr8 adds its
CA to the system bundles and, for NSS (Firefox, Chrome), to p11-kit's anchors.

## What the command can reach

A gr8 sandbox is confined, whatever its policies say:

- **DNS is synthetic.** A name a policy allows is answered with an address from
  `198.18.0.0/15` that stands for that name. Any other name is refused. The
  cluster's own names (`*.cluster.local`) resolve as usual.
- **Everything else is denied.** Connections by IP address, IPv6, UDP other than
  DNS, and connections to the API server or the node itself are all refused by a
  built-in last rule, `gr8-sandbox`.
- **Allowed names go through the proxy.** The node egress proxy checks each
  connection against the name its address stands for. A TLS client that names
  another host in its SNI is refused.

To allow names, either pass `--allow` for one run, or write a
ClusterNetworkPolicy for a command. `--allow` creates a policy that selects only
this run's Pod and deletes it when the Pod goes. A standing policy looks like
this:

```yaml
apiVersion: policy.networking.k8s.io/v1alpha2
kind: ClusterNetworkPolicy
metadata: {name: claude-egress}
spec:
  tier: Admin
  priority: 10
  subject:
    pods:
      namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: gr8}}
      podSelector: {matchLabels: {gr8s.io/gr8-command: claude}}
  egress:
  - action: Accept
    to:
    - domainNames: [api.anthropic.com, platform.claude.com, "*.githubusercontent.com"]
```

A sandbox needs no Deny rule: its built-in last rule denies everything no policy
accepts.

## Seeing every request

The proxy terminates a sandbox's TLS for every allowed host. It presents a
certificate from the cluster's egress CA, which the sandbox trusts: gr8 adds the
CA to the sandbox's system trust bundle and sets `SSL_CERT_FILE`,
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE` and `GIT_SSL_CAINFO`. It then opens
its own verified TLS connection to the real server and relays HTTP/1.1 request by
request.

Every decision is a flow event:

- each DNS name answered or refused;
- each connection admitted or refused, with the rule that decided it;
- each request: method, host, path (without its query string), status, and the
  rule that injected a credential, never the credential itself.

Watch them with `gr8s doctor observe --namespace gr8`, in the dashboard's
Network view, or through OTLP flow logs:

```text
12:01:44.012 gr8s-local: gr8/gr8-curl-x8ms -> DNS github.com REFUSED by policy
12:01:44.019 gr8s-local: gr8/gr8-curl-x8ms -> GET example.com/some/path 404
```

The command's SandboxProfile controls this (see below). `tls: Passthrough`
relays TLS undecrypted, and `passthroughHosts` does so for named hosts only.
Use it for clients that pin certificates or speak only HTTP/2. The proxy offers
the client HTTP/1.1, and most clients fall back to it.

## Credentials

The command never holds a real credential. Each real credential lives in a
Secret. A SecurityProfile binds it to hosts and Pods. The proxy overwrites the
named header on matching requests with the real value.

### Logins

A tool that keeps an OAuth login in a file, as Claude Code does, can hand it to the
cluster:

```console
$ gr8 --login claude
gr8: claude's login is in the cluster; sandboxed runs of it hold stand-in tokens
$ gr8 claude
$ gr8 --logins                  # which logins gr8 knows, and which are stored
$ gr8 --logout claude           # remove it from the cluster
```

`gr8 --login NAME` copies the tool's tokens from its own file into the Secret
`gr8/login-NAME`, and applies a SecurityProfile that injects the access token into
requests to the login's hosts and, when the tool refreshes, handles the refresh
exchange at its token endpoint. A sandboxed run of one of the login's commands
sees the tool's file with stand-ins at exactly the token keys, and may reach the
login's hosts without listing them.

When the sandboxed tool refreshes, the proxy sends the real refresh token, keeps the
new tokens the response carries, and gives the tool stand-ins. The node writes the
new tokens back to the Secret. While the command runs, gr8 keeps the Secret and the
host's file in step, whichever expires later winning, so the tool outside the
sandbox keeps working after a refresh inside it retires its old refresh token.

gr8 knows `claude`. Describe any other tool's login in `~/.config/gr8/logins.yaml`:

```yaml
acme:
  commands: [acme]                      # the commands it is for
  file: .config/acme/credentials.json   # relative to $HOME; YAML if .yaml or .yml
  accessToken: oauth/access_token       # key paths, split on / (keys may hold dots)
  refreshToken: oauth/refresh_token     # optional
  expiresAt: oauth/expires_at           # optional
  expiresUnit: seconds                  # milliseconds (default), seconds or rfc3339
  inject:
    hosts: [api.acme.example]
    header: authorization               # the default
    template: "Bearer {{ .Token }}"     # the default
  refresh:                              # optional: the OAuth token endpoint
    hosts: [auth.acme.example]
    path: /oauth/token
```

A policy file can carry a stored login for one run: `credentials: [{from:
login:acme}]`.

An API key works the same way, with a SecurityProfile rule that targets
`x-api-key` and a stand-in in the command's environment. See
[credential injection](design-agent-egress.md#3-credential-injection).

Every stand-in contains `gr8s-injected`, and each one is bound to the hosts its
rules inject for. A request that would carry a stand-in anywhere else, or on a
path no rule covers, gets `403` with a body that says which header, for what
request, and where the Pod's credentials are bound. Nothing real can leak this
way, and the client learns why instead of seeing the server's `401`.

## Policy files

One file can say everything a command gets. `gr8 claude` reads
`~/.config/gr8/policies/claude.yaml`, else the working directory's
`.gr8/claude.yaml`; `--policy NAME` picks `~/.config/gr8/policies/NAME.yaml`, and
`--policy FILE` a file.

```yaml
apiVersion: gr8.gr8s.io/v1alpha1
kind: Policy
metadata: {name: claude}
spec:
  hosts: [api.anthropic.com, platform.claude.com, "*.githubusercontent.com"]
  credentials:
  - from: env:GITHUB_TOKEN                 # or file:~/.config/gh/hosts.yml#github.com/oauth_token,
                                           # or login:NAME, a stored login
    hosts: [api.github.com, github.com]
    header: authorization                  # the default
    template: "Bearer {{ .Token }}"        # the default
    env: GH_TOKEN                          # the sandbox gets a stand-in in $GH_TOKEN
  home:
    readWrite: [.claude, .claude.json]
    readOnly: [.config/git]
  env: {EDITOR: vi}
  egress:                                  # as a SandboxProfile's spec.egress
    enforcement: Audit
    binaries:
    - hosts: [api.github.com]
      paths: [/usr/bin/gh, /usr/bin/git]
  desktop: {audio: false}                  # display, audio and gpu default to on
  resources: {cpu: "4", memory: 8Gi}
```

gr8 turns it into resources for the one run, scoped to its Pod by the
`gr8s.io/gr8-run` label: a ClusterNetworkPolicy allowing `hosts` and the
credentials' hosts; a Secret per credential, read from its source on your
machine when the run starts, and a SecurityProfile injecting them; and, for
`egress`, a SandboxProfile for this run alone (`spec.run`), which the node prefers
to any other for it. The Secrets and SecurityProfile are owned by the Pod, so they
go with it even if gr8 doesn't; gr8 deletes everything when the run ends. Flags
win over the file. A missing credential stops the run before it starts.

**A policy the sandbox could edit isn't trusted as it stands.** The command may
write its working directory, so a `.gr8/` policy there could be widened by the very
agent it confines. gr8 shows such a policy and asks before using it, records your
approval by its content, and asks again, showing what changed, whenever it differs.
Without a terminal to ask on, gr8 refuses it. Policies in `~/.config/gr8/policies`,
which the sandbox can't write, are used as they are.

## SandboxProfiles

A `gr8.gr8s.io/v1alpha1` SandboxProfile says what a command gets. It is
cluster-scoped, so only a cluster administrator can write one.

```yaml
apiVersion: gr8.gr8s.io/v1alpha1
kind: SandboxProfile
metadata: {name: claude}
spec:
  commands: [claude]
  namespaceSelector: {matchLabels: {team: a}}   # optional
  home:
    readWrite: [.claude, .claude.json]
    readOnly: [.config/gh]
    placeholders: [.claude/.credentials.json]  # shown with stand-in tokens
  env:
    ANTHROPIC_API_KEY: gr8s-injected           # a stand-in the proxy replaces
  egress:
    tls: Terminate               # the default; or Passthrough
    passthroughHosts: ["*.pinned.example"]
    enforcement: Enforce         # the default; or Audit
    binaries:                    # only these programs may reach these hosts
    - hosts: [api.github.com]
      paths: [/usr/bin/gh, /usr/bin/git]
```

- `home` paths are relative to `$HOME` and may not climb out of it.
- `egress.enforcement: Audit` reports a request that breaks a rule and forwards
  it: a `Host` other than the name the connection was admitted by (domain
  fronting), or a stand-in nothing injects. `Enforce` refuses such a request.
- `egress.binaries` narrows a host to the programs that may reach it:
  `[{hosts: [api.github.com], paths: [/usr/bin/gh, /usr/bin/git]}]` lets only `gh`,
  `git` and what they run reach api.github.com, so `curl` inside the sandbox can't.
  Paths are the program's real file as the sandbox sees it, symlinks resolved
  (`readlink -f $(which gh)`); `*` matches within a path segment and `**` across
  them. Every connection event names the program that opened it.
- `namespaceSelector` limits the profile to the gr8 Pods of the namespaces it
  selects. For a command, a profile whose selector matches wins over one without
  a selector, then the first by name. gr8 and the node choose the same profile:
  gr8 for the home grants, the node for `egress`.

The node reads only `commands`, `namespaceSelector` and `egress`. It chooses the
profile from the Pod's command label and its namespace, never from anything the
Pod itself sets.

## Limits

- **Linux only.** gr8 needs a gr8s node on the same host.
- **No X11 or D-Bus.** An X11 client can read every other window and every key,
  and a D-Bus session client can start processes outside the sandbox, so neither
  is offered. Wayland apps work; an app that needs a portal or notifications runs
  without them.
- **HTTP/1.1 through termination.** A client that speaks only HTTP/2 or gRPC
  needs a passthrough host.
- **Certificate pinning.** A client that pins certificates, or ignores both the
  system trust bundle and the CA variables, fails the TLS handshake. List its
  hosts in `passthroughHosts`.
- **Non-HTTP over TLS.** A terminated connection must carry HTTP. Other protocols
  over TLS to an allowed host, such as IMAPS, need a passthrough host. Protocols
  where the server speaks first, such as SSH, are relayed as they are: git over
  SSH works once the host is allowed and `~/.ssh` is granted with `--ro`.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Could not resolve host` (curl exit 6) | No policy allows the name. Use `--allow` or a ClusterNetworkPolicy. |
| `403` with "carries a gr8 stand-in credential" | The request sent a stand-in to a host or path no rule injects for. The body names where the credential is bound. |
| `421 Misdirected Request` | The request's `Host` differs from the name it connected to. |
| A TLS handshake error to an allowed host | The client doesn't trust the egress CA, or pins certificates. Use `passthroughHosts`. |
| `gr8: Pod ... did not start` | The node is not ready, or the `gr8` namespace's Pod Security level is not `privileged`. gr8 creates that namespace with it. |
| `no node has an address of this host` | No gr8s agent runs here. Start one, or name a node with `--node`. |

For the design and security model, see
[design-agent-egress.md](design-agent-egress.md).
