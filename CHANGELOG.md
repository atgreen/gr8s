# Changelog

Notable changes to gr8s. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions combine
the Kubernetes API version with a gr8s release suffix (see
[Versioning](README.md#versioning)).

## [Unreleased]

### Security

- Containerd's state directory, which holds each container's OCI bundle and so any
  Secret given as an env var, is now a tmpfs (podster-j9gd), as stock containerd's
  `/run/containerd` is, rather than on the node's disk. A node upgraded with Pods
  running moves it when they're gone or it restarts, and logs that until then.
  Containerd's metadata database still records each container's spec on disk, as
  upstream's does; the docs now say to mount Secrets as files, which never reach
  the node's disk.
- gr8 users on one machine are kept apart (podster-tcr8). A Pod in a namespace gr8
  --setup made must run as its owner's UID and groups, may not escalate privilege,
  drops all capabilities, and uses no host namespaces, host ports or other sysctls;
  gr8's namespaces admit privileged Pods (the host's `/` is mounted), so before this
  anyone who could create a Pod in one could become root on the node. A `gr8:` user
  may make a ClusterNetworkPolicy or SandboxProfile only for their own namespace's
  Pods. gr8's sandbox container now sets `allowPrivilegeEscalation: false` and drops
  all capabilities, and its run SandboxProfiles name their namespace.
- Streaming into a Pod over a WebSocket (exec, attach and port-forward as a GET) needs
  `get` as well as `create` on the subresource, as upstream requires
  (AuthorizePodWebsocketUpgradeCreatePermission, GA in 1.38; podster-i18c.3). gr8s
  checked `create` alone.
- Every authenticated identity could GET any single named object without an RBAC
  grant, Secrets included (podster-8kxy). The discovery URLs every authenticated user
  may read (`/api/*`, `/apis/*`) were matched against resource paths too, so any
  credential the cluster accepts, a Pod's ServiceAccount token among them, could read
  objects by name. Lists and watches were not affected. Those URLs now grant only
  non-resource requests, as RBAC's `nonResourceURLs` do.
- Checked content no longer lets plain requests evict honest browser nodes
  (podster-k8oi). A tab was tainted `gr8s.io/tampered:NoExecute` for any answer but
  the expected file, so a directory without its slash (a redirect), a path with `//`,
  or an honest error cost it its Pods. Now only files the image holds are asked for,
  by their plain path, and only a 200 with other bytes taints.
- A browser node's frames pass to the server only as IPv4 from its Pods' own
  addresses, or as ARP for them (podster-vlnv). Every other kind, IPv6 included,
  passed with no NetworkPolicy or source-address check; and without a policy in
  place, IPv4 wasn't checked for its source either.
- Another site can't make its visitors browser nodes (podster-zar9): the join page
  can't be framed, and its WebSocket accepts only the join page's own origin.

### Fixed

- An HA member that applies a replicated change gives the Events it records that
  change's time, as intended, not its own clock (podster-8o0k). `*event-clock*` was
  bound in a file compiled before its `defvar`, so the binding was lexical and had no
  effect. Fourteen other variables were read before their definitions were compiled;
  all are now declared special first, and CI fails on any undefined function or
  variable (`make check-undefined`).
- `gr8` run in a git worktree lets the command write the repository's shared git
  directory and its `.beads` database (podster-0ii.10). Neither is under the
  worktree: git couldn't commit, and `bd` silently started an empty database in the
  worktree, which the host's `bd` then preferred, so beads seemed to disappear.
- An egress-only NetworkPolicy no longer cuts a Pod off from its own node
  (podster-zx0m). The node reaches its Pods from the node gateway (169.254.1.1, or
  fe80::1), which the ingress guard left unrecorded, so since egress policy started
  governing the node (podster-5hv.10) the Pod's replies were refused as new
  connections: probes, the Gateway and a curl on the node got no answer. Those
  connections are now recorded, without being reported or checked against ingress
  policy, so the replies pass; the Pod's own new connections to the gateway are
  still its egress policy's to decide.
- A Gateway or Pod-proxy reply whose body fails partway, after its head is sent, no
  longer ends as if it were whole (podster-ox5r). The proxy re-sends a chunked body
  chunked, and closing the stream wrote the terminating chunk, so a browser got a
  short file with no error and kept it: an 11 MB WebAssembly module arrived as 9.7 MB.
  The connection now closes without that chunk.
- A browser tab that rejoins after a server restart keeps its running Pods'
  addresses (podster-r34s). The server's address table was in memory only, so it
  handed them out afresh: the tab's Pods reported no podIP, Services lost them, and
  a new Pod could get an address a running one held. Each Pod now gets back the
  address it last reported.
- Editing only the browser-node page or runtime, or a dashboard page, rebuilds the
  file that embeds it (podster-qihf). ASDF doesn't count a `:static-file` dependency
  as making a fasl stale, so `make native` kept serving the old copy.
- `gr8s dashboard` no longer quits when the API server is slow to answer
  (podster-iumy). A read that ran out of time ended the dashboard with "Unhandled
  TIMEOUT in thread gr8s network favicons": SBCL's timeout isn't an error, so the
  thread's error handling missed it. It is now an ordinary error, and the dashboard
  also ignores a timer that fires late, as `serve` does.
- An idle HA member no longer spends most of a core checking Raft peer
  certificates (podster-480g). Every Raft message, and every node operation relayed
  between members, verified the peer's certificate again with two ECDSA checks,
  though the TLS handshake had already done so. A certificate verified under the
  cluster's CA now stands for a minute, never past its notAfter. Relayed node
  operations (logs, exec, the API's proxy to Pods) queued behind those checks and
  could time out.
- `/metrics` no longer fails once a node that reported its dataplane is deleted
  (podster-iha8). Every scrape answered 404 "Node … was not found" after a browser
  node's tab closed. A deleted node's last report is now let go.
- The lab scale run is measured again with podster-7op6 and podster-mtqe fixed
  (podster-i7yl). A browser node costs its server about 0.007 of a core and 6 to
  8 MiB, not the 2% of the machine the first run showed: that was the reconnect
  loop past the per-address cap and the port binding loop. The scale harness now
  measures the server idle first and in steady state, and skips a sample a
  checkpoint turns away instead of stopping.
- A server hosts more than 31 browser nodes (podster-7op6). Each node's agent dials
  the node listener from the server's own address, and the listener took at most
  32 connections from one address and 128 in all, so tabs past 31 joined but never
  went Ready. Loopback and the other control-plane members are now outside the
  per-address cap, and the listener takes 512 connections (`--node-max-connections`).
- A browser node's agent no longer opens its hosting server's node ports, health
  check ports and Gateway listeners (podster-mtqe). It runs in that server's process
  and network, where the server's own agent already holds them, so each browser node
  retried them, failing with EADDRINUSE about 1000 times a minute.
- A browser node whose tab closes is deleted at once, with its Pods, so their
  controllers start replacements elsewhere within seconds (podster-yucg). The Node
  used to stay until its lease lapsed and the Pod garbage collector caught up. A tab
  that stops answering pings for 10 s, because its machine slept or lost its
  network, counts as closed.
- Removing a browser node waits out a checkpoint instead of leaving its Node behind.
  On an HA member under load, a routine checkpoint turns writes away for about a
  second, and a removal or sweep that met one failed and left the Node NotReady.
- Pods bound to a Node that no longer exists are deleted, as Kubernetes' Pod garbage
  collector does, once the Node has been gone 40 s, so their controllers replace them
  (podster-k988). A browser node whose tab closed left its Pods bound for good, not
  ready, still counted by their Deployments and DaemonSets, and still listed as ready
  endpoints. Deleting such a Pod also works now: it failed with "Node … was not found",
  even with `--force --grace-period=0`, because the deletion tried to tell the absent
  Node to stop the Pod.
- A node's agent no longer rejects every desired-state snapshot while a browser node is
  hosted on one of its peers (podster-epec). The leader routes a browser node's Pod CIDR
  through the node hosting it, so that node's route carries two CIDRs, and the agent
  allowed one per address family: it refused the whole snapshot, its session ended and
  started again about once a second, and node operations (stats, logs, exec) failed, so
  `metrics.k8s.io` and Headlamp showed nothing. Peers also had no route to the browser
  node's Pods. A route may now carry further CIDRs after the peer's own, each inside the
  cluster's Pod range and overlapping nothing else the node routes.

### Added

- Secrets can be encrypted at rest with a KMS v2 plugin (podster-qyp9), the upstream
  `k8s.io/kms` protocol: `serve --kms-plugin NAME=ENDPOINT`, `secrets-encrypt enable
  or prepare --kms NAME`. The store keeps only data keys the plugin wrapped; a
  `kms-providers` health check reports the plugin; a rotated KMS key is followed
  online by a fresh data key. Any KMS v2 plugin works, Vault or OpenBao Transit and
  cloud KMSes among them, and HA members reach the same KMS rather than share a key.
- `gr8s-kms`, a bundled KMS v2 plugin, and `gr8s-kms.service` (podster-af7o). Its keys
  are sealed with systemd-creds, to the TPM when there is one; `rotate`,
  `export-recovery` and `import-recovery` (a passphrase-sealed copy for when the
  machine is gone) manage them.
- New standalone clusters from the packages encrypt their Secrets with `gr8s-kms`
  from their first one (podster-wsmz): `server.env` now passes `--kms-plugin` and
  `--encrypt-secrets-with`. Existing and HA clusters are left as they are.

- gr8 asks, at the terminal, when a sandbox reaches a host its policy refuses: allow
  it once, always, or no (podster-3zu0). The node answers the name with an address that
  stands for it without looking it up, so the name leaves the node only once allowed,
  and holds the connection while gr8 asks; the command's output waits, and a
  full-screen program redraws after. Allowing adds the host to the run's
  ClusterNetworkPolicy, and always to the policy file too; no labels the run's Pod so
  the node refuses at once.
- When a run ends, gr8 lists the hosts its policy refused and offers to add them to
  the run's policy file, keeping its comments, or to a new one (podster-l3zx). gr8
  users may read their own namespace's flow events for this.
- `gr8` offers to move a login it knows into the cluster the first time a command
  that uses it runs without it (podster-pojp), so `gr8 claude` on a fresh desktop
  needs no `gr8 --login claude` first. It asks only on a terminal, defaults to
  yes, and remembers a no in `~/.config/gr8/declined-logins`.
- A local user gets gr8 without sudo (podster-7uof). `gr8s-server` listens on
  `/run/gr8s/gr8.sock`, knows who connects from the kernel (`SO_PEERCRED`), and
  answers with their own kubeconfig, after making their namespace and grant. gr8
  asks it on first run; sudo is needed only to start `gr8s-server` on a machine
  where it isn't running. Root and system accounts are refused; `--gr8-users
  GROUP` limits it to a group, and `--gr8-socket ""` turns it off.
- `gr8 --setup` makes a fresh machine a gr8s node for the desktop user, and gr8
  offers it on a terminal when it finds no kubeconfig (podster-q35k). One sudo
  starts `gr8s-server`, waits for the node, makes the user a namespace of their
  own (`gr8-USER`), and grants them only what gr8 needs there; their kubeconfig,
  at `~/.config/gr8/kubeconfig`, carries a client certificate of its own, never
  the administrator's. `gr8s kubeconfig --user NAME` issues such a certificate.
  Setup itself runs sudo.
- StatefulSet `updateStrategy: Recreate`, for Kubernetes 1.38 (podster-i18c.5): every
  old-revision Pod is deleted, and no new-revision Pod is made until none is left, so
  the two never run at once; the `Progressing` condition reports `RecreateInProgress`
  and then `RecreateCompleted`. It turns on with the move to 1.38, as upstream's
  StatefulSetRecreateStrategy does.
- Container `lifecycle.stopSignal`, for Kubernetes 1.38 (podster-i18c.4): kept and
  checked against the Pod's `spec.os.name`, passed to containerd as the container's stop
  signal, and reported in `status.containerStatuses[].stopSignal`. It turns on with the
  move to 1.38, as upstream's ContainerStopSignals does; until then the field is dropped,
  as in 1.37.
- The join page keeps its device's screen awake while the tab is a node
  (podster-2yfv), so a phone or laptop that would lock and sleep stays in the
  cluster. The browser lets go of the lock while the page is hidden, and the page
  takes it again when shown. Its "screen" fact shows whether it holds one.
- Browser joins wait for the server's headroom (podster-vyec). While its spare
  memory is under a reserve (`--browser-memory-reserve-mib`, 1 GiB) a tab is
  refused. While its CPUs have been over 90% busy (`--browser-busy-above`, not
  counting niced work), the tab is asked to wait, and its page shows "Server busy,
  retrying…" and tries again. At most 8 browser Pods start at once
  (`--browser-starts-at-once`).
- Checked content tells the browser Pod about the visitor, as a reverse proxy would:
  their `User-Agent`, `Referer` and `Accept-Language`, `X-Forwarded-Proto` and
  `X-Forwarded-Host`, and their address as `X-Forwarded-For` and `X-Real-IP`. The Pod's
  logs showed the gr8s server and drakma for every visitor (podster-6bss). A tab's
  owner reads its Pod's logs, so `serve --browser-forward-client-address false` keeps
  visitors' addresses from strangers' tabs.

## [v1.37.2-gr8s.9] — 2026-11-27

### Highlights

This release brings five major features. Each has its own section below, with the
fixes that went with it.

- **Browser nodes: a web browser tab is a worker node.** `gr8s serve
  --browser-listen` publishes a join page, and a tab that opens it becomes a node
  whose Pods each run in their own Linux VM compiled to WebAssembly. Nothing is
  installed on the visitor's machine. Browser Pods have real cluster networking
  (DNS, Services, NetworkPolicy), reach each other over WebRTC across NATs, share
  image layers between tabs over BitTorrent, can lend the visitor's GPU to a Pod
  through WebGPU, and can serve web content the server checks against the image.
  See [docs/browser-nodes.md](docs/browser-nodes.md); demo.gr8s.io runs it.
- **gr8: commands and AI agents in a sandbox.** `gr8 COMMAND` runs a command in a
  sandboxed Pod on your node, reaching only the hostnames a policy allows. Real
  credentials stay in the cluster: the command holds stand-ins, which the node's
  egress proxy swaps for the real values on the way out. ClusterNetworkPolicy
  with `domainNames`, credential injection, OAuth logins for any tool, and desktop
  sandboxes with display, audio and GPU. See [docs/gr8.md](docs/gr8.md).
- **The dashboard's Network tab.** A live map of the cluster's traffic, drawn
  from flow events: workloads, Services, Gateways, the LAN and the world, with
  rates, drops and latency. It explains which NetworkPolicy allowed or dropped a
  connection, shows `gr8s doctor`'s findings on the map, and links Gateway
  traffic to its traces.
- **Let's Encrypt certificates through the Gateway.** A cert-manager `acme`
  Issuer or ClusterIssuer gets publicly trusted certificates over HTTP-01, which
  every node's Gateway listeners answer, scoped so a tenant can't validate
  another's hostnames.
- **OpenTelemetry.** Gateway listeners record a span for each request, joining
  the client's trace and passing it to the backend, and agents can send their
  flow events as OTLP log records.

### Browser nodes

- Browser nodes, first steps (podster-57fv, docs/design-browser-nodes.md): `serve`
  can run node agents for nodes whose containers live elsewhere ("virtual nodes",
  `--virtual-node NAME` on the fake runtime), each enrolled, labelled and tainted
  before its agent starts. `serve --browser-listen HOST:PORT` serves a join page: a
  browser that connects becomes a node (`browser-XXXXXX`, `kubernetes.io/arch: arm64`,
  taint `gr8s.io/browser=true:NoSchedule`) whose agent runs in the server and whose
  containers run in the tab, one unkernel instance per Pod
  (`--browser-distro FILE` is the root image they boot). Pods run their own
  linux/arm64 images, which the server resolves and caches and the tab unpacks; they
  get addresses in the node's Pod CIDR, routed through the hosting node to the tab,
  so Services and Gateways reach them; `kubectl logs` and `kubectl exec` work. A
  browser proves a non-extractable key, so a reload is the same node, and browser
  nodes refuse Pods that bring Secrets, host paths or privileges. A Node's
  `kubernetes.io/arch` is now the architecture its agent reports, so an arm64 node
  joined to an amd64 server is labelled arm64, and virtual nodes are no longer
  offered to the overlay as peers.
- Limits on browser joins: `serve --browser-max-nodes N` (default 64) and
  `--browser-max-per-client N` (default 4, by the client address the Gateway forwards
  in `X-Forwarded-For`). A browser past either is told why and doesn't join.
- Browser nodes connect across NATs (podster-zra1): `serve --browser-stun-listen
  HOST:PORT` answers STUN binding requests on UDP, so each tab learns the public
  address its NAT gives it and tabs on different networks connect directly, with no
  third party seeing visitors' addresses. `--browser-ice-server URL` (repeatable) adds
  other STUN or TURN servers. `--browser-peering all|same-network|none` says which
  tabs connect directly, since direct peers learn each other's public address; the
  default is `same-network`, and the join page says so when it is `all`. Tabs that
  don't connect directly still reach each other through the server.
- Browser nodes share image layers over the agents' BitTorrent protocol (podster-9mio):
  each layer is a BEP 52 torrent, the very torrent agents build for it (a zstd layer,
  served decompressed, gets one bound to the bytes served), described to tabs at
  `/torrents/DIGEST` on the join listener. Tabs speak the standard peer wire, byte for
  byte as cl-torrent does, over WebRTC data channels: they fetch pieces rarest first from
  up to 8 tabs that hold a layer or are still downloading it, check each piece against
  its Merkle root, share pieces while downloading, and drop a peer at its first bad
  piece. The server seeds every piece over HTTP ranges, so a layer always arrives. The
  whole-layer tab-to-tab transfer it replaces is gone.
- Checked content from browser Pods (podster-23v9.8): a Service annotated
  `gr8s.io/verified-content-root: DIR` is served at `/verified/NAMESPACE/SERVICE/` on
  the browser join listener. The server asks one of the Service's browser Pods over the
  Pod network and passes the answer on only when it is, byte for byte, the file the
  image (which the server pulled and checked) holds under DIR. Any other answer fails
  the request and taints the node `gr8s.io/tampered:NoExecute`. An HTML page that passes
  gets `<!--gr8s:node-->`, `pod`, `browser`, `image`, `digest`, `file`, `up` and
  `served-at` filled in by the server. `examples/browser-demo` is such a page.
- The browser node join page shows each Pod's container logs and its VM's boot console
  in a drop-down under the Pod, read from the tab itself with no traffic to the server
  (podster-y81l).
- Browser tabs rejoin on their own when their server restarts or is upgraded, and
  always on the server's current page and runtime: the page is never cached and loads
  the runtime at a URL naming its hash (podster-w22b).
- Pods on browser nodes can use the visitor's GPU (podster-tr2r): a tab with a
  hardware WebGPU adapter offers `gr8s.io/gpu: 1` and labels naming it, and a Pod that
  asks for it gets Vulkan 1.2 on the tab's WebGPU device, with the driver given to its
  containers.
- [docs/browser-nodes.md](docs/browser-nodes.md): how to offer browser nodes from a
  cluster (podster-931v).

#### Fixed

- Pods on browser nodes reach Services by ClusterIP (podster-kw5u). Connections to
  one timed out: nothing translated the address for a Pod in a tab, and the server
  judged egress policy against the ClusterIP. The tab now translates, asking the
  server for a Service port's backends when a Pod first uses it.
- A browser tab no longer retries a direct link to a peer it can't reach on every
  packet (podster-99q4): after a failure it waits 10 s, doubling up to 10 minutes,
  and meanwhile sends that peer's traffic and layer requests through the server
  without waiting on a link.
- Browser tabs no longer drop when the leader checkpoints (podster-0hp0). A report that
  couldn't be made while the store was blocked ended the tab's reporter for good, and
  the Gateway, which cut an upgraded connection whose backend was quiet for 10 s (its
  connect timeout, which SBCL also applies to reads), then closed the tab's session. A
  tab now misses one report; upgraded connections may stay quiet for an hour at either
  end; and a browser's statistics are waited for 5 s, not 120.

### gr8 and egress control

- gr8: `gr8.gr8s.io/v1alpha1` SandboxProfile says what a command gets in the
  caller's home and environment; the sandbox trusts the egress CA when the cluster
  has one; `gr8 login claude` moves Claude Code's subscription token into the
  cluster, so the sandboxed claude sees only stand-in tokens. The RPM and DEB
  packages install `/usr/bin/gr8` beside `gr8s`; `make gr8` builds it from source.
- Egress control and credential injection for AI agents, declared as Kubernetes
  resources and enforced by the node (podster-wv1w, docs/design-agent-egress.md):
  - `policy.networking.k8s.io/v1alpha2` ClusterNetworkPolicy is served natively:
    Admin and Baseline tiers around NetworkPolicy, Accept, Deny and Pass, Pod,
    namespace, node and CIDR peers, named ports, and `domainNames`.
  - A Pod whose egress policy names domains is captured: its outbound TCP to public
    addresses goes to a node egress proxy, which admits a connection by the TLS SNI
    or HTTP Host it names, never by address; its DNS is answered only for allowed
    names; UDP 443 is refused, so QUIC falls back to TCP.
  - A subset of OpenKruise Agents' `agents.kruise.io/v1alpha1` SecurityProfile
    injects credentials: the proxy overwrites the named headers of matching
    requests with a value from a Secret, terminating TLS with a leaf from a new
    egress CA that Pods trust through the `gr8s-egress` ClusterTrustBundle. The
    Pod holds only a placeholder; a Host that differs from the TLS name gets 421,
    and a missing credential 403. A profile's Secret reaches only the nodes
    running the Pods it selects, with their assignments.
  - Proxied connections and requests appear in the flows and the Network view
    under the name they went to, with the rule that injected a credential.
  - A Pod with a hostname allowlist resolves its allowed names to synthetic
    addresses in `198.18.0.0/15` and reaches only those, so the proxy admits a
    connection by the name the Pod looked up, whatever protocol it speaks, and dials
    only the addresses resolved with the answer (podster-wv1w.8). The range is
    reserved: Pod pools and ServiceCIDRs may not overlap it.
- gr8 policy files (podster-wv1w.14): one `gr8.gr8s.io/v1alpha1` Policy says a
  command's hosts, credentials (read from `env:` or `file:` sources on the host when
  the run starts), home grants, environment, egress inspection, desktop and
  resources. gr8 makes them resources scoped to the run's Pod, owned by it where
  namespaced, and removes them when the run ends. `~/.config/gr8/policies/CMD.yaml`
  is trusted; a working directory's `.gr8/CMD.yaml`, which the sandbox could edit, is
  pinned by content, and shown and asked about again whenever it changes.
  SandboxProfile gains `spec.run`, a profile for one run, which the node prefers.
- A gr8 sandbox is a desktop one (podster-wv1w.15, .16, .17): it gets the caller's
  Wayland display and audio (PipeWire, PulseAudio) at the same paths in its own
  runtime directory, and the GPU through a device plugin built into the agent,
  `gr8s.io/dri`, which shares the render nodes and NVIDIA's device nodes.
  `--no-display`, `--no-audio` and `--no-gpu` withhold them. Never X11 or D-Bus.
  NSS clients (Firefox, Chrome) trust the egress CA through p11-kit's anchors, so
  `gr8 firefox` works with TLS termination.
- A gr8 sandbox requests 1 CPU and 1Gi and is limited to half the node's CPU and
  memory by default, `--cpu` and `--memory` setting both; it was BestEffort, with
  no ceiling and the first to be killed.
- Logins for any tool (podster-wv1w.20): `gr8 --login NAME` moves a tool's OAuth
  login into the cluster, described by its file, token key paths, expiry, inject
  hosts and token endpoint; claude is built in and `~/.config/gr8/logins.yaml`
  adds others. A sandboxed run of its commands sees the tool's file with stand-ins
  at the token keys and may reach the login's hosts. `--logout NAME` and `--logins`;
  policy files take `from: login:NAME`. This replaces `gr8 login claude`, whose
  Secret and profiles it removes. gr8's own modes inside the Pod (hold, launch,
  enter, confine) now follow `--internal`, so no command of those names is mistaken
  for one.
- Per-credential stand-ins (podster-wv1w.27): each gr8 policy credential gets its own
  stand-in, recorded on its Secret as `gr8s.io/stand-in`, and the node egress proxy
  swaps the real value in only where a request carries it, in any header or inside
  `Authorization: Basic`, keeping the client's own form. A Pod can hold several
  credentials for one host, a request without the stand-in gets none, and git over
  HTTPS works. `prefix` shapes a stand-in for clients that check (`gho_`). Secrets
  without a stand-in keep the rule's header overwrite.
- gr8 policy credentials take `paths` (prefixes, or `=PATH` exact) and `methods`,
  binding a credential to those requests on its hosts alone (podster-wv1w.29).
- A stand-in credential is bound to the hosts its rules inject for (podster-wv1w.12):
  a relayed request that would carry one anywhere else, or on a path no rule covers,
  gets 403 with a body saying which header, for what request, and where the Pod's
  credentials are bound; Audit enforcement reports it and forwards.
- The node egress proxy terminates a gr8 sandbox's TLS for every allowed host and
  reports each request it makes (podster-wv1w.11). SandboxProfile `spec.egress` sets
  `tls: Terminate|Passthrough`, `passthroughHosts` for clients that pin certificates,
  and `enforcement: Enforce|Audit` (Audit reports a broken rule, such as domain
  fronting, and forwards). `spec.namespaceSelector` scopes a profile to namespaces;
  the node chooses the profile from the Pod's command label and namespace, never from
  anything the Pod sets.
- The node egress proxy handles an OAuth refresh for a sandbox (podster-kn03): a
  SecurityProfile rule of the gr8s type `OAuthRefresh` swaps the real refresh token
  into a refresh request, keeps the new tokens the response carries and hands the
  client stand-ins. The node writes the tokens back to the Secret through a new
  `CredentialRotation` node-protocol message, which the server accepts only for that
  node's Pod and rule. `gr8 login claude` stores the refresh token and adds the rule,
  the sandbox refreshes on the login's real expiry, and gr8 keeps the Secret and the
  host's credentials file in step, the later expiry winning.
- Binary-scoped egress (podster-wv1w.13): SandboxProfile `spec.egress.binaries` lets a
  host be reached only by listed programs (`hosts`, `paths` with `*` and `**`), or
  their children. The node finds the program behind each proxied connection from the
  Pod's `/proc` (the socket by the client's address, the process holding it, its
  executable and parents), and every connection event names it (`l7.process`).
- `gr8 --allow NAME` lets one run reach a hostname (repeatable; `*.example.com` for
  subdomains) through a ClusterNetworkPolicy that selects only that run's Pod and is
  deleted with it (podster-xazj). It needs permission to create ClusterNetworkPolicies.
- A gr8 sandbox, any Pod labelled `gr8s.io/gr8-command`, is always on synthetic
  DNS, and anything its policies don't allow is denied (podster-1mzb). Its DNS
  answers only the names a ClusterNetworkPolicy accepts for it (none: `REFUSED`).
  It reaches those names through the node egress proxy. Every other connection is
  denied by a built-in last rule, `gr8-sandbox`: by address, over IPv6, over UDP,
  and to the API server and its own node, which other Pods reach past policy.

#### Fixed

- Egress capture works on a real node (podster-uevw). It validated the service
  load balancer's pinned maps against the CNI policy maps' layouts, so every write
  failed ("incompatible schema"), and native agents never recorded a Pod's network
  namespace cookie, by which capture names it. The proxy's decision read three of
  the agent's four egress-view parts, so every captured connection signalled and
  was reset. The proxy now logs its refusals and its connection errors, which it
  used to swallow.
  Hostname allowlists, credential injection and synthetic DNS did nothing outside
  the unit tests.
- The node egress proxy's verdicts reach the flow stream, the Network view, OTLP flow
  logs and `observe_flows` (podster-5hv.11): a second `:report` argument had silently
  replaced the one that sent them. The egress DNS gate reports each name it answers
  or refuses for a captured Pod, and the Network view draws a refused lookup in red to
  the site it names.
- The egress DNS gate reports a Pod's lookup of a name once per decision: a
  resolver's A and AAAA queries and retries made one refused lookup four events.
- Egress NetworkPolicy now governs node DNS, the API server and the Pod's own
  node (podster-5hv.10, closing security deviation F5). The egress guard used
  to deliver those to the host before checking policy, so a Pod under
  default-deny egress could still resolve names, reach the API server and the
  node's services, and its connections to them never appeared in the flows or
  on the Network map. **Behaviour change:** a Pod isolated for egress now needs
  a rule for each. The usual rules work: a peer selecting `k8s-app: kube-dns`
  Pods in `kube-system` selects the node DNS gateway, and a rule admitting the
  API server's endpoints (the members' addresses on 6443) admits its Service
  address too.
- A host running avahi-daemon (or any mDNS responder) no longer shows its Pods
  dropping spoofed packets on mDNS's schedule, doubling from a Pod's start up to
  hourly (podster-4yh). The host's mDNS query out each Pod veth came back to it
  as a loopback copy received on that veth, which the egress guard took for the
  Pod's traffic from the wrong address. The guard now passes the host's own
  loopback copies; a Pod can't make one.

### Dashboard and observability

- `gr8s dashboard` has a Network tab: a live map of the cluster's traffic,
  drawn from its flow events (podster-5hv). A node is a workload (a Pod
  resolved through its owners to its Deployment, StatefulSet, DaemonSet or
  Job), a Service, a Gateway, a cluster node, the LAN or the world; traffic a
  Gateway relays reads client → Gateway → backend. Edges carry their ports,
  rate, drops, HTTP errors and median latency over the last 1, 5 or 15
  minutes; picking one shows its counts and latest flows, with the policy that
  dropped a connection. Cards show the app's own favicon when it has a web UI,
  else a logo for recognised software, else an icon for its kind. A live
  layout keeps nodes where they are as traffic changes, and a flow layout lays
  traffic out left to right; a flow table follows the same filters. Its
  scripts, icons and font (Cytoscape.js, Simple Icons, Lucide, Inter) are
  embedded, pinned by version and checksum.
- The Network tab explains NetworkPolicy (podster-5hv.3): selecting an edge
  shows, for each connection behind it, which rule of which policy allows it
  each way, or which policies refused it and the smallest rule that would
  allow it, ready to copy. Cards of workloads a policy isolates carry a
  shield. The view (namespace, window, verdict, selection, flow table) is kept
  in the URL so it can be linked. A policy's name, and a selected workload,
  open that resource in the Headlamp tab.
- The Network tab shows `gr8s doctor` on the map (podster-5hv.4): it surveys
  the cluster every minute and marks the workloads a problem is about and the
  ones it holds up, with each problem's evidence and next step in their panels
  and every problem under Health.
- The Network tab links a Gateway edge to its traces (podster-krg.3): the edge
  lists its slowest recent requests, and a `DashboardTab` that shows traces
  (`spec.traces`, a path with `{traceId}` in it, such as Grafana Explore's for
  Tempo) opens each one. The dashboard page now also escapes every tab field it
  draws, a cluster's `DashboardTab` title among them.
- The Network view draws more than 8 World sites in a view as one Internet node, with
  one edge per workload and direction carrying their sum, and a scrollable list of
  the sites on its card (most dropped first, then busiest) that opens each one's
  connection. A browser in a gr8 sandbox reaches dozens of sites, which buried the
  view.
- Flow events name a peer outside the cluster by the DNS name a Pod looked up
  to reach it (`peerName`), as the node's DNS server saw it answered
  (podster-5hv.8), and the Network tab draws each such site as a node of its
  own: `grafana → secure.gravatar.com` instead of `grafana → world`.
- Gateway tracing with OpenTelemetry (podster-krg.1): an agent configured with
  OTel's standard environment variables (`OTEL_EXPORTER_OTLP_ENDPOINT` and the
  rest) records a SERVER span for each request its Gateway listeners answer,
  joining the client's W3C trace or starting one, hands the backend its span as
  the `traceparent`, and exports spans over OTLP/HTTP. Off unless configured.
- Flow events as OpenTelemetry log records (podster-krg.2): with
  `OTEL_LOGS_EXPORTER=otlp`, each agent sends its flow events -- connections,
  drops and why, Gateway requests with their trace ids -- over OTLP/HTTP to the
  logs endpoint, one record per event with OTel's network attributes.
- `gr8s dashboard` on a port a dashboard already serves says so -- "gr8s
  dashboard is already running at URL" -- and opens that one, instead of
  failing with `USOCKET:ADDRESS-IN-USE-ERROR`; a port another program holds is
  named as such, with `--port` to choose another. A running dashboard records
  its URL in a private file under `$XDG_RUNTIME_DIR/gr8s/`, removed when it exits.

#### Fixed

- A followed flow stream (the dashboard's Network tab, `gr8s doctor observe -f`) no
  longer loses a node for good when that node's stream ends, as when its agent
  restarts in a rolling upgrade: the node is asked again every 2 seconds, resuming
  after the last event delivered (podster-v7sj).
- The Network tab's side panel no longer redraws itself every two seconds. It
  flashed and lost its scroll position on each poll; it now changes only when
  what it shows has, keeps where you had scrolled, and wraps long names instead
  of scrolling sideways.
- `make native` in a fresh checkout embeds the Network tab's graph assets. The
  binary's build didn't depend on them, so it built without them and the tab
  had no graph; release builds, which fetch every asset first, were unaffected.
- The dashboard's Hubble tab draws a workload's replicas as one card. Each Pod
  had its own identity, so a Deployment of four showed as four identical cards;
  identities now follow a Pod's namespace and labels, leaving out the labels that
  tell replicas apart (`pod-template-hash` and the like), as Cilium's do
  (podster-u0e).
- `gr8s dashboard` no longer burns a CPU core after a watch ends. When the
  cluster ended a watch (a member restarting, say), the relay closed the
  browser's socket while its reader thread was still waiting on it, and that
  thread then polled the dead descriptor without pause, for as long as the
  dashboard ran. The dashboard's other relays (the multiplexer's watches and
  the REPL tab's tunnel) had the same race. A relay now only shuts a socket
  down to wake a reader, and closes it once the reader has finished
  (podster-gek).
- `gr8s doctor` no longer reports a finished Pod as not ready (podster-191). A
  Job's Pod that completed is not ready by design, but the readiness checks
  flagged it, so a cluster with CronJobs always had a problem to read past. The
  readiness checks now skip Succeeded and Failed Pods; a failed Pod keeps the
  findings about its exit.
- `gr8s doctor diagnose` and `impact`, and the MCP doctor tools, read the cluster
  with gr8s's own API client instead of running `kubectl`, so they work on a host
  without it, such as a control-plane member, where they defaulted to the
  member's own kubeconfig. Before, every kind came back "unknown" with no reason.
  A failed read now says why (the HTTP status and the server's message, or that
  it didn't answer), and the standalone `scripts/gr8s-doctor`, which still uses
  `kubectl`, says when it can't run it (podster-71m).
- `gr8s doctor` refuses a word that is neither a command nor a directory, and
  suggests the command meant: `gr8s doctor diagnosis` checked an empty
  `./diagnosis/` state directory, found the node's live routes stale, and
  advised a `--fix` that would have torn them down (podster-m6w).

### Gateway, certificates and networking

- A cert-manager `acme` issuer (podster-23v9.4): an Issuer or ClusterIssuer with
  `spec.acme` gets publicly trusted certificates from Let's Encrypt, or any RFC 8555
  server, validated over HTTP-01 through `http01.gatewayHTTPRoute` solvers. The
  controller keeps the account key in the `privateKeySecretRef` Secret (a
  ClusterIssuer's in `kube-system`), writes an `acme.cert-manager.io/v1` Challenge
  per pending authorization, and every node's Gateway listeners answer
  `/.well-known/acme-challenge/<token>` for it before route matching. The issued
  chain and RSA key land in the Certificate's `kubernetes.io/tls` Secret for an
  HTTPS listener, and renew like other issuers' certificates. Failed orders back
  off from 5 minutes, doubling to a day, and a server's `Retry-After` defers the
  next step. A listener answers a Challenge only where an HTTPRoute from the
  Certificate's namespace could attach for its host (hostname, `allowedRoutes`,
  the solver's `parentRefs`), and the issuer refuses authorizations for names the
  Certificate does not list, so a tenant cannot validate another's hostnames.
  Steps run off the reconcile pass with bounded requests over verified TLS. DNS-01,
  Ingress solvers and external account binding are rejected at admission.
  A Certificate's `renewBefore` must now be shorter than its `duration`, and one
  not shorter than the validity the issuer chose falls back to a third of it.
  On a port, only the listener that wins a Challenge's host may answer it, and
  only with the solver's `parentRefs`, which admission now requires. An ACME step
  stops writing once its control plane stops leading. Durations parse as Go
  writes them (`2160h0m0s`), and the `renewBefore` rule applies only when a
  Certificate's spec changes.
- A Pod can wait for its node to enforce its network policy with the readiness gate
  `gr8s.io/NetworkReady`, which the node reports. gr8 Pods use it, so a command no
  longer starts before its allowlist is in place (podster-ae08).

#### Fixed

- Pods can reach the LAN and the internet (podster-swq). gr8s masqueraded Pod
  traffic only to other nodes and the API, so a Pod's packets left with its
  private address and replies never came back. Each agent now masquerades its
  Pods' traffic leaving the cluster's Pod network, as other CNIs do;
  `--pod-masquerade off` keeps Pod addresses on networks that route them.
- A NetworkPolicy no longer cuts an idle connection after two hours. The policy
  guards admitted a TCP connection's replies for 2 hours after its last packet,
  exactly Linux's default `tcp_keepalive_time`, so an idle pooled connection's
  first keepalive arrived just too late, was dropped, and the connection died
  (seen with Postgres). Replies now stay admitted for 5 days, as conntrack keeps
  an established connection; the flow maps are LRU, so this costs no memory
  (podster-af3).
- NetworkPolicy no longer drops IPv6 neighbor discovery and MLD (podster-6cy).
  An isolated Pod's ICMPv6 (and MLD behind a hop-by-hop header) to or from a
  link-scope peer -- fe80::/10, ff02::/16 or the unspecified address -- passes
  as interface housekeeping, as Cilium always admits NDP; without it a
  dual-stack Pod's IPv6 could not resolve its neighbors. Other link-local
  traffic, such as mDNS, is still the policy's to allow.
- A new Pod is in a ClusterNetworkPolicy's subject from the snapshot that assigns it,
  not one after its address reaches the control plane, so its first connections are
  not decided without the policy (podster-ae08).
- A node no longer resolves a new Pod's policy with the labels of a deleted Pod whose
  address it reused (podster-ae08).
- A new Pod's first connections to Pods behind an ingress policy on other nodes
  are refused for much less time: about half a second, under TCP's first
  retransmission, rather than up to 7-11 seconds under load. The agent reports a
  Pod's new address at once instead of at its next 7-second status report, and
  the control plane sends it to the other nodes at once instead of on its next
  one-second pass (podster-auf).
- A proxied connection whose client closed first could leave the Gateway's L4 proxy or
  the node egress proxy waiting on the upstream forever: closing a socket another
  thread is receiving on neither wakes it nor tells the peer. Both sockets are now
  shut down first.
- A Gateway passes on each of a backend's `Set-Cookie` headers on its own line,
  as the Pod proxy already did. It joined them into one with commas, so a browser
  kept only the first cookie: an OIDC login that sets a verifier and a state
  cookie together lost the state and looped back to the login page (podster-qnr).
- A worker joined with `gr8s agent` now serves the kubelet's endpoints
  (`/stats/summary`, `/metrics/resource`, `/metrics/cadvisor`) on 10250, as a
  control-plane member's own node does; `--kubelet-port` moves them, and 0 turns
  them off. It gets its kubelet's certificates from the control plane over its
  node identity, through a new `IssueKubeletCredentials` node RPC, and admits the
  port through firewalld. Before, it ran without them, so the Node proxy answered
  "does not serve /stats/summary" for it, and Prometheus could not scrape it. An
  agent whose kubelet endpoint is off for want of certificates now says so
  (podster-b55).

### Control plane, nodes and Kubernetes compatibility

#### Fixed

- A control-plane member no longer exits when a checkpoint briefly blocks its store
  (podster-0hp0). The flow observer and the resource-metrics collector let the
  momentary "Application restore is blocking store access" error escape their
  threads, which ends the server: a lab follower exited five times in three days.
  Each now keeps its previous result and tries again.
- A control-plane member no longer goes down when the member it relays a node
  operation to is restarting (podster-2aum). Connecting to that peer, a refusal or
  a TLS handshake that timed out, escaped the relay's error handling and ended the
  whole process, so a rolling upgrade could take out the leader while the other
  member restarted. The route now fails over or reports the peer unreachable. An
  error in a routing thread fails its operation, not the server. A process that
  does end on an unhandled error now exits within 10 seconds, not after SBCL's
  60-second wait for its threads, so systemd restarts it promptly.
- `gr8s status` compares each control-plane member's own `/version` too, so a
  member without a Node (`serve --disable-agent`) on another release shows as
  skew (podster-gta).
- A Node's `Ready` condition carries its `lastTransitionTime`: when the node's
  ready lease began, or for a node that isn't ready, when it was last heard from.
  Headlamp works out a node's uptime from it, and showed "NaNy" (podster-zac).
- `/stats/summary` reports the node's filesystem (`node.fs`): the one under
  `/var/lib/kubelet`, which DiskPressure watches. Headlamp shows it as the node's
  ephemeral storage, and left that empty on every node (podster-b55).
- Every Burstable container got `oom_score_adj` 999, as if it requested no memory:
  the node's memory capacity was read as NIL (`/proc/meminfo`'s value was parsed
  twice), so the kubelet's scaling by memory request never applied.
- `kubectl exec` of a command that can't start says why, as Kubernetes does
  (podster-dcz): `executable file not found in $PATH`, not a bare "command
  terminated with exit code 1". The agent dropped the runtime's reason when a
  status had no exit code. This is what distroless images (no shell, no
  coreutils) hit: exec works in them, but only for programs they contain.
- `kubectl apply` of a Service whose ports changed works. A strategic merge patch
  to a Service was applied as a plain JSON merge patch, so the directives kubectl
  sends (`$setElementOrder/ports`, `{"$patch": "delete"}`) were rejected as
  unknown fields (422), and a patch naming one port replaced the whole list.
  Services now merge as upstream does, ports keyed by their port number
  (podster-0i0).
- The `kubernetes` Service carries the labels kube-apiserver gives it,
  `component: apiserver` and `provider: kubernetes` (podster-c6e), and a cluster
  whose Service lacks them gains them. Monitoring finds the API server by them:
  kube-prometheus-stack's apiserver ServiceMonitor found nothing, which led to
  scraping every node on 6443, agents that don't serve the API included.

### Removed

- `gr8s dashboard`'s Hubble tab, and the Hubble UI bundle it embedded: the
  Network tab replaces it. The Hubble API stays: `gr8s doctor observe --serve`
  still serves Hubble's Observer API for the `hubble` CLI.

## [v1.37.2-gr8s.8] — 2026-11-24

Ninth trial pre-release. `gr8s upgrade` rolls a cluster onto a signed release,
host by host: the voters one at a time, the leader last after handing its
leadership on, then the agents, with a quorum check before each step, a record
to resume from, and rollback. Releases are now published as signed OCI
artifacts for it to install from. A Gateway sends PROXY protocol v2 to TCP and
TLS route backends that ask for it, so they can see their clients' addresses.
Nodes report the release their own agent runs. Hosts on v1.37.2-gr8s.7 or older
move to this release once with `sudo gr8s upgrade self --to v1.37.2-gr8s.8`.

### Added

- `gr8s upgrade` rolls a cluster onto a signed gr8s release, host by host,
  through the cluster API (podster-igs). `plan` shows each host's step and
  refuses what isn't safe: a voter whose restart would leave too few votes for
  a quorum, a downgrade, a release with no package for a host's architecture.
  `apply` upgrades the voters one at a time, hands the leadership on before
  upgrading the leader, then the agents, and waits for each host to come back
  on the release; a node that is away is upgraded when it returns. Progress is
  kept in a `ClusterUpgrade`, so `apply` resumes, and `status` and `rollback`
  read it. `finalize` lets the cluster use a release's new formats once every
  voter runs it; a member too old for them refuses to start. A witness needn't
  run the release, and is left be. `self` upgrades one host as root, as one
  running a gr8s from before `gr8s upgrade`, `mirror` copies a release to another
  registry, and `publish` is what the release workflow pushes with.
- Releases are published as a signed OCI artifact,
  `ghcr.io/atgreen/gr8s-packages:<tag>`, holding the RPMs, DEBs and executables
  for each architecture and a `release.json` signed with the gr8s release key
  (Ed25519). A host installs only a package that release.json, under a key the
  gr8s it runs carries, vouches for.
- A TCPRoute, TLSRoute or GRPCRoute backend can learn the client's address. The
  gateway connects to the backend itself, so the backend saw the node as every
  client. A backend Service annotated `gr8s.io/proxy-protocol: v2` is now sent a
  PROXY protocol v2 header naming the client and the address it dialed, ahead of
  the client's first byte, so it can, for example, keep passthrough TLS and still
  record who connected. Other backends are unchanged (podster-0gz).

### Changed

- A Node reports the gr8s release and architecture its own agent runs, in
  `nodeInfo.kubeletVersion` and `nodeInfo.architecture`; they were the control
  plane's. A node whose agent is too old to report them shows
  `v0.0.0-unknown`, and `gr8s status` warns of it.
- `/version` names the platform's real architecture, and adds
  `gr8sFormatLevel`, the newest store format the member reads.

### Fixed

- A request relayed to a control-plane member that had restarted since the last
  one no longer fails once with "Broken pipe": a connection that fails under the
  frame is replaced and the frame sent again (podster-3ao).
- `gr8s dashboard` no longer exits on a flow of a protocol gr8s can't name,
  such as IGMP: its Hubble UI feed put the protocol's number where text goes,
  and nothing caught the error (podster-atf).

## [v1.37.2-gr8s.7] — 2026-11-23

Eighth trial pre-release. Container logs no longer stop the server: a log is
read a piece at a time, from where the request begins, and rotated as kubelet
rotates it. In v1.37.2-gr8s.6, `kubectl logs` on a 471 MB log exhausted a
member's heap. The dashboard's Agent tab starts its terminals at once instead
of after minutes, and its REPL tab reaches a member whose earlier debug session
was lost.

### Added

- Container logs are rotated, as kubelet rotates them: past 10 MiB a log is
  renamed with the time, the container starts a new file, and five files are
  kept, the one being written among them. The agent looks every 10 seconds.
  Before, a log grew without bound; one reached 471 MB in a day and a half
  (podster-xps).
- `gr8s skill` explains how to add a dashboard tab for one of the cluster's
  own apps with a `DashboardTab`, including where to get its CRD, which
  release packages don't carry (podster-032).

### Changed

- Reading a container's log no longer reads the whole file. The node sends it
  a piece at a time, as the client takes it, and begins where the request
  does: `tailLines` is found from the end of the file and `sinceSeconds` or
  `sinceTime` by bisecting it, and `limitBytes` stops the read. A followed log
  reads only what was written since. An older node, which sends the whole file,
  still works. Before, a log was read whole and copied several times, and a
  follow read it again every second (podster-0gf).

### Fixed

- `kubectl logs` on a large container log no longer stops the server. A
  request for a 471 MB log exhausted a member's 2 GiB heap, and the server
  exited (podster-0gf).
- The dashboard's REPL tab, and `gr8s debug icl --member`, can again reach a
  control-plane member whose earlier debug session was lost: a member now ends
  a session whose origin no longer holds it, after half a minute, instead of
  keeping its one debug session taken until it restarts. A member that refuses
  a session says why, as a 503 with the reason, instead of an HTTP 500
  (podster-bkm).
- Terminals in the dashboard's Agent tab start at once. Headlamp watches some
  resources over WebSockets of their own, which the dashboard passed to the
  cluster as plain watch requests that never answered; Chrome opens one
  WebSocket to a host at a time, so a terminal waited behind them for minutes.
  The dashboard now relays those watches itself, and answers its other
  WebSockets (Headlamp's exec, attach and log views, which never worked
  through it) with 501 at once (podster-c7r, podster-db5).
- The Agent tab's terminals echo what is typed: a shell's input showed nothing.
- A dashboard app tab keeps every cookie the app sets: the API proxy joined
  several `Set-Cookie` headers into one, and a browser keeps only the first,
  so Grafana's login didn't stick.
- A dashboard app tab no longer passes the browser's `Origin` on to the app,
  which sees another host behind the API proxy and refused it as cross-site
  (Grafana). The tab refuses a request whose `Origin` is another page's.
- The REPL tab says that it needs ICL 1.26.0 or later.
- The README and `gr8s skill` name the package the Slynk debug helpers are in,
  `GR8S.APISERVER`.

## [v1.37.2-gr8s.6] — 2026-11-23

Seventh trial pre-release. `gr8s dashboard` gains an Agent tab, running AI
coding agents in terminal tabs with the cluster's kubeconfig, and a REPL tab,
ICL's REPL inside a running gr8s process; and `gr8s mcp` gives AI agents
read-only tools for the cluster. It fixes `gr8s doctor diagnose`, which in
v1.37.2-gr8s.5 failed on every unhealthy Pod, app tabs that failed on a
request header gr8s didn't know, and the latency of operations relayed between
control-plane members.

### Added

- `gr8s dashboard` has an Agent tab: terminals running AI coding agents you
  have installed (Claude Code, Codex, Gemini CLI) or your shell, on your own
  machine with your own login, and with `KUBECONFIG` naming the dashboard's
  cluster. Nothing is deployed to the cluster. **+** starts an agent in a tab
  of its own; an agent keeps running when you switch tabs or reload the page,
  and ends when you close its tab or stop the dashboard. The gear defines
  agents of your own, a name and a command line that can name the gr8s guide,
  a `gr8s mcp` server config, the kubeconfig and gr8s; they are kept in
  `$XDG_CONFIG_HOME/gr8s/dashboard-agents.json`. A terminal opens, and agents
  are defined, only from the dashboard's own page. The terminal is xterm.js,
  embedded like the other frontends (podster-2ry, podster-9et).
- `gr8s mcp` serves an AI agent read-only Model Context Protocol tools on
  stdio: `gr8s_guide` (the guide `gr8s skill` prints, which its instructions
  say to read first), `doctor_diagnose`, `doctor_impact`, `observe_flows` and
  `cluster_status`, with the kubeconfig's credentials. The dashboard's Agent
  tab registers it for Claude Code and Codex, and starts them with the guide
  in their context (podster-j53).
- `gr8s dashboard` has a REPL tab: ICL's browser REPL inside a running
  control-plane member or node agent, through the same authenticated Slynk
  tunnel as `gr8s debug icl`, with ICL started on your machine on SBCL. It
  needs ICL 1.26.0 or later, whose `--embed-origin` lets the dashboard frame it.
  A session outlives the page; Disconnect ends it.

### Fixed

- `gr8s doctor diagnose` works again on the Pods it reads closely. In
  v1.37.2-gr8s.5 the image lacked the new image-pull rules' code, so every
  unhealthy Pod was reported as a diagnosis error and the report as
  incomplete.
- Operations relayed between control-plane members are no longer slowed by
  about 45ms a message. Their gRPC connections sent small writes under Nagle's
  algorithm, and a delayed ACK held each: an exec, a log stream, a proxied
  request or a REPL through a member other than the one holding the node's
  session answered in about 90ms instead of a few. Node and member channels
  now set TCP_NODELAY at both ends (podster-1wk).
- A dashboard app tab, such as Grafana's, no longer fails requests that carry
  a header gr8s doesn't know by name, such as `X-Grafana-Device-Id`.

## [v1.37.2-gr8s.5] — 2026-11-22

Sixth trial pre-release. Flow observability: every node reports dropped
traffic and new connections, which `gr8s doctor observe`, the stock `hubble`
CLI and a Hubble UI tab in `gr8s dashboard` read, and the dashboard gains a
tab for any app the cluster declares with a `DashboardTab`. `gr8s doctor
diagnose` names why an image would not pull. It also fixes nodes
flapping NotReady under a busy stream through a member that doesn't hold their
sessions, slow proxied requests through such a member, and pulls from quay.io.

### Added

- Flow events (podster-e9a). The endpoint guards report drops, with their
  reason, and every Pod's new connections, once each (`--flow-events drops`
  limits that to Pods a NetworkPolicy isolates), to one ring per node; the agent
  names each event's Pod and keeps the last 4,096. Nothing leaves the node
  until someone asks. `GET /apis/gr8s.io/v1/flows` (and per namespace, with
  `?watch=true`) merges every node's events and names the peer and, for a
  policy drop, the NetworkPolicies isolating the Pod. **Upgrading:** a Pod
  already running reports no flow events until it is recreated, unless its
  node runs the Service packet pipeline (docs/networking.md, "Flow events").
- `gr8s doctor observe` prints flow events, filtered by namespace, Pod, node
  or verdict, once or following. `gr8s doctor diagnose` reports a Pod's recent
  NetworkPolicy drops as a finding naming the isolating policies.
- `gr8s doctor observe --serve` serves Hubble's Observer gRPC API (`GetFlows`,
  `GetNodes`, `ServerStatus`, health) on `127.0.0.1:4245` from the flows API,
  so the stock `hubble` CLI works against gr8s, with Hubble's filters applied
  as Hubble applies them.
- `gr8s dashboard` opens one page with two tabs, Headlamp and Hubble UI, both
  embedded in the image and served on one loopback port under one unguessable
  session path. Hubble UI's backend is implemented in gr8s: the namespace
  list, service map and flow table. The page has a gr8s icon. It prints only
  its URL; `--verbose` logs every request and server error to stderr.
- `DashboardTab` (`dashboard.gr8s.io/v1`, cluster-scoped) adds a tab for one
  of the cluster's apps to every `gr8s dashboard`, proxied through the cluster
  API's `services/proxy` and served from a loopback origin of its own, behind a
  per-tab secret, away from the Headlamp proxy's credentials.
- L7 flows for Gateway traffic: each HTTP request the Gateway proxy answers is
  a flow with its method, host, path (never the query string), status,
  latency and route, shown by `doctor observe`, Hubble and Hubble UI.
- On foreign clusters, `gr8s net-agent` collects its node's flow events and
  serves them on loopback (`--flow-port`, default 4246). `doctor observe` and
  the dashboard's Hubble tab reach every agent through the cluster API's `pods/portforward`
  when the cluster doesn't serve the gr8s.io API, so a reader needs only
  Kubernetes RBAC and no node opens a port.

- `gr8s doctor diagnose` reports a failed image pull as one finding named by
  the error the kubelet reported: the node's gr8s image mirror, an untrusted
  registry certificate, a rate limit, refused credentials, a missing image, an
  unresolvable or unreachable registry. The back-off and the `Failed` Event
  are listed beneath it instead of standing as two findings with generic
  advice (podster-6id).

### Fixed

- An IPv4-only Pod's interface has IPv6 turned off, so the kernel's IPv6
  link-local traffic (router solicitations, MLD reports) is no longer dropped
  and counted as spoofed by its guard.
- Nodes no longer flap NotReady while a busy operation runs through a member
  that doesn't hold their sessions. The leader relayed each frame of an
  agent's output to the member that started the operation with an RPC, inside
  the loop that also reads that agent's heartbeats, and every node's frames
  waited on one link. Following flows through such a member delayed every
  node's heartbeats past their lease. Output for another member now waits in
  a queue of its own, sent by its own thread, and a node sends its flow events
  in batches (podster-8kl).
- Requests through the `pods/proxy` and `services/proxy` subresources, and
  webhook calls, are fast again on a member that doesn't hold the node's
  session. Since v1.37.2-gr8s.3 each write the API server made on a connection
  through an agent went to the node as its own message, and through another
  member each was a round trip: about 2.3 seconds per request, so a dashboard
  tab for an app like Grafana appeared blank for minutes. A connection now sends
  what it has gathered when it is flushed (podster-tjp).
- Pulls of images not yet on a node work again from registries that redirect
  blobs to a signed CDN URL, such as quay.io. Since v1.37.2-gr8s.3 the image
  mirror escaped such a URL's query a second time, the CDN refused it with
  403, and containerd saw the mirror answer 503 and retried without end
  (podster-dq2).

## [v1.37.2-gr8s.4] — 2026-11-22

Fifth trial pre-release, to fix image pulls on Fedora 44: since
v1.37.2-gr8s.3 they failed, because registry TLS verification found no
system CA bundle there.

### Fixed

- Pulls from public registries work on Fedora 44 again. Since
  v1.37.2-gr8s.3, the image mirror verifies registry TLS against the system
  roots, but its TLS library looked only in older bundle locations, found
  none there (the bundle is /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem),
  and refused every registry with "No trusted root
  certificates available". gr8s now names the distribution's bundle in
  `SSL_CERT_FILE` at startup when neither it nor `SSL_CERT_DIR` is set
  (podster-8ak).

## [v1.37.2-gr8s.3] — 2026-11-22

Fourth trial pre-release. Agents connect to the control plane, and the control
plane never connects to an agent: the API server now reaches webhooks,
aggregated APIs and the proxy subresources through each node's own session, so
no node needs a route from the control plane. The image mirror verifies
registry TLS, with per-registry and cluster-wide private CA trust.

### Added

- `--registry-ca HOST[=FILE]` on `gr8s serve` and `gr8s agent` (repeatable)
  verifies registry HOST against FILE's CAs instead of the system roots. A
  bare HOST trusts the cluster CA, for an in-cluster registry serving a
  cert-manager certificate from the cluster's `ca` issuer.
- Cluster-wide registry trust: a ClusterTrustBundle annotated
  `gr8s.io/registries: "HOST[:PORT], ..."` makes its CAs trusted for exactly
  those registries on every node, with no restart. Adding, rotating or
  deleting the bundle takes effect from the next node snapshot; nodes keep the
  last trust they received across restarts. A host also named by a node's
  `--registry-ca` trusts both (podster-b0c).
- A control plane with no route to Pod IPs reaches webhooks, aggregated API
  servers and the `pods/proxy`, `services/proxy` and `nodes/proxy`
  subresources through the agent on the endpoint's node, as Kubernetes's
  konnectivity agent does. The agent opens the connection, and its bytes travel
  over the agent's existing session, so no node needs to be reachable from the
  control plane. An agent connects only to its own Pods and its own address.
  `serve --pod-network-egress direct` restores direct dialing (podster-he2).

### Fixed

- The Gateway proxies WebSocket upgrades. A handshake used to reach the
  backend with its `Connection` and `Upgrade` headers stripped, so the
  backend answered 400. It now replays the handshake to the backend and,
  once the backend answers 101, relays the connection both ways, past the
  listener's 20-second read timeout. The rule's rewrite and header filters
  apply as on any request (podster-1fk).
- A Certificate's `ipAddresses`, `uris` and `emailAddresses` reach the issued
  leaf's subjectAltName. They used to be dropped while the Certificate still
  reported Ready. Admission checks each IP address as cert-manager does, and
  accepts any of these lists as the subject. The controller records the
  identity a Secret was issued for, so a changed spec reissues at once
  instead of at renewal, and a Secret issued before this fix reissues once
  (podster-upj).
- An NFS volume's directory is deleted only from a node its StorageClass's
  `allowedTopologies` admits. Cleanup used to pick any Ready node, so a node
  with no route to the NFS server could take the first attempt, fail, and log
  an error before another node succeeded (podster-hlc).
- `make generate-protocol` works again. The `ocicl.csv` refresh in
  v1.37.2-gr8s.2 dropped `clingon`, which the protocol generator needs
  (podster-1gx).

### Security

- The image mirror verifies every registry's TLS certificate. It used to
  accept any certificate, so anyone on the path could answer a pull with
  their own manifest for a tag. A registry must now present a certificate
  for its name from a CA in the system roots, or one trusted for it by a
  ClusterTrustBundle or `--registry-ca`.
  A blob redirect is verified against its own host's trust, and must stay
  on https (podster-sqb). **Upgrading:** pulls from a registry with a
  private or self-signed certificate fail with a TLS verification error
  until its CA is trusted: by a ClusterTrustBundle annotated
  `gr8s.io/registries`, which nodes honor once the leader runs this release,
  or by `--registry-ca` on each node, which also covers the rollout itself
  (docs/runtime.md, "Private registries and TLS trust").

## [v1.37.2-gr8s.2] — 2026-11-21

Third trial pre-release. A cluster doctor, miniwit as the witness of a
two-member control plane, and HA hardening from live operation: every member
shows the same `resourceVersion`s and Events, a leadership handover refuses no
write, and a witness stores the log sealed from its own host.

### Added

- `gr8s doctor diagnose [KIND/NAME]` reads a cluster through `kubectl` and
  says what is wrong and why. It links workloads to the Pods they own,
  Services to the Pods they select, and Pods to their Nodes, Secrets,
  ConfigMaps and claims, and reports each cause once, with the symptoms it
  explains beneath it, in the order to fix them. Each problem quotes its
  evidence (conditions, recent Events, the last lines a crashed container
  wrote) and suggests a next step. The report is styled for a terminal and
  plain text in a pipe; `--markdown` and `--json` write it for an issue or
  for tools. It only reads, and exits 0, 1 or 2 for no problems, problems
  or incomplete coverage. The rules are Prolog, compiled into the binary
  when it is built. See [Doctor](docs/doctor.md).
- `gr8s doctor impact KIND/NAME` says what would stop working if a node,
  workload, Secret, ConfigMap or claim went away, and where a drain would
  be stopped by a PodDisruptionBudget.
- `gr8s doctor host` times flushed writes in the state directory and names
  the filesystem when they are slow: every Raft commit waits for one, and a
  slow disk looks like a network fault. It also checks that the host's
  in-kernel NFS client is available, and describes how the host firewall
  admits the cluster ports.
- `gr8s member transfer-leadership NAME` hands the leadership to a named
  voter before the leader is restarted, so no election and no write waits
  on it. It waits until NAME leads (podster-f9u).
- `--dns-serve-zone ZONE` on `serve` and `agent` serves an external zone's
  Gateway hostnames authoritatively from each node's address, so one static
  forward replaces ExternalDNS. That listener refuses every name outside
  its zones (podster-iga).
- miniwit, a small Go Raft witness for a two-member control plane. It is
  pure Go, so it cross-compiles to a static binary for any platform Go
  targets, small enough for a home router such as pfSense, and renews its member certificate from a voter thirty days before it
  expires. See `miniwit/README.md`.
- `gr8s status` warns when an HA member is ready but stuck in an
  interrupted application restore, where store-backed work fails silently.

### Changed

- Release builds move `ghcr.io/atgreen/gr8s-net:latest` to the release's
  image as well as publishing its version tag.
- Dependencies are re-pinned: ironclad 20261114 (from 20240503) and a newer
  cl-cancel; unused pins are dropped.
- `gr8s doctor` on its own prints help. The host checks are
  `gr8s doctor host`; `gr8s doctor --state-directory DIR [--fix]` still runs
  them.
- A read that names no `resourceVersion` is confirmed with the leader, as
  Kubernetes does with a quorum read of etcd. A member cut off from the
  leader used to answer with state the cluster had moved past; it now
  answers 503 with `Retry-After`, and its `/readyz` fails (podster-gxi).
- A follower carries a write to the leader itself, as the client, instead
  of redirecting the client with a 307. A client no longer loses a request
  to its own timeout when the leader it was sent to has just stopped
  (podster-l8i).
- A request that arrives while a checkpoint has the store closed waits for
  it, up to twenty seconds, and is then answered 429 with `Retry-After`. It
  used to be answered 503, which Helm does not retry (podster-j76).
- A drain that waits more than one second names the requests it waits on;
  it used to wait five. The Raft clock thread reports each pass that runs
  half a second late, with which thread held the member lock, and every
  change of role, term or leader (podster-0tg).
- cl-raft prints a WAL record once instead of twice: appending a 518 kB
  entry falls from 155 ms to 23 ms, all of it under the member lock
  (podster-9wb). cl-safe-yaml reads a single-line JSON apply in linear time;
  large CRDs applied with server-side apply took 13 to 22 seconds each.
- `gr8s network explain` authenticates through `--kubeconfig` like the other
  operator commands, and `make kubeconfig` writes an `https://` URL.

### Fixed

- HA node sessions survive checkpoints. A checkpoint quiesces the store for a
  moment, and the leader took that for lost leadership: it closed every node's
  session and refused new ones until the checkpoint finished. Agent endpoint
  lists no longer include witnesses, which have no node listener, and a session
  dial gives up after ten seconds instead of the kernel's two minutes
  (podster-htq).
- Only the member that hears a node's heartbeats expires its lease, and only
  after listening for a whole lease period. Heartbeat renewals are not
  replicated, so a follower saw every ready node with a long-expired lease,
  marked it not ready, and that write overrode the leader's fresh record until
  the next heartbeat: nodes flapped NotReady every few seconds (podster-htq).
- A member that refuses a node session because it is not the leader now names
  the members that can admit it, and the agent goes there. An agent started
  with one `--server`, or a member's own agent started before the others
  joined, could not otherwise follow a leadership change. Every session hello
  also lists those members and the agent keeps the list on disk, so it finds
  another member when the one it was configured with is gone and can say
  nothing (podster-1t0).
- `metrics.k8s.io` requests and the HPA pass no longer wait on silent nodes.
  Node metrics are collected on their own thread and a reader waits two
  seconds at most before it is served the previous collection; a request used
  to hold its store lease for the per-node timeout times the number of silent
  nodes, stalling every checkpoint drain behind it (podster-9o6).
- `gr8s doctor --fix` removes a `gr8s-services` interface that another
  cluster left behind, which made `gr8s serve` exit with `service interface
  belongs to another cluster` after a rebuild in a wiped state directory.
  `gr8s-killall.sh` now ends the containers its shims started; they used to
  survive under init and hold their host ports (podster-mg4).
- A Pod spec field set to `null` is read as omitted, as Kubernetes reads it.
  A Deployment whose chart rendered `volumes: null` was accepted and then
  never got a Pod: `spec.volumes must be an array` (podster-crv).
- Workload reconciliation preserves typed Kubernetes and runtime failures until
  rendering status. Unexpected programming errors are logged at the controller
  boundary without being reported as ordinary replica failures, and other
  workloads continue reconciling (podster-kag).
- Keep HA node streams on the active publishing leader and reconnect them after
  demotion, preventing follower-owned agents from missing later Gateway routes.
  Fail queued operations if leadership changes during their handshake (podster-c28).
- CRD CEL admission shares one request-size bound across nested unbounded
  collections, matching Kubernetes cardinality accounting. This admits the
  upstream AlertmanagerConfig CRD without raising validation cost limits
  (podster-b85).
- HTTP probes accept `httpHeaders: null` as an absent optional list, including
  server-side applied DaemonSets such as node-exporter (podster-2zo).
- API and kubelet authentication accept case-insensitive Bearer scheme names.
  This supports the Python Kubernetes client's lowercase `bearer` header while
  retaining token validation and RBAC checks (podster-xnq).
- Restarting an HA control-plane member no longer risks a restart-loop: the
  committed-application recovery wait now extends the systemd start deadline
  while it runs (`sd_notify EXTEND_TIMEOUT_USEC`), and the packaged and
  installer-generated units set an explicit `TimeoutStartSec=120s` instead
  of inheriting the host's `DefaultTimeoutStartSec` (45s on some hosts).
  Previously a member restarted into recovery — which must wait for the
  leader's dead-peer detection to drop its prior session (~15s) before it
  can catch up — could overrun a 45s start timeout and, with `Restart=always`,
  re-enter the same too-short window repeatedly without ever finishing. The
  recovery wait is deliberately unbounded (an operator ends a permanently
  lost quorum with `--cluster-reset`), so it now tells systemd it is still
  making progress rather than being killed as a hung start (podster-lmm).
- Every HA member gives an object the same `resourceVersion`. Each member
  used to count revisions for itself, so a client that read through a
  follower and then updated was refused as a conflict. Revisions are now
  taken only when a committed write is applied, and a version a member has
  not reached is answered 504. Members that already differ compare what
  they hold at one place in the log and renumber until they agree, and a
  restart or a stopped member coming back no longer sets them apart again
  (podster-gts, podster-b5d, podster-69p, podster-eb0, podster-lgi).
- Every HA member shows the same Events. An Event was stored only on the
  member it was written to, so `kubectl get events` through a follower
  showed none of a node's. A kubelet publishes a repeating Event at once
  for its first ten occurrences and once a minute after that (podster-xm5).
- A leadership handover refuses no write. Under write load each handover
  used to fail one or two (podster-f9u).
- The `kubernetes` Service leads to every member that serves the API and is
  heard from, not only to the founding member. Pods lost the API whenever
  the founder stopped (podster-bn8).
- A wiped member rejoining a busy cluster becomes a voter, and a joiner
  that waits for recovery says why every thirty seconds; that report had
  never printed. A snapshot transfer that keeps failing is logged instead
  of retried in silence (podster-kiw).
- A member whose store stays closed for a restore with no leader for three
  minutes restarts itself, the manual fix for that wedge (podster-7l9).
- A voter paused with SIGSTOP during a TLS handshake no longer exits with
  `DEADLINE-TIMEOUT` when it resumes (podster-fao).
- A checkpoint no longer ends a watch with 410 Expired, and no watch, log
  follow, exec, attach, port-forward or proxy holds its store lease while it
  writes to its client. One slow client or one `kubectl logs -f` used to
  stall every checkpoint, failing writes for up to 30 seconds. A log follow
  now ends when its client goes (podster-bbv, podster-0o5).
- A valid token is not answered 401 while a checkpoint has the store
  closed; kube-state-metrics crash-looped on that (podster-j76).
- A webhook that exceeds its timeout is reported with one message, and a
  finished HTTPS request no longer waits out its deadline (cl-cancel).
- HTTPRoutes on a gr8s Gateway get `status`, with `Accepted` and
  `ResolvedRefs`; tools reported every route as having no controller.
- The Gateway forwards the client's `Authorization` header to the backend.
  Backends that authenticate the caller, such as S3 SigV4, refused every
  request through it (podster-8lq).
- Secrets accept the `type` field selector. The Prometheus operator's
  Secret informer never synced without it (podster-rml).
- The kubelet serving certificate covers every local IPv4 address, the
  node's InternalIP included, and the kubelet reviews its callers through
  the local API server, following an HA leader redirect. Prometheus scrapes
  and `kubectl` proxies to non-founding nodes failed TLS or timed out
  (podster-6ls, podster-pxb).
- A Pod can reach a service bound to another node's host address, such as
  node-exporter or the kubelet. gr8s now SNATs that traffic in its own nft
  table on every node, with or without firewalld (podster-v7c).
- A reboot that reports a few kB less memory no longer stops the node agent
  with `Resource policies or topology changed with live reservations`.

### Security

- An HA witness stores the log sealed with AES-256-GCM under a key only
  voters hold, so Secret contents and signing keys no longer sit in
  plaintext on the less-trusted witness host. A witness certificate can no
  longer propose writes or relay operations such as exec through a voter
  (podster-00c, podster-106).

## [v1.37.2-gr8s.1] — 2026-11-17

Second trial pre-release. Hardening from live multi-node HA operation on a
roaming WireGuard cluster, plus Kubernetes-native Pod failure reporting.

### Fixed

- Follower writes no longer break on a roaming cluster: the control-plane
  API is advertised on the node's own cluster interface. The advertise
  address now considers `--node-listen` (the WireGuard address chosen for
  roaming) before scanning the host's first non-loopback IPv4, which
  returned whatever LAN address came first and stranded every follower's
  redirect — and the dashboard's auth probe — on an address unreachable
  once the node roamed off that network (podster-1ig). The advertised API
  URL is also no longer pinned as consensus identity: only the member id
  and Raft endpoint are, so a member that moves can restart with its new
  address instead of being refused and forced to re-found, and the leader
  re-advertises its current URL to the cluster so followers redirect there.
- `gr8s dashboard` (and any client probing permissions against a
  follower) no longer fails with "Error Authenticating": the Headlamp
  login check POSTs a `SelfSubjectRulesReview`, which — being a POST —
  was redirected to the Raft leader like a write. Authorization and token
  reviews are read-only evaluations every member can answer from its
  replicated RBAC, so they are now served locally instead of redirected.

- Dead peers are detected in seconds, not minutes: every node and member
  channel now sets `TCP_USER_TIMEOUT` (15s) and keep-alive probes, so a
  suspended or vanished peer surfaces as a connection error within
  ~15 seconds instead of waiting out the kernel's retransmission
  patience — after a laptop resume, the agent previously wrote
  heartbeats into a dead session for 2m22s while its node sat NotReady.
  Session-stall reports also stopped dumping unbounded structure
  graphs into the journal.

- Workloads survive control-plane restarts and upgrades: the packaged
  and installer-generated systemd units use `KillMode=process` with
  `Delegate=yes` (k3s parity), so stopping `gr8s-server` kills only the
  gr8s process — managed containerd and the container shims survive, and
  the restarted gr8s reconnects and re-adopts the running containers.
  Previously every service restart SIGKILLed the shims (they live in the
  unit's cgroup), restarting every pod on the node. Verified live: the
  same container process survived a full `systemctl restart`.
  `gr8s-killall.sh` remains the way to stop workloads too.
- Replica readiness beliefs can no longer poison node-delta replication
  (follow-up to the lease-clock fix): the replicated-node conflict check
  also ignores `ready` and `runtimeDownMessage`, which every member's
  expiry monitor flips locally at its own pace. A replica that once
  marked a node NotReady used to skip every later heartbeat delta
  forever — even one freshly rebuilt from the leader's snapshot
  re-forked within seconds. A committed heartbeat now heals the
  skipping replica's belief instead.

- `gr8s status` and `gr8s member` now work against kubeconfigs with inline
  certificate data (`certificate-authority-data` and friends) — which
  `gr8s kubeconfig` itself emits. The CLI previously failed TLS
  verification with UNKNOWN-CA unless credentials were file paths; the
  inline data is now materialized into private temporary files for the
  duration of the call, as the slynk tunnel already did.
- A stuck API request can no longer turn HA checkpointing into a standing
  outage: when the pre-checkpoint drain times out, the journal now names
  each request still holding an access lease (method, path, age), the
  compaction worker backs off exponentially (60s doubling to a 600s cap)
  instead of immediately re-entering another 30-second drain window, and
  the Slynk debug tunnel no longer takes a store lease — so it stays
  usable precisely when the store is wedged.
- Refusals that cross the wire now carry and log their reasons
  (podster-ddc): a node-session handshake answered with a protocol-error
  reports the peer's own explanation instead of a bare
  ":PROTOCOL-ERROR"; a refused Raft admission names its reason in the
  leader's journal and in the JoinResponse (new `reason` field), and the
  joiner's failure message repeats it.
- HA replicas can no longer fork over the node lease clock (podster-uvs):
  the replicated-node conflict check now ignores `lastHeartbeat`,
  `leaseDeadline` and `readySince`, which renew every few seconds on the
  session-owning member — including them gave a write racing a heartbeat
  member-dependent verdicts, so some replicas silently skipped a
  committed delta, diverged, and then conflicted on every later delta
  from the forked side (observed live as a leader marking the author
  NotReady while its handshakes were refused once a second). A member
  that does skip a genuinely conflicting committed delta now says so in
  its journal instead of staying silent.
- `gr8s doctor` now preflights the host firewall against the member's
  recorded HA endpoint: it maps the member address to its interface and
  firewalld zone and FAILs with the exact `firewall-cmd` repair when the
  raft/node/API ports are dropped — the silent join-stall we hit when a
  WireGuard interface sat in no zone. `serve` also admits the raft port
  through firewalld alongside the node and API ports.
- A joining member's catch-up is now observable (podster-84o): the
  recovery-wait journal line reports snapshot-transfer progress (bytes
  received, time since the last chunk), and an admitted learner that has
  received nothing says so explicitly with a pointer at `gr8s doctor`'s
  firewall check — previously a healthy transfer and a firewalled stall
  logged identically. `gr8s member list` no longer presents healthy
  peers as ghosts when queried on a follower: contact is reported as
  `unknown` off-leader (followers rarely message each other), with a
  note naming the leader to query.

- HA control-plane shutdown now always completes: stopping a Raft member
  bounds every worker-thread join under one deadline (10s), abandoning a
  thread that will not exit with a warning instead of hanging until
  systemd kills the process — previously an unreachable peer during a
  membership change could wedge `systemctl stop` forever.

- Pod failures now say why, in the status fields and Events `kubectl`
  already shows and worded as a kubelet words them. A missing ConfigMap
  or Secret volume — whose 404 used to escape every handler and surface
  only in the node log — now waits in `ContainerCreating` with a
  `FailedMount` Event (`configmap "x" not found`), as do other volume
  set-up failures; `CrashLoopBackOff` reports its back-off time with a
  `BackOff` Event; a failing pull is `ErrImagePull` then
  `ImagePullBackOff` (and `ErrImageNeverPull` under `imagePullPolicy:
  Never`); a container the runtime refuses to create is
  `CreateContainerError` instead of failing the whole Pod sync as
  `RuntimeError`; and an eviction raises an `Evicted` Event. The
  control-plane node-Event allowlist no longer drops `BackOff`,
  `FailedToRetrieveImagePullSecret` or `RestartingAllContainers`.

### Changed

- `gr8s skill` gains an HA troubleshooting playbook distilled from live
  incident experience: membership-first orientation, the journal lines
  that explain refusals and what each means, the member-failure decision
  tree (remove vs `--cluster-reset`), the wipe-and-rejoin checklist, and
  per-member replica forensics.

- The dashboard is no longer optional: `make native` requires the
  embedded Headlamp frontend, which is now extracted automatically from
  the digest-pinned upstream container image (podman/docker, no Node.js)
  — previously a source build without a manual asset step silently
  shipped no dashboard. Release builds use the same pinned image instead
  of an npm build from a Headlamp checkout;
  `make dashboard-assets-from-source` remains for hacking on Headlamp.

- `gr8s doctor` gains `--fix`: pod-pool route overlaps caused by a killed
  instance's leftovers (stale `gr8s-vxlan`/`gr8s-gateway`/`gr8s-services`
  links, orphan pod veths) are deleted when the link is provably
  gr8s-owned, instead of crash-looping the next startup. The startup
  refusal now names the offending interface and points at the fix.
- The packaged and installer-generated systemd services report readiness
  (`Type=notify`): `active` now means the API or node is serving, not
  merely that the process started, and repeated startup failures stop in
  `failed` after five attempts instead of restarting forever. The RPM/DEB
  config files pin `--state-directory` to `/var/lib/gr8s/server` and
  `/var/lib/gr8s/agent` rather than inheriting root's XDG default.
- Gateway reconciliation reuses unchanged routing and discovery data and wakes
  promptly for committed updates, reducing repeated work as route counts grow.
- Foreign-cluster Gateways isolate listeners, routes, and TLS material even when
  they share ports and hostnames. Gateway HTTP handling now covers hostname
  intersection, listener admission, backend and certificate ReferenceGrants,
  and invalid-reference status; the recorded candidate passed all 36 Gateway
  API v1.6.3 HTTP core conformance tests.
- `gr8s serve` joins a control-plane cluster with the same flags as
  `gr8s agent` and `gr8s witness`: `--join HOST:PORT`, `--token`, and
  `--ca-pin`. The token is bound to `--node-name`, which also names the Raft
  member unless `--raft-id` is given. `--raft-join`, `--raft-token`,
  `--raft-ca-pin`, and `--raft-node-name` are removed.

### Added

- `gr8s serve --mtu N`: the Pod interface MTU handed to every node
  (default unchanged: 1450, or 1420 for the wireguard backend). Needed
  when the node underlay is itself a tunnel — over a WireGuard underlay
  (MTU 1420), the default overlay frames overflow and fragment; `--mtu
  1370` leaves room for the vxlan overhead.
- `gr8s member`: operator-facing HA membership. `list` shows every durable
  control-plane member with role, address, leadership and contact state —
  a voter never heard from is flagged as a ghost — and `remove NAME`
  proposes dropping a member through the leader (it commits once the
  remaining voters agree). Backed by
  `GET/DELETE /apis/gr8s.io/v1/controlplanemembers`.
- `gr8s serve --cluster-reset`: the escape hatch for an HA cluster whose
  voting majority is permanently gone. It rewrites the durable membership
  to the surviving member alone — committed application entries and the
  snapshot baseline are preserved, membership changes are neutralized so
  replay cannot resurrect the lost configuration — and continues serving
  as the sole voter. While recovery waits for a quorum, the journal now
  says why: the quorum arithmetic, each member, and which peers have not
  been heard from. See
  [disaster recovery](docs/backup-restore.md#disaster-recovery-a-quorum-lost-forever).
- `gr8s status`: one screen of cluster health from anywhere a kubeconfig
  reaches — API readiness, nodes, workload exceptions, Services without
  endpoints, storage, version skew, and deduplicated recent Warning
  events, each warn/fail line naming the next command to run. `--output
  json` for agents; exit 0/1/2 for healthy/warnings/failures.
- `gr8s backup` (`keygen`, `save`, `verify`) and `gr8s restore`: offline
  operator backup of a control-plane state directory — cluster identity,
  keys, and the Raft store — into one encrypted, authenticated bundle,
  and verify-then-publish restore into a fresh state directory
  ([guide](docs/backup-restore.md)).
- RPM and DEB packages for amd64 and arm64, attached to each release. They
  install `/usr/bin/gr8s`, `gr8s-killall.sh`, and disabled `gr8s-server` /
  `gr8s-agent` systemd units configured through `/etc/gr8s/*.env`. A tag
  `v<k8s>-gr8s.<n>` maps to package version `<k8s>+gr8s.<n>` with packaging
  revision 1 in both formats.

- Failure and pressure metrics: `/metrics` exports
  `gr8s_endpoint_policy_drops_total` (the NetworkPolicy drop counter the
  guards kept but never published; inbound policy drops now also count in
  `dropped_packets`, as outbound ones always did), and
  `/metrics/cadvisor` adds `container_oom_events_total` and the PSI
  pressure-stall series. Node pressure conditions now carry the kubelet's
  own messages.

- ListenerSet support for foreign-cluster Gateways, with stable and experimental
  API discovery, explicit namespace admission, shared-port HTTPS certificates
  selected by SNI, isolated HTTP routing, incremental updates, and installed-state
  status. See the [setup and design notes](docs/design-listenersets.md).
  Small VM acceptance covers both APIs; full-scale benchmarking is deferred.

## [v1.37.2-gr8s.0] — 2026-11-15

Initial release, marked pre-release as a trial.

gr8s arrives as a single-binary, Kubernetes-compatible cluster — control
plane (`gr8s serve`), worker agent, HA quorum witness, Raft datastore, and
embedded containerd/runc — that passed 100% of the upstream Kubernetes
v1.37 `certified-conformance` suite (462/462) in a recorded two-node run
([evidence](docs/CONFORMANCE.md)). The same binary provides network
services to clusters gr8s did not create: `gr8s net-agent` with
independently selectable features — `cni` (Pod networking, IPAM, VXLAN or
encrypted WireGuard overlay, eBPF NetworkPolicy, hostPort), `service-lb`
(an eBPF kube-proxy replacement), and `gateway` (Gateway API and Ingress)
— packaged as the `gr8s-net` Helm chart (0.2.0) and the
`ghcr.io/atgreen/gr8s-net` container image.

Running clusters are debuggable live through `gr8s debug slynk`
(authenticated Slynk tunnel), `gr8s debug icl` (ICL's browser IDE on a
node's live image), and `gr8s debug trace` (selector-scoped kernel tracing
in a bpftrace-compatible language, JIT-compiled to eBPF by Whistler), and
explorable through the integrated Headlamp dashboard (`gr8s dashboard`).
Internal TLS 1.3 is pure Lisp with hybrid X25519MLKEM768 key exchange; no
OpenSSL. Release artifacts cover Linux amd64 and arm64: binaries with
checksums, tarballs carrying the installer and lifecycle scripts, and
CycloneDX and SPDX SBOMs for the Lisp dependencies.

[Unreleased]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.9...HEAD
[v1.37.2-gr8s.9]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.8...v1.37.2-gr8s.9
[v1.37.2-gr8s.8]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.7...v1.37.2-gr8s.8
[v1.37.2-gr8s.7]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.6...v1.37.2-gr8s.7
[v1.37.2-gr8s.6]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.5...v1.37.2-gr8s.6
[v1.37.2-gr8s.5]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.4...v1.37.2-gr8s.5
[v1.37.2-gr8s.4]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.3...v1.37.2-gr8s.4
[v1.37.2-gr8s.3]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.2...v1.37.2-gr8s.3
[v1.37.2-gr8s.2]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.1...v1.37.2-gr8s.2
[v1.37.2-gr8s.1]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.0...v1.37.2-gr8s.1
[v1.37.2-gr8s.0]: https://github.com/atgreen/gr8s/releases/tag/v1.37.2-gr8s.0
