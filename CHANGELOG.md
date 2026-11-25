# Changelog

Notable changes to gr8s. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions combine
the Kubernetes API version with a gr8s release suffix (see
[Versioning](README.md#versioning)).

## [Unreleased]

### Added

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
- Flow events name a peer outside the cluster by the DNS name a Pod looked up
  to reach it (`peerName`), as the node's DNS server saw it answered
  (podster-5hv.8), and the Network tab draws each such site as a node of its
  own: `grafana → secure.gravatar.com` instead of `grafana → world`.

### Removed

- `gr8s dashboard`'s Hubble tab, and the Hubble UI bundle it embedded: the
  Network tab replaces it. The Hubble API stays: `gr8s doctor observe --serve`
  still serves Hubble's Observer API for the `hubble` CLI.

### Fixed

- The dashboard's Hubble tab draws a workload's replicas as one card. Each Pod
  had its own identity, so a Deployment of four showed as four identical cards;
  identities now follow a Pod's namespace and labels, leaving out the labels that
  tell replicas apart (`pod-template-hash` and the like), as Cilium's do
  (podster-u0e).
- A NetworkPolicy no longer cuts an idle connection after two hours. The policy
  guards admitted a TCP connection's replies for 2 hours after its last packet,
  exactly Linux's default `tcp_keepalive_time`, so an idle pooled connection's
  first keepalive arrived just too late, was dropped, and the connection died
  (seen with Postgres). Replies now stay admitted for 5 days, as conntrack keeps
  an established connection; the flow maps are LRU, so this costs no memory
  (podster-af3).
- A new Pod's first connections to Pods behind an ingress policy on other nodes
  are refused for much less time: about half a second, under TCP's first
  retransmission, rather than up to 7-11 seconds under load. The agent reports a
  Pod's new address at once instead of at its next 7-second status report, and
  the control plane sends it to the other nodes at once instead of on its next
  one-second pass (podster-auf).
- `gr8s dashboard` no longer burns a CPU core after a watch ends. When the
  cluster ended a watch (a member restarting, say), the relay closed the
  browser's socket while its reader thread was still waiting on it, and that
  thread then polled the dead descriptor without pause, for as long as the
  dashboard ran. The dashboard's other relays (the multiplexer's watches and
  the REPL tab's tunnel) had the same race. A relay now only shuts a socket
  down to wake a reader, and closes it once the reader has finished
  (podster-gek).
- `gr8s doctor diagnose` and `impact`, and the MCP doctor tools, read the cluster
  with gr8s's own API client instead of running `kubectl`, so they work on a host
  without it, such as a control-plane member, where they defaulted to the
  member's own kubeconfig. Before, every kind came back "unknown" with no reason.
  A failed read now says why (the HTTP status and the server's message, or that
  it didn't answer), and the standalone `scripts/gr8s-doctor`, which still uses
  `kubectl`, says when it can't run it (podster-71m).
- `kubectl apply` of a Service whose ports changed works. A strategic merge patch
  to a Service was applied as a plain JSON merge patch, so the directives kubectl
  sends (`$setElementOrder/ports`, `{"$patch": "delete"}`) were rejected as
  unknown fields (422), and a patch naming one port replaced the whole list.
  Services now merge as upstream does, ports keyed by their port number
  (podster-0i0).
- `gr8s doctor` refuses a word that is neither a command nor a directory, and
  suggests the command meant: `gr8s doctor diagnosis` checked an empty
  `./diagnosis/` state directory, found the node's live routes stale, and
  advised a `--fix` that would have torn them down (podster-m6w).
- `gr8s status` compares each control-plane member's own `/version` too, so a
  member without a Node (`serve --disable-agent`) on another release shows as
  skew (podster-gta).
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
- `/stats/summary` reports the node's filesystem (`node.fs`): the one under
  `/var/lib/kubelet`, which DiskPressure watches. Headlamp shows it as the node's
  ephemeral storage, and left that empty on every node (podster-b55).
- A Node's `Ready` condition carries its `lastTransitionTime`: when the node's
  ready lease began, or for a node that isn't ready, when it was last heard from.
  Headlamp works out a node's uptime from it, and showed "NaNy" (podster-zac).

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

[Unreleased]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.8...HEAD
[v1.37.2-gr8s.8]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.7...v1.37.2-gr8s.8
[v1.37.2-gr8s.7]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.6...v1.37.2-gr8s.7
[v1.37.2-gr8s.6]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.5...v1.37.2-gr8s.6
[v1.37.2-gr8s.5]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.4...v1.37.2-gr8s.5
[v1.37.2-gr8s.4]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.3...v1.37.2-gr8s.4
[v1.37.2-gr8s.3]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.2...v1.37.2-gr8s.3
[v1.37.2-gr8s.2]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.1...v1.37.2-gr8s.2
[v1.37.2-gr8s.1]: https://github.com/atgreen/gr8s/compare/v1.37.2-gr8s.0...v1.37.2-gr8s.1
[v1.37.2-gr8s.0]: https://github.com/atgreen/gr8s/releases/tag/v1.37.2-gr8s.0
