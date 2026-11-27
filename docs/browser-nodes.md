<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Browser nodes: running them

A browser node is a web browser tab that has joined the cluster as a worker. The
visitor opens a page; the tab becomes a node named `browser-XXXXXX`; Pods that
tolerate browser nodes run inside it, each in its own
[unkernel](https://github.com/pithings/unkernel) Linux VM compiled to
WebAssembly. This page covers how to offer browser nodes from a cluster. The
design, and what each part does, is in
[design-browser-nodes.md](design-browser-nodes.md).

## Turn it on

Browser nodes are served by `gr8s serve`:

```console
gr8s serve --browser-listen 127.0.0.1:8099 --browser-distro /var/lib/gr8s/browser/alpine.erofs
```

| Option | Meaning |
|--------|---------|
| `--browser-listen HOST:PORT` | Serve the join page and the tabs' sessions there. Required. |
| `--browser-distro FILE` | The root image (erofs) each Pod's VM boots: unkernel's Alpine image, from the unkernel release the page loads. |
| `--browser-max-nodes N` | At most N browser nodes connected at once (default 64). |
| `--browser-max-per-client N` | At most N of them from one client address (default 4). |
| `--browser-stun-listen HOST:PORT` | Answer the tabs' STUN requests on UDP, so tabs behind NATs connect directly. |
| `--browser-ice-server URL` | Also give tabs this `stun:` or `turn:` server. Repeatable. |
| `--browser-peering MODE` | Which tabs connect directly: `all`, `same-network` (the default) or `none`. |
| `--browser-forward-client-address BOOL` | Whether checked content tells the Pod the visitor's address (default `true`). See below. |

The node agent must be enabled (it is by default): browser Pods get their
addresses through a TAP device on the serving host, which needs
`CAP_NET_ADMIN`. Without it, browser nodes still run Pods, but the Pods have no
network address.

Other sites can't make their visitors nodes: the join page refuses to be framed, and its WebSocket accepts only
the join page's own origin (clients that aren't browsers send none, and are let in).

A browser past the limits is told why on the join page and doesn't join. The
client address is the one the Gateway forwards in `X-Forwarded-For`, so put the
join listener behind the Gateway rather than exposing it directly.

## Publish the join page over HTTPS

The page must be served over HTTPS (or from `localhost`): a tab proves its
identity with a WebCrypto key, and browsers offer WebCrypto and WebGPU only in a
secure context. Route a hostname to the join listener through the Gateway, with a
certificate from the cert-manager `acme` issuer:

- a Service with no selector, and an EndpointSlice naming the join listener's
  address and port;
- an HTTPRoute from the public hostname to that Service;
- a ClusterIssuer with `spec.acme` (Let's Encrypt over HTTP-01, which the
  Gateway answers) and a Certificate for the hostname.

[`examples/browser-demo/demo.yaml`](../examples/browser-demo/demo.yaml) is the
complete set of manifests behind demo.gr8s.io; change its hostnames, address and
email for another host.

Open TCP 80 and 443 to the Gateway, and, with `--browser-stun-listen`, the STUN
port over UDP (3478 is the usual one).

## Who connects to whom

Tabs reach each other's Pods over WebRTC data channels when they can, and through
the server when they can't: a tab behind a strict NAT still works, only through a
longer path. Tabs that connect directly learn each other's public address, so
`--browser-peering` decides which may:

- `same-network`: only tabs whose browsers come from one client address.
- `all`: every pair of tabs. The join page tells visitors so.
- `none`: every packet goes through the server.

With STUN served, tabs on different networks can connect directly; without it,
only tabs that can reach each other's local addresses do. A tab that can't reach
a peer tries again after 10 s, then less and less often, up to every 10 minutes.

Tabs also give each other image layers, over the same BitTorrent protocol gr8s's
agents use, under the same peering rule. Each piece is checked against the layer's
digest; the server always has every piece too.

## Run Pods on them

Browser nodes carry the taint `gr8s.io/browser=true:NoSchedule` and the label
`gr8s.io/browser=true`, and their architecture is `arm64` whatever the
visitor's CPU. A Pod for them tolerates the taint and uses a `linux/arm64` image:

```yaml
spec:
  nodeSelector: {gr8s.io/browser: "true"}
  tolerations: [{key: gr8s.io/browser, operator: Exists}]
```

Browser nodes refuse Pods that bring a Secret (as a volume, projection or
environment variable), a host path, privileges or host namespaces. Private
images work: the server pulls them with the Pod's `imagePullSecrets`, which never
reach the browser.

Browser Pods use cluster DNS and reach Services by name or ClusterIP, and other
Pods by address, over IPv4 only: the server passes a tab's IPv4 from its Pods'
own addresses, and ARP for them, and drops everything else, IPv6 included.
NetworkPolicy applies to them, with one gap: traffic sent
directly between tabs is checked against the receiving Pod's ingress policy, but
not yet the sending Pod's egress policy.

## Serve web content from tabs

A browser node is untrusted: whoever runs the tab can change what its Pods do. For
static content the server can check every response. Annotate a Service whose
Pods run on browser nodes:

```yaml
metadata:
  annotations:
    gr8s.io/verified-content-root: /usr/share/nginx/html
```

The join listener then serves it at `/verified/NAMESPACE/SERVICE/`; route a
hostname there with an HTTPRoute `URLRewrite` (`ReplacePrefixMatch`). Each
response passes only if it is byte for byte the file under that directory in the
image the server pulled. Only files the image holds are asked for, by their plain
path; anything else is answered 404 without asking a tab. A tab that answers 200
with other bytes fails the request and its node is tainted
`gr8s.io/tampered:NoExecute`; any other answer (an error, a redirect) just fails
the request, as an honest tab can give one. The server can fill in
`<!--gr8s:node-->`, `<!--gr8s:pod-->`, `<!--gr8s:image-->` and similar
placeholders after the check.

The Pod is asked as a reverse proxy would ask it: with the visitor's `User-Agent`,
`Referer` and `Accept-Language`, `X-Forwarded-Proto` and `X-Forwarded-Host`, and the
visitor's address as `X-Forwarded-For` and `X-Real-IP`. A web server logs the
connection's own address, the gateway on the tab's network device, unless told to
believe those headers from it (nginx: `set_real_ip_from` the Pod range and
`real_ip_header X-Forwarded-For`). The tab's owner can read its Pod's logs, so on a
cluster whose tabs are strangers', as a public demo's are, run `serve` with
`--browser-forward-client-address false`: the Pod is then not told who the visitor is,
only what browser they use.

## GPUs

A tab whose browser has a hardware WebGPU adapter offers it: its node gets
capacity `gr8s.io/gpu: 1` and labels `gr8s.io/gpu-vendor` and
`gr8s.io/gpu-architecture`. A Pod that asks for it gets Vulkan 1.2 on that GPU:

```yaml
resources:
  limits: {gr8s.io/gpu: "1"}
```

The image brings the Vulkan loader (`libvulkan1` on Debian); gr8s gives the
container the driver. The driver needs glibc, so use a Debian, Ubuntu or UBI
image. Software adapters (SwiftShader) aren't offered. Like a tab's CPU and
memory, the GPU is what the browser says it has.

## Upgrades and restarts

When the server restarts, every tab's session ends. A tab the visitor didn't
leave waits for the server to answer again and reloads itself, rejoining under
the same name; its Pods are started again. The join page is never cached, and it
loads the tab's code at a URL naming its hash, so after an upgrade every tab runs
the new code.

## Watch them

```console
kubectl get nodes -l gr8s.io/browser=true
```

The API server's `/metrics` has `gr8s_browser_nodes`, `gr8s_browser_node_pods`,
`gr8s_browser_node_rtt_seconds` and the other `gr8s_browser_*` families. The join
page shows its visitor the node, the cluster, and under each Pod a drop-down with
its containers' logs and its VM's console, read from the tab itself.

A node whose tab is gone goes NotReady when its lease expires, and is removed
after a grace period.
