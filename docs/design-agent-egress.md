# Agent egress control and credential injection

> **Status:** implemented (podster-wv1w, 2026-11-25), with the differences and
> limits listed under *As built* at the end. The design below is as proposed.

## Goal

Make gr8s a safe place to run AI agents: a prompt-injected agent should have
nothing worth stealing and nowhere to send it. Two capabilities, both declared as
Kubernetes resources and enforced by the gr8s node agent:

1. **Egress control by hostname.** A selected Pod reaches only the hosts its
   policy names, and nothing leaves by another route: not raw TCP, not QUIC, not
   DNS queries.
2. **Credential injection.** The Pod never holds a real API key or token. The
   node agent adds the credential, from a Secret, to requests bound for the
   destinations a policy names, and only those.

`gr8` (see the podster-0ii epic) is the first consumer, but nothing here is
specific to it: an agent Deployment elsewhere in the cluster gets the same
protection from the same resources, selected by label.

## Threat model

The agent process is assumed hostile after a prompt injection: it runs arbitrary
code as the Pod's user, may be root inside its container, and wants to send a
secret, or data it read, to an attacker. It may ignore `HTTPS_PROXY`, open raw
sockets, use QUIC, encode data in DNS query names, or send a valid credential to
an allowed host that the attacker controls an account on (a GitHub gist).

Out of scope: a compromised node agent (it already holds the node's Secrets),
timing side channels, and data the agent sends *inside* a request to an allowed
destination with its own credential (an LLM API call carrying the stolen data in
its prompt). The last is why the allowlist should be as narrow as the task allows.

## Prior art

| Project | Shape | What we take |
|---|---|---|
| [network-policy-api `ClusterNetworkPolicy`](https://network-policy-api.sigs.k8s.io/reference/spec/) v1alpha2 | Cluster-scoped, tiered policy; experimental `domainNames` egress peer, Accept rules only | Serve it natively for hostname egress, as gr8s serves cert-manager |
| [OpenKruise Agents `SecurityProfile`](https://openkruise.io/kruiseagents/user-manuals/security/credential-injection) (`agents.kruise.io/v1alpha1`) | Label selector; rules matching domains, paths, methods, schemes; `tokenTransformation` rewrites named headers from a Secret; fail-closed | The resource shape for credential injection (see the decision below) |
| [Agent Substrate](https://github.com/agent-substrate/substrate) egress | Per-actor `EgressPolicy` in its own gRPC API (not Kubernetes objects); TLS-terminating gateway; DNS relay that forwards only policy names | DNS gating; the trust-bundle approach |
| [kubernetes-sigs/agent-sandbox](https://agent-sandbox.sigs.k8s.io/docs/use-cases/examples/network-policy-api-sandbox/) | `Sandbox`/`SandboxTemplate`; NetworkPolicy per template; ClusterNetworkPolicy for cluster-wide egress | Confirms ClusterNetworkPolicy as the upstream egress story |
| [KeyFence](https://github.com/atgreen/keyfence) | Per-user MITM proxy swapping opaque `kf_` tokens | The design pressure: destination-locked credentials, audit, fail-closed |

## Resources

### 1. NetworkPolicy: addresses and ports

Unchanged. A namespace that runs agents should carry a default-deny egress
policy. This depended on fixing security deviation F5 (podster-5hv.10, done):
DNS, the API server and the node's own address used to bypass egress policy.

### 2. ClusterNetworkPolicy: hostnames

gr8s serves `policy.networking.k8s.io/v1alpha2` `ClusterNetworkPolicy` natively
(do not also install the upstream CRDs; see *Built-in APIs* in `gr8s skill`). The
first scope is what agent egress needs: Pod selection by namespace and Pod
labels, egress rules with `domainNames` (Accept), CIDR and Pod peers, and a
lower-precedence Deny to turn the accepts into an allowlist.

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
    - domainNames: [api.anthropic.com, platform.claude.com, raw.githubusercontent.com]
  - action: Deny
    to: [{networks: ["0.0.0.0/0", "::/0"]}]
```

Field names follow the v1alpha2 reference; verify them against the current
release before implementing. `domainNames` is experimental upstream.

**Enforcement differs from upstream's DNS-snooping implementations on purpose.**
Allowing the IP addresses a name resolved to is weak here: most API hosts sit
behind shared CDN addresses, so the IP admits every other site on it. gr8s
instead sends a selected Pod's TCP connections to the node egress proxy (below),
which admits a connection by its TLS SNI or HTTP `Host`, never by its address.

### 3. Credential injection

The real credential stays in a Secret. A policy binds it to destinations and
Pods. The proxy overwrites the named header on matching requests, whatever the
agent sent; the agent only needs *some* value so its client sends the header.

```yaml
apiVersion: v1
kind: Secret
metadata: {name: anthropic, namespace: gr8}
stringData: {apiKey: sk-ant-...}
---
apiVersion: agents.kruise.io/v1alpha1     # see the decision below
kind: SecurityProfile
metadata: {name: claude-anthropic, namespace: gr8}
spec:
  selector:
    matchLabels: {gr8s.io/gr8-command: claude}
  rules:
  - name: anthropic-api-key
    match:
    - domains: [api.anthropic.com]
      schemes: [https]
      paths: [{type: Prefix, value: /v1/}]
    actions:
      tokenTransformation:
        type: ApiKey
        failStrategy: Block
        credentialRef: {secret: {name: anthropic}}
        apiKey:
          targetHeaders: {names: [x-api-key]}
          value: {template: "{{ .Token }}"}
```

**Decision: whose API group.** Two options:

- *A compatible subset of OpenKruise's `SecurityProfile`* (recommended). It is the
  closest existing Kubernetes-native shape, and serving it natively follows the
  cert-manager precedent: manifests carry over between gr8s and Kruise Agents
  clusters. gr8s would accept only what it implements (selector, `match` with
  domains/paths/methods/schemes, `tokenTransformation` `ApiKey` with
  `targetHeaders.names` and a `{{ .Token }}` template, `credentialRef.secret`,
  `failStrategy: Block`) and reject the rest at admission. Risks: it is
  `v1alpha1` in a project gr8s doesn't control, and a cluster that also installs
  Kruise Agents would register the group twice.
- *A gr8s group* (`egress.gr8s.io/v1alpha1`) with the same field names, so a
  later move to an upstream standard, if one appears, is a rename.

### 4. Trusting the proxy's CA

Injection needs TLS termination for the hosts that carry a credential, and only
those; every other allowed host passes through undecrypted, by SNI. The node
agent signs per-host certificates from a gr8s CA published as a
`ClusterTrustBundle` (for example `gr8s.io:egress`). A Pod trusts it through a
projected `clusterTrustBundle` volume combined with the system roots, plus
`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE` and `GIT_SSL_CAINFO`.
gr8s already serves both pieces. `gr8` does this automatically for its
sandbox; other Pods declare the volume themselves.

### 5. gr8 sandbox profiles

Which host paths a command gets is `gr8`-specific and has no upstream analog
(agent-sandbox's `SandboxTemplate` describes a Pod, not grants into a user's
home), so it is a gr8s resource:

```yaml
apiVersion: gr8.gr8s.io/v1alpha1
kind: SandboxProfile
metadata: {name: claude}
spec:
  commands: [claude]
  home:
    readWrite: [.claude, .claude.json]
    readOnly: [.gitconfig, .config/git]
  env:
    ANTHROPIC_API_KEY: gr8s-injected   # a placeholder the proxy overwrites
```

`gr8` reads the profile for its command from the cluster in place of its
built-in table. The Pod's labels then select the egress and credential policies
above; `gr8` needs no policy logic of its own.

## Enforcement in the node agent

**Why the node agent, not a sidecar.** The node agent is already authorized to
read the Secrets of the Pods it runs, so injecting credentials for those Pods
gives it no new authority. A sidecar proxy in the Pod can be bypassed by a
container with `NET_ADMIN` (a documented limit of OpenKruise's sidecar), needs
Pod-spec injection, and fails for Pods taken from a warm pool. In the node agent,
none of these apply.

- **Capture.** For a Pod selected by any egress or injection policy, the agent's
  cgroup connect hook (the mechanism the Service load balancer already uses)
  rewrites every outbound TCP connect to the node egress proxy, recording the
  original destination by socket cookie. UDP 443 is refused, so QUIC clients
  fall back to TCP. Other UDP and raw sockets follow NetworkPolicy, which denies
  them by default.
- **Admission.** The proxy reads SNI (TLS) or `Host` (HTTP) and admits the
  connection only if a policy for that Pod names the host. It never admits by
  destination address.
- **Injection.** For hosts with a matching injection rule, the proxy terminates
  TLS with a certificate for that host, applies the rule's header rewrite with
  the Secret's current value, and opens a fresh TLS connection to the origin.
  A missing or unreadable Secret fails closed (`failStrategy: Block`).
- **Pod identity** comes from the socket's cgroup, which the kernel binds at
  socket creation, not from the source address.
- **DNS.** For a selected Pod, the node DNS server forwards only names its
  policies name (wildcards at a label boundary) and answers `REFUSED` for the
  rest, so query names stop being a channel. This replaces the F5 bypass for
  these Pods.
- **Authorization.** The node authorizer must let the agent read a Secret that
  an injection policy references, for a Pod bound to that node, and nothing
  more. This extends the graph that already covers volume and env Secrets.
- **Reuse.** TLS termination, certificate minting and HTTP forwarding come from
  the Gateway proxy (`src/controllers/gateway-proxy.lisp`); SNI routing from
  `gateway-router.lisp`.

## Observability

The proxy reports one flow event per request: Pod, host, method, path, the rule
that injected a credential (never the credential), and the verdict. These join
the existing flow stream and its OTLP export, so the dashboard's Network view
shows requests on a Pod's edges and refusals in red. That is the per-run audit
trail: what this agent asked for, and what it was refused.

## Not in the first version

- **OAuth subscription logins** (Claude Code's `~/.claude/.credentials.json`):
  the refresh exchange returns new real tokens in a response body, which the
  proxy would have to replace with placeholders while keeping the real ones.
  API keys and bearer tokens first.
- Credentials used locally to sign (AWS SigV4, minted JWTs).
- Client certificates and SSH keys (KeyFence handles both; later).
- Namespaced hostname rules: `ClusterNetworkPolicy` is cluster-scoped, so a
  namespace owner can't write one. Add a namespaced form only if needed.

## Milestones

1. F5: gate the DNS, node and API-server bypasses with policy (podster-5hv.10).
2. Serve `ClusterNetworkPolicy` v1alpha2 for the scope above.
3. Node egress proxy: capture, SNI/Host admission, QUIC refusal, DNS gating.
4. Credential injection: the injection resource, node-authorizer grant, TLS
   termination, the egress `ClusterTrustBundle`.
5. gr8: `SandboxProfile`, trust bundle and placeholder env in the sandbox,
   policies selected by the Pod's labels.
6. Request-level flows in the dashboard.
7. OAuth subscription tokens.

## As built

- **Secrets reach nodes with Pod assignments**, not through a new node-authorizer
  rule: the control plane adds the Secrets of the SecurityProfiles selecting a Pod to
  that Pod's assignment, and the node accepts them only when a profile in its snapshot
  selects the Pod. The scoping is the one proposed above.
- **One cluster-wide egress CA** (`kube-system/gr8s-egress-ca`), carried to every node
  in its snapshot, so any node can mint leaves for the Pods it runs. A per-node CA,
  so one node's key can't mint for another's Pods, is follow-up work.
- **Synthetic addresses** (podster-wv1w.8, after OpenShell's policy DNS). A Pod with a
  hostname allowlist gets answers from `198.18.0.0/15` that stand for the names, and may
  reach only that range by TCP; the proxy reads the name from the dialled address, so
  protocols that name nothing (Postgres, Redis, SSH) are admitted by name, it dials only
  the real addresses pinned with the answer, and it refuses a TLS SNI that names
  another host. A mapping is keyed by address for the whole node, not by Pod: every
  connection is decided by the dialling Pod's current policy, so a guessed address
  reaches nothing its real one wouldn't. For the same reason a Pod that loses its
  allowlist keeps reaching cached answers through the proxy, decided by its new policy,
  so there is no separate grace period. Pods captured only by a SecurityProfile keep
  real answers and SNI/Host admission. Only A answers are synthesized; AAAA and other
  types get no data. UDP other than DNS and QUIC's 443 is still left to address policy.
  A node whose own address is in `198.18.0.0/15` is not detected.
- **A gr8 sandbox is always confined** (podster-1mzb). A Pod labelled
  `gr8s.io/gr8-command` is captured and synthetic whether or not a policy names hosts,
  and its egress ends with a built-in Deny of `0.0.0.0/0` and `::/0` (`gr8-sandbox`)
  below every policy's rules, so it reaches what Admin rules, its NetworkPolicy and
  Baseline rules allow and nothing else. With no policy, its DNS answers nothing outside
  the cluster zone and it reaches only the egress proxy. Its host-redirect table holds
  the proxy alone: the API server and the node's own addresses, which other Pods reach
  past policy (podster-5hv.10), are decided by policy for it.
- **`gr8 --allow NAME`** (podster-xazj) creates a ClusterNetworkPolicy named after the
  run's Pod that accepts NAME for that Pod alone, selected by its `gr8s.io/gr8-run`
  label, and deletes it when the Pod goes. Whether a user may is RBAC on
  `clusternetworkpolicies`; nothing on the Pod widens its own egress.
- **The command waits for its policy** (podster-ae08). A gr8 Pod has the readiness gate
  `gr8s.io/NetworkReady`. The node reports it True once the view its policy, capture and
  DNS gate are written from has the Pod's address, and gr8 starts the command when the
  Pod is Ready. Before, a command's first lookups could fail for up to half a second.
  gr8 gives a node that never reports the condition two seconds. Two things made that
  window: the control plane resolved a policy's subject only from Pods with an address,
  so the node learned a new Pod was selected one round trip after its address; and a
  deleted Pod's address, already given to a new Pod, could still resolve to the old
  Pod. A subject is now resolved from every nonterminal Pod, and a live Pod owns an
  address over one being deleted or finished.
- **Capture is IPv4.** A captured Pod's IPv6 TCP is left to address policy.
  Private, shared and link-local destinations are exempt from capture (address policy
  applies to them as before), and a captured Pod can't reach a public address by IP
  alone: the redirect keeps the port, not the address.
- **Domain fronting.** A TLS connection the proxy doesn't terminate is admitted by its
  SNI; a different Host inside it reaches whatever that server routes it to. Hosts
  with an injected credential are terminated, and their Host is checked.
- **The DNS gate** is a small server on the proxy address: cl-dns-proxy's hooks don't
  see the client, so captured Pods' DNS is redirected to the gate, which relays allowed
  names to the node DNS server.
- **OAuth subscription logins** (podster-wv1w.7) work without the refresh exchange:
  `gr8 login claude` stores the access token for injection, the sandbox sees the
  credentials file with stand-in tokens and a far-off expiry so it never refreshes,
  and gr8 keeps the Secret in step with the host's credentials file, which the
  host's own claude refreshes. Rewriting the refresh exchange itself is follow-up work.
- **Verification.** Unit and in-process tests cover policy compilation, the proxy
  (pass-through, refusal, cleartext and TLS injection), the DNS gate, the CA and the
  APIs; the endpoint guard, socket hooks and sk_lookup steering ran on a real kernel
  (`test-endpoint-policy-kernel`, `test-service-lb-program --kernel`,
  `test-egress-steering-kernel`). A full multi-node run in VMs is follow-up work
  (podster-62dq).
