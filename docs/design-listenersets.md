# ListenerSet support for foreign-cluster Gateways

Status: stages 1–5 below are landed — discovery/adapters and watches,
admission/merge and reverse indices
([`gateway-listenersets.lisp`](../src/controllers/gateway-listenersets.lisp)),
shared-port SNI TLS dispatch, route attachment, and status including
`attachedListenerSets`, with the discovery order and `--listenerset-api-group`
selection described under "Enabling ListenerSets". Only stage 6, full-scale
validation, remains: full-scale and doubling runs have not been demonstrated.
Current VM validation is limited to two Gateways, at most six routes, and a few
ListenerSets.
This records the explicitly permitted decomposition of podster-dk9. HTTP core
conformance does not cover it.

## Required workload and API compatibility

The target is 2,500 ListenerSets and TLS Secrets, with 16 HTTPRoutes per set
(40,000 routes) per Gateway. The local benchmark template is
`~/git/gateway-api-bench/tests/listenerset-load.sh`: each set contributes an
HTTPS listener on port 443 with a wildcard hostname and its own Secret.
A route names its ListenerSet as its parent, not the parent Gateway.

The task originally names `gateway.networking.x-k8s.io`; the current local
benchmark and Gateway API v1.6.3 use `gateway.networking.k8s.io/v1`. Discover
served resources before choosing a watch. Support the requested experimental
group through an explicit version adapter when installed, and the current v1
shape. The experimental v1alpha1 resource is `XListenerSet` / `xlistenersets`;
the stable resource is `ListenerSet` / `listenersets`.
Test each adapter against its installed CRD schema. Never rewrite route
parent groups implicitly or watch two served versions as two objects. If both
resource groups exist, preserve group in object and parent identities and apply
an explicit controller configuration for which group is enabled. Missing optional
CRDs must leave ordinary Gateway operation healthy; authorization failures must
be surfaced rather than treated as absence.

Dynamic port assignment is unsupported. Experimental listeners with an omitted
or zero port never reserve or open a socket. When no valid listener remains, the
owner reports Accepted=False with reason UnsupportedPort. The v1alpha1 CRD
requires a positive port in each status listener entry, so unbound dynamic
listeners are omitted from that optional list; valid siblings retain their
entries and continue operating.

## Model and admission

Retain one Gateway UID as the owner of its Service, node EndpointSlices, private
port leases and acceptors. ListenerSets do not allocate another Service or a new
private port per hostname. Logical listener identity is `(group, owner UID,
listener name)`; socket identity remains `(Gateway UID, public port, transport)`.
Names need only be unique within the owner resource.

Normalize Gateway and ListenerSet listeners into immutable records carrying the
owner kind/group/namespace/UID/generation, parent Gateway UID, hostname, TLS
reference and allowedRoutes. Do not flatten away the owner namespace: same-
namespace Secret and Route defaults are relative to the ListenerSet. A Secret
ReferenceGrant must name ListenerSet as the source kind and its actual API group;
a grant to Gateway does not authorize the child. The grant helper
`gateway-reference-permitted-p` accepts the full source identity, including an
optional source group.

Attach a set only if its parent reference resolves to a controlled Gateway and
Gateway.allowedListeners admits the set's namespace. Missing allowedListeners
means deny, unlike allowedRoutes' default Same. Implement None, Same, All and
Selector with Namespace-label invalidation. Removal, parent UID replacement,
policy revocation and namespace relabeling must withdraw the child configuration.
Apply allowedRoutes and hostname intersection separately to each logical listener.
Direct Gateway route parents must not silently attach to child listeners.

Use the v1.6.3 merge precedence: Gateway listeners first, then oldest ListenerSet,
then namespace/name. Detect conflicts deterministically and publish the specified
listener conditions. Keep losing listeners out of the active routing/certificate
snapshot. Do not reveal sibling Secret contents in diagnostic messages. Check
legacy experimental conditions and precedence against that adapter's schema.

## Shared-port HTTPS dispatch

The planner once kept the first TLS reference on a port, with a
`gateway-ssl-acceptor` storing a single certificate and key; that model is gone.
The controller builds one immutable per-socket snapshot containing an SNI
certificate index and HTTP hostname routing index (`gateway-build-tls-snapshot`
in [`gateway-controller.lisp`](../src/controllers/gateway-controller.lisp)).
Exact hostname wins over wildcard; equal matches use the API's
conflict precedence. An unmatched SNI must not select another
tenant's arbitrary certificate, and the no-SNI behavior is defined and tested
explicitly.

Each handshake selects parsed certificate/key material from that snapshot
through pure-tls's server `certificate-provider` capability
([`gateway-proxy.lisp`](../src/controllers/gateway-proxy.lisp)). Parse and
validate once per Secret content version, with authorization
checked outside the material cache. Publish new indices atomically; each handshake
and request captures a consistent snapshot. Existing connections may finish on
their captured state, but new connections after acknowledgement must use the new
certificate or reject the revoked listener. Rotate one Secret without restarting
unrelated hostnames or accepting plaintext on port 443. Keep ordinary HTTP Host
routing constrained to the admitted logical listener, including SNI/Host mismatch
cases. Test all these behaviors using real TLS clients in the disposable VM.

## Watches, indices and update cost

Extend the foreign resource registry, discovery/watch setup, desired view and
chart RBAC for ListenerSets and their status. Preserve source group/version when
writing status. Extend native node projection only if the same normalized planner
is used there; do not silently claim native API support from projection alone.

Maintain reverse indices for Gateway UID to sets, set UID to routes, Secret
identity to logical listeners, and namespace selectors to affected Gateways.
A route edit reparses that route and its indexed listener intersections. A Secret
rotation updates dependent certificate entries; a set edit updates its own routes
and the affected socket's persistent hostname buckets. An unrelated namespace or
Secret must not rebuild all 40,000 routes. Keep a full reconciliation as recovery
and compare it against incremental results in randomized tests.

Bound caches by live content references and retire unused versions after readers
release snapshots. Parsed per-controller material already uses live-reference
accounting. The separate process-wide 4,096-entry digest/verdict cache in
`gateway-tls-material-valid-p` still clears wholesale at capacity; replace that
policy before measuring sustained ListenerSet churn. Do
not retain private material merely to cache a negative verdict. Record bytes
consed with SBCL deltas and allocation profiles, alongside CPU and propagation
latency, for initial load and single-object changes.

## Status and validation sequence

Publish ListenerSet Accepted/Programmed and per-listener conditions, supported
kinds, attached route counts, observedGeneration and stable transition times.
Gateway attachedListenerSets counts accepted attached sets under the API rules.
Route parent status retains the ListenerSet parent identity. Preserve status
owned by other controllers and remove stale entries owned by this controller.
Programmed must correspond to the installed listener snapshot, including failure
and revocation paths; a successful watch is not evidence of programming.

Implement in the dependent stages recorded as children of podster-dk9:

1. API discovery/adapters, watches, RBAC and desired-view identity.
2. Admission, ownership, merge/conflict model and reverse indices.
3. Shared-port SNI TLS dispatch and safe Secret rotation.
4. Route attachment and incremental reconciliation.
5. ListenerSet/Gateway/Route status and generation acknowledgement.
6. Real VM acceptance and benchmark-shape scalability validation.

Each stage starts with failing tests. The final VM run must include two isolated
Gateways sharing port 443 and overlapping hostnames, distinct certificates across
sets, namespace/grant revocation, delete/recreate UIDs, conflicting listener
precedence and agent restart. For full-scale validation,
exercise 2,500 sets/Secrets and 40,000 routes
per Gateway, verify all expected routes and certificates, and measure p50/p95/p99
change-to-observable latency plus allocation and memory high-water marks. Double
the workload and compare initial-load/update cost to detect quadratic behavior.
No throughput or propagation target is claimed until that evidence exists.

Benchmark installation/wiring remains podster-qx7, outside this goal. These
acceptance fixtures can reproduce its resource shape without changing that repo.

### Remaining scale work

The 2026-11-19 audit found the original `podster-dk9` unavailable in this
checkout's issue database. Its local counterpart, `podster-18x.3`, decomposes
stage 6 into concrete acceptance work:

- `podster-18x.3.1`: a parameterized disposable-VM fixture generating two
  isolated Gateways, each with 2,500 sets/Secrets and 40,000 routes. Keep a
  deterministic inventory and verify every route and certificate. Capture
  generation acknowledgement, propagation percentiles, allocation, RSS, API
  writes and full-reconciliation counts for initial load and single-object edits.
- `podster-18x.3.2`: replace wholesale digest/verdict-cache eviction. Start with
  a regression using more than 4,096 distinct materials and repeated rotation;
  measure parse counts, allocation and memory. Preserve grant checks outside
  the cache and avoid retaining private material for negative verdicts.
- `podster-18x.3.3`: after those prerequisites, run the target workload and double
  it to 5,000 sets/Secrets and 80,000 routes per Gateway. Exercise route, set,
  Secret and namespace/grant changes, UID replacement and restart. Compare CPU,
  allocation, memory and p50/p95/p99 propagation to detect quadratic growth;
  prove route/Secret edits do not reparse unrelated routes. Publish raw output
  with exact source, binary, CRD, cluster and hardware identifiers.

This decomposition is permitted by the supplied goal. Small functional fixtures
and HTTP core conformance do not establish benchmark-scale readiness.

## Enabling ListenerSets

This support runs in `gr8s net-agent` against an existing Kubernetes cluster.
Install the desired ListenerSet CRD, enable the chart's `gateway.enabled`, and
set `gateway.tls.enabled=true` for HTTPS certificate access. API discovery
prefers `gateway.networking.k8s.io/v1`, then its v1beta1 version, then
`gateway.networking.x-k8s.io/v1alpha1`. To select the experimental group when
both are installed, set
`gateway.listenerSetAPIGroup=gateway.networking.x-k8s.io`, or pass
`--listenerset-api-group gateway.networking.x-k8s.io` to `gr8s net-agent`.

The parent Gateway uses GatewayClass `gr8s` and must explicitly allow child
namespaces through `spec.allowedListeners.namespaces`. For example,
`from: Same` permits ListenerSets in the Gateway's namespace. Each set names
that Gateway in `spec.parentRef`. Its HTTPRoutes name the set in `parentRefs`,
using kind `ListenerSet` and group `gateway.networking.k8s.io` for the stable
API, or kind `XListenerSet` and group `gateway.networking.x-k8s.io` for the
experimental API. Route and Secret namespace defaults are relative to the set.
Cross-namespace Secrets require a ReferenceGrant for that exact source kind
and group.

Check the set's Accepted and Programmed conditions and the Gateway's
`attachedListenerSets` count. A newly watched object is not Programmed until
its current listener configuration has been installed. On HTTP, the most
specific admitted listener hostname selects the routing table; requests do
not fall through to another listener's routes when that table has no match.

## Current small-scale evidence

The native candidate with SHA-256
`717c64679e1cd83faf5b77979cf72833888799bdcef0bcb255dc847c70637342`
passed the disposable-VM fixture in `scripts/test-foreign-listenersets.py`:
31 checks against the stable API and 34 against the experimental API. These
runs include installed-generation readiness, the indexed parent lookup,
HTTP listener isolation across route updates, and preserving parent Gateway
routes when the last HTTP child is removed.
The fixture uses two Gateways, at most six routes, and five ListenerSets;
it does not establish the target workload's performance or scalability.
The corrected implementation passed `make check`: 33,725 Lisp checks passed,
nine opt-in checks were skipped, and no checks failed. The remaining Makefile
gates, including packet-program fixtures, installation lifecycle, conformance
runner, shell syntax, and static runtime verification, also passed.

A separate SBCL lookup microbenchmark used 16 Gateways with two sets each.
After warmup and a full GC, 1,000 reads allocated about 6 KB per indexed
lookup versus 99 KB for copying and filtering the whole collection. Both
paths returned the same two children. Allocation profiling of 100,000 indexed
reads attributed 97% of inclusive allocation samples to `copy-core-object`.
The remaining copies preserve the desired-state snapshot boundary; this
measurement does not justify exposing mutable snapshot objects to callers.
These are lookup measurements, not route propagation or TLS throughput results.
