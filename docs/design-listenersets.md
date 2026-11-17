# ListenerSet support for foreign-cluster Gateways

Status: implementation design, not implemented. This records the explicitly
permitted decomposition of podster-dk9. HTTP core conformance does not cover it.

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
shape. Test each adapter against its installed CRD schema. Never rewrite route
parent groups implicitly or watch two served versions as two objects. If both
resource groups exist, preserve group in object and parent identities and apply
an explicit controller configuration for which group is enabled. Missing optional
CRDs must leave ordinary Gateway operation healthy; authorization failures must
be surfaced rather than treated as absence.

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
a grant to Gateway does not authorize the child. Extend the existing grant helper
(which currently fixes the source group) to accept the full source identity.

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

The current planner keeps the first TLS reference on a port, and
`gateway-ssl-acceptor` stores a single certificate and key. Replace that model
with one immutable per-socket snapshot containing an SNI certificate index and
HTTP hostname routing index. Exact hostname wins over wildcard; use the API's
conflict precedence for equal matches. An unmatched SNI must not select another
tenant's arbitrary certificate. Define and test the no-SNI behavior explicitly.

Use pure-tls's server `sni-callback` capability to select parsed certificate/key
material. Parse and validate once per Secret content version, with authorization
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
release snapshots. The current 4,096-entry material cache clears wholesale at
capacity; replace that policy before measuring sustained ListenerSet churn. Do
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
precedence and agent restart. Then exercise 2,500 sets/Secrets and 40,000 routes
per Gateway, verify all expected routes and certificates, and measure p50/p95/p99
change-to-observable latency plus allocation and memory high-water marks. Double
the workload and compare initial-load/update cost to detect quadratic behavior.
No throughput or propagation target is claimed until that evidence exists.

Benchmark installation/wiring remains podster-qx7, outside this goal. These
acceptance fixtures can reproduce its resource shape without changing that repo.
