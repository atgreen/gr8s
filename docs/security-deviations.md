# Deliberate security deviations from upstream Kubernetes

gr8s is a single-node-first control plane. A few of its security behaviours
deliberately differ from upstream Kubernetes. They are recorded here so they are
explicit, auditable decisions rather than silent gaps. Each entry notes the
behaviour, why it is acceptable for gr8s, and when it should be revisited.

These were identified in the k1/k2 security spot-checks, whose findings are
summarized in the
[2026-11-13 compatibility review](history/compatibility-review-2026-11-13.md).

## Certificate leaves live up to ~1 year with no revocation (F11)

CSR-API leaves honor the requested lifetime up to `*csr-certificate-duration*`
(365 days, `src/resources/csr-signer.lisp`). Internal node/member enrollment
leaves are signed with a fixed 365-day validity in `certificate-der`
(`src/security/pki.lisp`), and the cluster CA with ten years. There is no
CRL/OCSP revocation.

- **Why acceptable:** this matches the upstream Kubernetes model (certificate
  rotation plus Node deletion rather than revocation). Upstream's
  `--cluster-signing-duration` also defaults to one year.
- **Residual risk:** a compromised key is usable until expiry. For a
  revocation-free system, one year is on the long side.
- **Revisit if:** a shorter default is wanted. Lowering the overridable
  `*csr-certificate-duration*` shortens only CSR-API issuance; internal
  enrollment leaves need the fixed validity in `certificate-der` changed
  (internal certificates rotate automatically before expiry).

## Voter enrollment ships CA, node-CA, and SA signing keys as plaintext PEM (F14)

A successful HA voter enrollment response carries the cluster CA private key, the
node-CA key, and the ServiceAccount signing key as plaintext PEM
(`src/security/raft-tls.lisp`).

- **Why by design:** a voter must be able to admit replacement members, which
  requires these signing keys. The response travels over mutual TLS and is gated
  by a one-time token bound to the node name and the voter role.
- **Residual risk:** a single leaked voter token has a large blast radius.
- **Revisit if:** voter admission can be redesigned so replacements are signed by
  an existing voter on request rather than by shipping the keys.

## No owner-reference permission enforcement (C1)

gr8s has no equivalent of upstream `OwnerReferencesPermissionEnforcement`.
`validate-owner-references` checks only shape; GC-time deletion is gated by
admission webhooks, not RBAC.

- **Why acceptable for now:** owner resolution is UID- and same-namespace-bound,
  so this is not a general cross-tenant deletion. gr8s is single-tenant-first.
- **Residual risk:** a subject with `update` on a child but no rights on the
  owner can set `blockOwnerDeletion: true` to hold another principal's owner from
  foreground deletion, and in narrow cases attach a victim object under an owner
  so GC deletes it. (This is the GC analogue of the RBAC escalate/bind controls,
  which gr8s now enforces — see F2.)
- **Revisit if:** gr8s adds multi-tenancy; then enforce owner-reference and
  `blockOwnerDeletion` permissions on writes, as upstream does.

## Controllers re-scan on a fixed interval with no per-item backoff (C3)

The leader re-scans all resources every `interval` (default 1.0s) rather than
using a rate-limited per-item workqueue.

- **Why acceptable:** the scan is bounded (no retry storm), failed-scheduling
  events are rate-limited to 30s, and Job retries use real exponential backoff.
- **Residual cost:** a persistently failing hot object retries roughly every
  second indefinitely. Low impact.
- **Revisit if:** controller load or write-failure amplification becomes a
  concern; add a per-object exponential backoff / workqueue.
