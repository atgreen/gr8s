# Kubernetes API client certificates

The public Kubernetes TLS API accepts client certificates signed by its cluster
CA. It verifies the actual TLS CertificateVerify proof and certificate chain,
validity, key usage and client-authentication purpose. A certificate's common
name becomes the username; organization attributes become groups, together
with `system:authenticated`. An optional subject UID uses Kubernetes' published
OID `1.3.6.1.4.1.57683.2`, requires exactly one nonempty string, and is copied to
server-owned CSR actor data. The credential ID is the lowercase DER SHA256
fingerprint prefixed with `X509SHA256=` under
`authentication.kubernetes.io/credential-id`.

These rules follow the pinned [v1.36 X.509 authenticator](https://github.com/kubernetes/apiserver/blob/v0.36.0/pkg/authentication/request/x509/x509.go)
(source SHA256 `6340fb96c36cf6025aaa72b4c0947773af734f0c1bd706e4c5557f7c22c2ba51`)
and [UID mapping](https://github.com/kubernetes/apimachinery/blob/v0.36.0/pkg/apis/asn1/oid.go)
(SHA256 `9ad0e5c02e333bff62913fca55482c6b38c4592c90c68f53528c8dd8072c13f0`).

Live RoleBindings and ClusterRoleBindings grant access through User, Group and
standard ServiceAccount subjects. Certificate authentication does not grant
resource permissions by itself. CSR approval and signing additionally require
signer-specific `approve` and `sign` permission; the same admission applies to
certificate users and ServiceAccount tokens. CSR username, UID, groups and
credential extra are derived from authenticated credentials. Client-supplied
actor fields, impersonation headers and forwarded identity headers cannot
supply that identity.

TLS client certificates are optional so existing ServiceAccount bearer-token
clients continue working. Peer certificate identity is isolated per connection
and retained across keepalive requests. Every request rechecks certificate
validity and current RBAC bindings. This TLS implementation's resumption tickets
do not retain verified peer chains, so each new connection uses a full handshake
with a fresh ticket key. The local administrative HTTP listener keeps its
existing explicit administrative trust model.

[API certificate profile policies](certificate-signing-requests.md) continue to
separate API credentials from internal enrollment credentials. API-issued
certificates cannot authenticate an internal node or control server; enrollment
credentials, cluster CA and pins retain their existing behavior. This feature
does not implement certificate revocation lists, impersonation, external client
CA configuration or automatic custom-signer controllers.
