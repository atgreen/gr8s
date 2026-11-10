# Kubernetes API client certificates

The public Kubernetes TLS API accepts client certificates signed by its cluster
CA. TLS requests optional client certificates and verifies the actual
CertificateVerify signature proving possession of the private key. HTTP
certificate authentication then verifies the chain, validity, key usage and
client-authentication purpose. A certificate's common
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
resource permissions by itself. As in the pinned [privileged group authorizer](https://github.com/kubernetes/kubernetes/blob/v1.36.0/pkg/kubeapiserver/authorizer/reload.go#L89),
a verified certificate whose signed organizations contain `system:masters`
receives standard privileged authorization without a RoleBinding. Ordinary
users and groups retain their namespace, resource and verb grants. CSR approval
and signing also require
signer-specific `approve` and `sign` permission; the same admission applies to
certificate users and ServiceAccount tokens. CSR username, UID, groups and
credential extra are derived from authenticated credentials. Client-supplied
actor fields, impersonation headers and forwarded identity headers cannot
supply that identity.

TLS client certificates are optional so existing ServiceAccount bearer-token
clients continue working. The pinned Kubernetes [serving configuration](https://github.com/kubernetes/apiserver/blob/v0.36.0/pkg/server/secure_serving.go#L72)
requests certificates, and its [authenticator union](https://github.com/kubernetes/apiserver/blob/v0.36.0/pkg/authentication/request/union/union.go#L30)
continues after certificate authentication errors. Expired, untrusted or
wrong-purpose certificates cannot supply an identity, but a valid live bearer
token can still authenticate that HTTP request. When neither credential works,
the response is HTTP 401. Invalid TLS proof of possession still fails TLS.
A valid certificate wins before bearer authentication; an RBAC denial does not
retry authorization using another identity. Peer certificate identity is isolated per connection
and retained across keepalive requests. Every request rechecks certificate
validity and current RBAC bindings. This TLS implementation's resumption tickets
do not retain verified peer chains, so each new connection uses a full handshake
with a fresh ticket key. The local administrative HTTP listener keeps its
existing explicit administrative trust model.

[API certificate profile policies](certificate-signing-requests.md) continue to
separate API credentials from internal enrollment credentials. API-issued
certificates cannot authenticate an internal node or control server; enrollment
credentials, cluster CA and pins retain their existing behavior. On the public
Kubernetes interface, a legacy enrollment certificate follows the same signed
CN/O identity and RBAC rule as every other trusted client certificate, including
its existing bare common name. The API-profile restriction applies specifically
to the additional internal node/control protocol. This feature
does not implement certificate revocation lists, impersonation, external client
CA configuration or automatic custom-signer controllers.

## Historical enrollment certificate compatibility

Earlier internal enrollment copied requested subject attributes, including
organizations, into cluster-root-signed client certificates. New enrollment
issuance constructs only the validated bare node common name and discards all
other requested subject attributes. This fixes future issuance; existing
certificates, CA files and pins are unchanged. It does not retroactively remove
organizations from previously issued certificates.

Before enabling public client-certificate authentication by deploying this
version against an existing cluster CA, deployments must audit historical
root-signed client certificates and revoke or rotate affected credentials/trust.
Those certificates follow the standard public CN/O authorization rule, including
privileged `system:masters` organization membership. This implementation does
not enforce per-certificate CRL revocation, so publishing a CRL alone does not
remove trust; unsafe or unauditable historical credentials require an effective
credential/issuer trust rotation before enablement. Generic root-signed clients
are not filtered by the API-profile policy.
