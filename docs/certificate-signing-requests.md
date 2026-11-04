# Certificate signing requests

`certificates.k8s.io/v1` serves cluster-scoped `CertificateSigningRequest`
objects with JSON/protobuf create and update, get/list, durable watches,
JSON/merge/strategic patches, delete and selector-based deletecollection.
`/approval` and `/status` support get, update and patch. Discovery and OpenAPI
v2 JSON/v3 describe actual routes; `csr` is the discovery shortcut.

Requests contain a base64-encoded PKCS#10 `CERTIFICATE REQUEST` PEM block.
Admission parses the signed request, validates its structure and SANs, and
checks the signature using its declared RSA, RSA-PSS, ECDSA or Ed25519 public
key. RSA-PSS parameters must match the actual hash/MGF/digest-length salt;
unknown or inconsistent key algorithms are rejected. Usages must be known,
unique and nonempty; `expirationSeconds`, if present, is at least 600.

Create clears client-provided status and actor claims. A live verified
ServiceAccount token supplies username, account UID and standard groups;
the existing local administrative HTTP listener otherwise records the
anonymous actor. Ordinary updates preserve spec and status. Approval updates
change conditions while preserving certificate/spec; status updates preserve
spec and existing approval/denial values. Approved/Denied/Failed conditions
cannot be removed, Approved and Denied are exclusive, and an issued certificate
cannot be replaced or cleared. Metadata changes use optimistic resource
versions, including upstream unconditional-update behavior when RV is omitted.

The authenticated TLS listener additionally requires signer-specific `approve`
or `sign` RBAC where appropriate, including the `example.com/*` signer name
form. The existing administrative HTTP listener retains its existing trust
boundary. Forged impersonation headers never supply CSR actor identity.

Structural unknown fields are pruned; Strict rejects unknown/duplicate JSON
fields and Warn emits actual HTTP Warning headers. Finalizers keep deletion
intent durable until removed. All mutations and watch history use the shared
atomic store, including failed-write rollback and restart recovery.

The signer controller never autoapproves. Once explicitly approved and not
Denied/Failed, the three built-ins issue actual CA-signed certificates:

- `kubernetes.io/kube-apiserver-client` requires client auth and permits optional
  digital signature and key encipherment. The default subject restriction
  rejects the `system:masters` organization, including BMP-encoded names.
- `kubernetes.io/kube-apiserver-client-kubelet` requires the standard
  `system:node:` common name, exactly `system:nodes` organization, client usages
  and no DNS/IP/email/URI SANs.
- `kubernetes.io/kubelet-serving` requires the node subject, server usages,
  at least one DNS/IP SAN and no email/URI SANs.

Policy failures receive a real Failed condition. Custom signers remain Pending
unless an authorized external signer supplies an actual certificate through
status. This is normal Kubernetes behavior; optional custom-signer controller
automation is tracked in `podster-uqb.22.1`. Certificate status accepts real PEM certificate
chains without pretending that an uploaded external certificate was issued by
this controller. Issuance honors requested lifetime up to the configured
one-year maximum and CA expiry, with upstream five-minute backdating rules.

API-issued certificates are distinguished from internal enrollment credentials
by an issuer-controlled noncritical `certificatePolicies` extension
(`2.5.29.32`). Its profile policy identifier is
`2.25.239647859381961005463536084722150751259`, derived from UUID v5
`b44a7fb4-94d0-583f-a90a-6be9694b3c1b` in the URL namespace for
`https://github.com/atgreen/gr8s/pki/api-csr-profile/v1`.
[UUID v5](https://www.rfc-editor.org/rfc/rfc9562.html#section-5.5) and
[ITU-T X.667 clauses 6.3/7](https://www.itu.int/rec/T-REC-X.667-201210-I/en)
define the name hashing and unsigned integer OID mapping. RFC 5280
[certificate policies](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4)
express issuance and purpose policy in an end-entity certificate.

Every built-in API issuer adds that policy itself; requested policy extensions
are discarded. Internal node and control-server validators inspect all policy
entries and reject this API profile, then require a direct enrollment-root
signature. Existing enrollment credentials, CA files and pins remain valid.
The current root has `pathLen:0`, so adding an intermediate beneath existing
roots would violate its path constraint. The profile keeps single-leaf
issuance and ordinary client/server TLS interoperability.

A direct custom extension with the long `2.25` UUID OID is not used: Go rejects
that outer extension identifier's large integer arc. The standard
certificatePolicies container permits the UUID policy identifier and has been
verified with actual Go X.509/TLS and OpenSSL, without relaxing verification.

The Kubernetes API TLS listener currently authenticates ServiceAccount tokens;
user client-certificate HTTP authentication is tracked in `podster-uqb.22.2`.
Real certificate issuance does not imply that this separate authentication
feature is implemented. Server-side apply remains outside this surface;
custom signer automation is an optional controller extension.

Run the focused native proof with strict validation enabled:

```sh
python3 scripts/test-csr-api.py --executable build/gr8s.bin --go /path/to/go
```

That proof uses the fake workload runtime because it creates no Pods. Its API,
PKI, independent Go TLS verification, mutations, watches and restart checks are
real. The unchanged upstream `Certificates API` family is run separately with
the real containerd runtime; focused evidence is not certification.
