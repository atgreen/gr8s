<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Certificate management

gr8s creates and owns a self-signed cluster certificate authority (CA), the
Kubernetes API serving certificate, an administrative client certificate, the
private node-protocol serving certificate, and—when HA is enabled—Raft member
credentials. The generated kubeconfig embeds the CA and administrative client
credentials. Keep the state directory private and back it up together with the
application data: losing the CA private key loses the cluster identity and the
ability to decrypt encrypted PKI authority records.

## Inventory and expiry checks

Inspect a stopped or running node's local state without modifying it:

```sh
sudo gr8s certificate status --state-directory /var/lib/gr8s/server
sudo gr8s certificate check --state-directory /var/lib/gr8s/server \
  --warn-within 45d
sudo gr8s certificate status --state-directory /var/lib/gr8s/server \
  --output json
```

`status` and `check` are aliases. They return nonzero when a present credential
is expired, not yet valid, invalid, or expires inside the warning window. The
default warning window is 120 days. Missing optional credentials are shown but
do not make the command fail.

## Automatic renewal and explicit leaf rotation

Locally owned leaf certificates renew before expiry while retaining their
private keys. Enrolled agents renew through their authenticated node sessions;
their one-time join tokens are not reconnect credentials.

Explicit rotation creates a new certificate and private key. Stop every gr8s
process using the state directory first; the command takes exclusive offline
ownership and refuses to race a live server.

```sh
sudo systemctl stop gr8s-server.service
sudo gr8s certificate rotate \
  --state-directory /var/lib/gr8s/server \
  --service api-server,admin,node-server,apiserver-kubelet-client \
  --api-address 192.0.2.10
sudo systemctl start gr8s-server.service
```

Valid service names are `api-server`, `admin`, `node-server`,
`apiserver-kubelet-client`, and `raft-member`. Without `--service`, gr8s rotates
every locally present service credential and skips an absent Raft credential.
Repeat `--api-address` for every non-default DNS name or IP address clients use
to reach the Kubernetes API. Restart the processes that load the rotated files.

## Cluster CA rotation

CA rotation is a staged trust transition:

1. `prepare` generates the next CA and publishes a bundle containing both trust
   anchors. The current CA remains the signer.
2. `promote` makes the prepared CA the signer while retaining the old CA as a
   retiring trust anchor.
3. `finalize` removes the retiring CA only after safety checks prove that local
   leaves and registered nodes no longer use it.

For a running HA cluster, use the kubeconfig form. The authenticated request is
routed to the leader; encrypted authority state is committed through Raft and
extracted by every voter.

```sh
sudo gr8s certificate rotate-ca prepare  --kubeconfig /etc/gr8s/kubeconfig
sudo gr8s certificate rotate-ca promote  --kubeconfig /etc/gr8s/kubeconfig

# Restart one control-plane member at a time and verify quorum/API health after
# each restart. Let every agent reconnect and renew under the active CA.

sudo gr8s certificate rotate-ca finalize --kubeconfig /etc/gr8s/kubeconfig
```

Do not run `finalize` merely because the API is healthy. It intentionally fails
while a local credential is signed by the retiring CA or a registered node has
not reconnected with an active-CA credential. Correct the named stale members
and retry; do not delete retiring material by hand.

For a stopped single-node cluster, use the offline form for each stage:

```sh
sudo gr8s certificate rotate-ca prepare \
  --state-directory /var/lib/gr8s/server
sudo gr8s certificate rotate-ca promote \
  --state-directory /var/lib/gr8s/server
sudo gr8s certificate rotate-ca finalize \
  --state-directory /var/lib/gr8s/server
```

Restart between promotion and finalization so locally owned leaves are reissued
by the active CA. Preserve a verified backup of the complete state directory
before beginning. An interrupted stage is durable and should be resumed with
the same stage or the next documented stage; do not mix files from different
cluster backups.

## ServiceAccount signing-key rotation

The token signer uses the same prepare/promote/finalize model. `prepare` adds a
new verification key, `promote` signs new tokens with it while retaining the old
verification key, and `finalize` removes superseded key material.

```sh
sudo gr8s certificate service-account-key prepare  --kubeconfig /etc/gr8s/kubeconfig
sudo gr8s certificate service-account-key promote  --kubeconfig /etc/gr8s/kubeconfig
sudo gr8s certificate service-account-key finalize --kubeconfig /etc/gr8s/kubeconfig
```

Use `--state-directory` instead of `--kubeconfig` only while a standalone
cluster is stopped. Allow existing projected tokens to turn over before
finalizing if workloads or external clients may still present them.

## Scope and limitations

gr8s currently owns its cluster CA. External CA/KMS integration, certificate
revocation lists, and automatic custom signer controllers are not implemented.
Kubernetes CertificateSigningRequests and API client-certificate profiles are
documented separately in [CertificateSigningRequests](certificate-signing-requests.md)
and [Kubernetes API client certificates](api-client-certificates.md).
