# ConfigMap and Secret APIs

gr8s serves namespace-scoped `v1/ConfigMap` and `v1/Secret` resources independently
of the node runtime. The HTTP API supports create, get, list, watch, replace,
patch, server-side apply, delete, and collection deletion, with discovery and
OpenAPI schemas for kubectl. JSON requests and responses are supported.
Create, replace, and DeleteOptions requests accept JSON or Kubernetes
protobuf, including the `k8s\0` envelope used by kubectl's typed clients.

```sh
kubectl create namespace demo
kubectl -n demo create configmap settings --from-literal=mode=development
kubectl -n demo create secret generic credentials --from-literal=password=example
kubectl -n demo get configmaps,secrets
kubectl -n demo patch configmap settings --type=merge -p '{"data":{"mode":"production"}}'
kubectl -n demo delete configmap settings
kubectl -n demo delete secret credentials
```

## Endpoints and supported behavior

| Endpoint | Methods |
| --- | --- |
| `/api/v1/namespaces/{namespace}/configmaps` | GET, POST |
| `/api/v1/namespaces/{namespace}/configmaps/{name}` | GET, PUT, PATCH, DELETE |
| `/api/v1/namespaces/{namespace}/secrets` | GET, POST |
| `/api/v1/namespaces/{namespace}/secrets/{name}` | GET, PUT, PATCH, DELETE |
| `/api/v1/configmaps`, `/api/v1/secrets` | GET across namespaces |

Lists support label equality, inequality, existence, and `in`/`notin` selectors,
plus `metadata.name` and `metadata.namespace` field selectors. `limit` and
`continue` provide pagination; if the stored revision changes between pages, the
API returns HTTP 410 so the client can restart the list.

PUT requires the current `metadata.resourceVersion`. Updates with stale versions
and DELETE requests with mismatched UID/resource-version preconditions return
HTTP 409. PATCH supports JSON merge patch, strategic merge patch of the resource's
map fields, and JSON Patch operations. Client-side `kubectl apply` is supported.
Dry-run writes validate the request and return a result without changing stored
objects or consuming a resource version, including DeleteOptions `dryRun`.

ConfigMap `data` and `binaryData` keys must not overlap. Secret `data` holds
base64 values; `stringData` overwrites matching data keys on write and is never
returned or persisted. Data sizes are limited to 1 MiB. `immutable: true` prevents
subsequent data changes or reversal of immutability while allowing metadata
updates. Standard Secret types such as TLS, SSH, basic-auth, and Docker credentials
receive their required-field checks; custom Secret types are accepted. Secret
`type` cannot change after creation.

The resource store checkpoints data to `objects/state.json` and records following
commits in `objects/journal.jsonl`, beneath the selected application generation
of the state directory. It records monotonic resource versions and survives
server restarts. These files use mode `0600`. Without encryption enabled, Secret
values are stored as base64. With it, each Secret is sealed with AES-GCM under its
key record's data key, which comes from one of two places:

- **A KMS v2 plugin** (the upstream `k8s.io/kms` protocol over a Unix socket). The
  data key is random; the plugin wraps it with a key it holds, and the store keeps
  only the wrapped key. A server unwraps it once at start with its own plugin and
  keeps it in memory, so the plugin is called rarely. Any KMS v2 plugin works: a cloud
  KMS's, Vault or OpenBao Transit's, an HSM's, or `gr8s-kms`, below. HA members each
  reach the same KMS, so no key passes between them.
- **Cluster identity**: a key derived from the cluster CA private key and the record's
  salt. Backups must then retain cluster identity as well as application data.

Give `serve` a plugin with `--kms-plugin NAME=ENDPOINT` (repeatable). The API's
`/healthz`, `/livez` and `/readyz` then report a `kms-providers` check, failing while
a plugin is unhealthy, as upstream's does; gr8s checks each plugin every minute. When
a plugin reports a new `key_id`, as after its key rotates, a standalone server or the
HA leader wraps a fresh data key with it and writes Secrets with that from then on;
older Secrets keep their key until `reencrypt`.

### gr8s-kms, the bundled plugin

The packages ship `gr8s-kms` and `gr8s-kms.service`. It keeps a ring of keys in
`/var/lib/gr8s/kms/keyring.cred`, sealed with `systemd-creds`: to the TPM and the host
key when the machine has a TPM, to the host key (`/var/lib/systemd/credential.secret`)
otherwise. A copy of `/var/lib/gr8s` or a backup is then useless without this
machine, and with a TPM so is a stolen disk. It doesn't protect a running machine
from its root, who can read what gr8s holds in memory.

```sh
sudo gr8s-kms status                    # the active key and how the ring is sealed
sudo gr8s-kms rotate                    # a new key wraps from now on
sudo gr8s-kms export-recovery --file /mnt/usb/gr8s-kms.recovery
sudo gr8s-kms import-recovery --file /mnt/usb/gr8s-kms.recovery
```

**Keep a recovery export.** A ring sealed to a TPM is gone with the machine. The
export is the ring under a passphrase (scrypt, AES-GCM); on a replacement machine,
`import-recovery` seals it there. The seal isn't bound to PCRs by default, so a
firmware or Secure Boot change doesn't lose it; `--tpm2-pcrs` binds it if you want
that. Without `systemd-creds`, `--unsealed` stores the ring root-only, and says so.

### Encryption by default

The packaged `/etc/gr8s/server.env` names `gr8s-kms` with `--kms-plugin
gr8s=unix:///run/gr8s/kms.sock` and `--encrypt-secrets-with gr8s`: a new standalone
cluster encrypts its Secrets with it from its first one, and won't start without it
rather than write one in plaintext. An existing cluster, or one starting or joining
HA, is left as it is; move one with `secrets-encrypt` (below).

### Secrets in containers' environments

A Secret given to a container as an env var is part of its OCI spec, which containerd
keeps in two places on the node. Its state directory (`containerd/run`), each
container's bundle, is now a tmpfs, as stock containerd keeps it under `/run`; on a
node upgraded with Pods running it stays on disk, with a log line saying so, until its
Pods are gone or it restarts. Its metadata database (`containerd/root/.../meta.db`)
also records the spec, as upstream containerd's does, and must persist across
restarts, so an env var's value is on the node's disk there for as long as the
container exists. Mount Secrets as files instead: a Secret volume is a tmpfs, and its
value is never written to the node's disk.

### Encryption-at-rest operations

`gr8s secrets-encrypt` operates directly on a standalone state directory. Stop gr8s
before changing it and take a verified backup containing the application data, and
cluster identity or a KMS recovery export. Give it the plugins its keys need with
`--kms-plugin NAME=ENDPOINT`, and `--kms NAME` for `enable` or `prepare` to wrap the
new key with one. Do not run these commands independently against individual HA
voters; with a KMS, a key rotation follows the plugin online, from the leader.

Enable encryption and rewrite existing Secrets in one operation:

```sh
sudo systemctl stop gr8s-server.service
sudo gr8s secrets-encrypt enable --state-directory /var/lib/gr8s/server
sudo systemctl start gr8s-server.service
```

For a staged key change, prepare a key, promote it for new writes, rewrite every
existing Secret, and only then discard superseded keys:

```sh
sudo gr8s secrets-encrypt status    --state-directory /var/lib/gr8s/server
sudo gr8s secrets-encrypt prepare   --state-directory /var/lib/gr8s/server
sudo gr8s secrets-encrypt promote   --state-directory /var/lib/gr8s/server
sudo gr8s secrets-encrypt reencrypt --state-directory /var/lib/gr8s/server
sudo gr8s secrets-encrypt finalize  --state-directory /var/lib/gr8s/server
```

Each command prints JSON containing the phase and non-secret key identifiers.
`finalize` refuses to discard keys until re-encryption has completed. To return
to plaintext storage, `disable` first rewrites Secrets and then removes the
encryption configuration.

Move an existing cluster's Secrets to a KMS key the same way:

```sh
sudo systemctl stop gr8s-server.service
K="--state-directory /var/lib/gr8s/server --kms-plugin gr8s=unix:///run/gr8s/kms.sock"
sudo gr8s secrets-encrypt prepare $K --kms gr8s
sudo gr8s secrets-encrypt promote $K
sudo gr8s secrets-encrypt reencrypt $K
sudo gr8s secrets-encrypt finalize $K
sudo systemctl start gr8s-server.service
```

(`enable $K --kms gr8s` does it in one step for a cluster without encryption.) Then
add `--kms-plugin gr8s=unix:///run/gr8s/kms.sock` to `serve`'s arguments.

## Runtime integration

Objects are scoped by the namespace in the request URL. Pods can consume
ConfigMaps and Secrets through environment references and volume projections.
Namespace lifecycle, owner-reference garbage collection, field ownership and
finalizers are handled by the corresponding API and controllers.

## Verification

The [metadata rotation validation](evidence/secret-metadata-validation-2026-11-10.json)
records prepare, promote, re-encrypt, finalize and cold reopening with a 1 MiB
Secret and full retained history inside a 384 MiB Lisp heap. Metadata-only phases
preserve the following journal. Build this internal probe with
`sbcl --noinform --non-interactive --load scripts/build-secret-metadata-native-harness.lisp`;
`python3 scripts/test-secret-metadata-native.py --help` describes its quiescent
checkpoint/journal inputs and matching history clock. It copies only application
files into a private standalone store. This is memory and persistence evidence;
production serve, HA and VM acceptance have separate scope.

`make test-core-api` runs a non-root kubectl smoke with the fake runtime and no
node agent. It exercises create/get, labels, selectors, merge/JSON patch, replace,
client-side apply, namespace isolation, server restart, dry-run, and deletion.
The smoke has been verified with kubectl 1.37.1. Override
`GR8S_CORE_API_EXECUTABLE` with an absolute dumped executable path to run the same
smoke against a native build. `GR8S_CORE_API_PORT` overrides its default port,
18189; `GR8S_CORE_API_KEEP_WORKDIR=1` preserves diagnostics.

The unit and HTTP suites also cover version conflicts, delete
preconditions, immutable data, input validation, full-size binary Secrets,
pagination expiry, and malformed/truncated protobuf requests. The request field
numbers follow the Kubernetes v0.37.1
[core API protobuf definitions](https://github.com/kubernetes/api/blob/v0.37.1/core/v1/generated.proto),
[metadata definitions](https://github.com/kubernetes/apimachinery/blob/v0.37.1/pkg/apis/meta/v1/generated.proto),
and [runtime envelope](https://github.com/kubernetes/apimachinery/blob/v0.37.1/pkg/runtime/generated.proto).
