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
values are stored as base64. `gr8s secrets-encrypt` manages authenticated
encryption at rest and key rotation. Encrypted data depends on the cluster CA
private key, so backups must retain cluster identity as well as application data.

## Runtime integration

Objects are scoped by the namespace in the request URL. Pods can consume
ConfigMaps and Secrets through environment references and volume projections.
Namespace lifecycle, owner-reference garbage collection, field ownership and
finalizers are handled by the corresponding API and controllers.

## Verification

The [metadata rotation validation](secret-metadata-validation-2026-11-10.json)
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
