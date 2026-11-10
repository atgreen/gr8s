# ConfigMap and Secret APIs

gr8s serves namespace-scoped `v1/ConfigMap` and `v1/Secret` resources independently
of the node runtime. The HTTP API supports create, get, list, replace, patch, and
delete, with resource discovery and OpenAPI schemas for kubectl. Responses use
JSON. Create, replace, and DeleteOptions requests accept JSON or Kubernetes
protobuf, including the `k8s\0` envelope used by kubectl's typed clients.

```sh
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

The resource store uses a single atomic state file at `objects/state.json` under
the server state directory. It records monotonic resource versions and survives
server restarts. The file is created with mode `0600`. Secret values are stored as
base64, without encryption at rest.

## Current limits

Namespace scoping isolates objects by the namespace in the request URL. gr8s does
not yet provide Namespace lifecycle APIs or require a Namespace object to exist.
These resources are not yet consumed through Pod environment references or
volumes. Watch, server-side apply and field ownership, collection deletion,
owner-reference garbage collection, and finalizers are unsupported. Discovery
omits their verbs, and unsupported operations return errors. Creating a
service-account-token Secret does not create a token controller or generate a
token.

## Verification

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
