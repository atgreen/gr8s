# Custom resources

The `apiextensions.k8s.io/v1` CustomResourceDefinition API installs actual
schema-backed JSON resource routes. A definition becomes Established only after
its group, names, scope, versions and structural schemas pass admission. Its
served versions appear in discovery; their custom object and list schemas and
CRUD/status paths appear in OpenAPI v2 and v3. Definitions remain scoped to their
own durable store rather than entering a process-global user registry. Discovery
uses Kubernetes version priority, preserving native storage and workload groups.

Custom objects support create, read, list, update, JSON merge/JSON patches,
delete and collection deletion. Namespaced collections also support cluster-wide
lists. Resource versions enforce optimistic updates and delete preconditions.
The shared durable journal provides resumable watches, selector transitions,
consistent pagination and restart recovery. Watches, signed continuations and
exact historical reads remain bound to the actual CRD UID, so recreating a
definition cannot expose data from its predecessor. Group/plural storage identifiers and
explicit persisted custom entries keep equal kinds and plurals in different
groups separate from one another and from builtin resources.

Supported structural schemas apply recursive defaults and unknown-field pruning,
including marked preserved subtrees. Validation covers types, required fields,
enums, numeric/string/array/object bounds, patterns, nullable fields, logical
constraints and map/set list identities. Unknown schema keywords, CEL and
unsupported validation formats fail admission instead of being ignored.

Served versions share object UIDs and one storage identity. Conversion strategy
None changes the API version without transforming fields; each version's schema
controls its defaults, pruning and validation. Removing a stored version requires
actual migration first. A declared status subresource isolates status writes from
desired fields and preserves generation. Ordinary writes preserve status. CRD
status writes preserve actual establishment/cleanup conditions and permit retiring
a stored version only after every persisted instance has really left it.

Deleting a definition deletes its actual custom instances. User finalizers block
instance deletion and keep the definition's cleanup finalizer and routes alive.
Owner garbage collection resolves exact custom owner UIDs across declared
versions and respects unknown external kinds. The controller resumes cleanup
after restart; failed durable writes do not
publish route or resource deletion. Recreating a definition is possible only
after its previous instances have been removed.

This workstream remains under development. CEL, conversion webhooks, scale
subresources, additional printer columns, custom field selectors, server-side
apply and protobuf requests for CRDs/custom objects are not implemented and are
not advertised as functioning features. Unsupported executable schema/conversion
features are rejected. Further structural edge cases and integration are still being
tested before integration review. The native kubectl smoke passes strict creation,
real streamed watches, version identity, restart persistence and finalizer
cleanup without disabling validation. Run it against a dumped executable with:

```sh
python3 scripts/test-crd-api.py --executable build/gr8s.bin
```
