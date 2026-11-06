#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Vendor the OpenAPI schemas Kubernetes v1.37.2 publishes for the versions gr8s serves.

Writes schema/openapi-v1.json: every component schema of upstream's published
api/openapi-spec/v3 documents for those versions, and the schema names each
document lists. gr8s serves its OpenAPI v3 documents from these and derives its
v2 definitions from them, so this also checks that the derivation gives back
upstream's swagger.json for every vendored name.
"""

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
VERSION = "v1.37.2"
BASE = f"https://raw.githubusercontent.com/kubernetes/kubernetes/{VERSION}/api/openapi-spec/"
SWAGGER = ("swagger.json", "465276aedf437726de5a6ed23a41b86d78bb0d347edf251a755ae26a93cdd8a6")
# Document name -> sha256. These are the group versions gr8s serves.
DOCUMENTS = {
    "api__v1": "d09ab224a98fb9c0e7fd128b6f395f66b23d43b6635272109dcaaafc4a3dd9c9",
    "apis__admissionregistration.k8s.io__v1": "4a54b50b7562d3b220cd2e7fd9547bac9585982968f692bc96e99fdcca42dbc3",
    "apis__apiextensions.k8s.io__v1": "41d85b9f6f2757d35b6645086d5bcadf4904a8f0133b00d77e2576b3feb47d56",
    "apis__apiregistration.k8s.io__v1": "a8e1310237c1b7a484ab98cd594f1d98e46e6d4c6ae7d7c9fd2c86f4cd91a19c",
    "apis__apps__v1": "e1326db2904fd6356d2f16e6179f8ad8e4800c0112cb74ab3b21da7286df4dbe",
    "apis__authentication.k8s.io__v1": "443427d822f77db77202c96df06d453845abc5cc67390180129a67e6c74d421e",
    "apis__authorization.k8s.io__v1": "520953628cb42765e372fe5d616421e3743f42bd236bf0b12cfd37781aa37b0f",
    "apis__autoscaling__v1": "424e756aa03460e09e39ead79c767dcb0450d0647dd1a4302598d3961c159898",
    "apis__autoscaling__v2": "9c0e4bd6cb82e135feddc7c36459d6bebcdd166409e1df64782582420d2db062",
    "apis__batch__v1": "39e41a47689d58ed0ba29c7e576fd88a47917b5c00dd2efaab71c9cf90a6b5f7",
    "apis__certificates.k8s.io__v1": "ec9984a600f4e8116faa04e64980bfda39ae4ec30333324900c59e0a8b43b4f8",
    "apis__certificates.k8s.io__v1beta1": "862c93b791e05332c611c53d6e5ad9aca897e948f268053d0a92d608160567dd",
    "apis__coordination.k8s.io__v1": "7799819c8dcc9d851cf8ba6150a8e5d4769299391bf7c04b61fe434533b0a2b3",
    "apis__discovery.k8s.io__v1": "ec495888f7179b410d365dca5491d3d928028330ace1337c507c29e800303155",
    "apis__events.k8s.io__v1": "d987e47b95996c84d6bd05a30e7064e377793641a442d28f884324d6e2e71693",
    "apis__flowcontrol.apiserver.k8s.io__v1": "39016db91b91e617f59cd40e8e8c96b657b583e142c92843f0b603fc99661e27",
    "apis__networking.k8s.io__v1": "253b343c3cae24b9c42df30842b55f54d0aed3b30d91c35aa25bf0511f6c7848",
    "apis__node.k8s.io__v1": "d36da40a20d350140016227fe371b3b87dcb8493cd0e56ee3b6e5c14680f0d24",
    "apis__policy__v1": "21d1bc36490cee723d1785f265de69d98228f1c51522b10f5c6e4c7d213ebb0b",
    "apis__rbac.authorization.k8s.io__v1": "58efa60097c0c4bfbde12e27bc14c00bbfd86e927feea109e5e368baee5c6fc0",
    "apis__resource.k8s.io__v1": "743996fbedf996cea03b243e83e23b2d254b80d4a0cdcbf8ed8e9874bc449ab6",
    "apis__scheduling.k8s.io__v1": "c95d06aaea2dbf186b67bd7d1854ee7d06b0be37a8441eb264c6d5db05c33259",
    "apis__storage.k8s.io__v1": "96c4f09112d51adc3d64c73f782927e88956ba6db4fa74b12fff2cf23ea7e5fe",
    "apis__storagemigration.k8s.io__v1": "65b0af315e396248fc1b88ac7b9c852f8e4c60350acb95ca1e2eaec4b04d19c7",
}
# Their GVK lists name every group version, so each document carries its own.
SHARED = ("io.k8s.apimachinery.pkg.apis.meta.v1.DeleteOptions", "io.k8s.apimachinery.pkg.apis.meta.v1.WatchEvent")


def fetch(cache, relative, digest):
    """Read a cached input or fetch it, rejecting content that differs from the lock."""
    path = cache / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_bytes(urllib.request.urlopen(BASE + relative, timeout=60).read())
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"Source checksum mismatch: {relative}")
    return json.loads(data)


def group_version(document):
    """api__v1 -> api/v1; apis__apps__v1 -> apis/apps/v1, as /openapi/v3 keys them."""
    return document.replace("__", "/")


def v2_schema(schema):
    """Mirror src/http.lisp's openapi-v2-schema: how kube-openapi writes a v3 schema in v2."""
    if not isinstance(schema, dict):
        return schema
    result = dict(schema)
    result.pop("default", None)
    result.pop("nullable", None)
    all_of = result.get("allOf")
    if isinstance(all_of, list) and len(all_of) == 1 and "$ref" in all_of[0]:
        del result["allOf"]
        result["$ref"] = all_of[0]["$ref"]
    if "$ref" in result:
        result["$ref"] = result["$ref"].replace("#/components/schemas/", "#/definitions/")
    one_of = result.get("oneOf")
    if isinstance(one_of, list) and [entry.get("type") for entry in one_of] in (["integer", "string"], ["string", "number"]):
        del result["oneOf"]
        result["type"] = "string"
    if isinstance(result.get("properties"), dict):
        result["properties"] = {key: v2_schema(value) for key, value in result["properties"].items()}
    for key in ("items", "additionalProperties"):
        if key in result:
            result[key] = v2_schema(result[key])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "build/kubernetes-openapi")
    arguments = parser.parse_args()
    swagger = fetch(arguments.cache, SWAGGER[0], SWAGGER[1])["definitions"]
    schemas, documents = {}, {}
    for document, digest in DOCUMENTS.items():
        components = fetch(arguments.cache, f"v3/{document}_openapi.json", digest)["components"]["schemas"]
        documents[group_version(document)] = sorted(components)
        for name, schema in components.items():
            if name in SHARED:
                continue
            if name in schemas and schemas[name] != schema:
                raise ValueError(f"{name} differs between documents")
            schemas[name] = schema
    for name in SHARED:
        # Kept without its GVK list; gr8s writes the list each document needs.
        schema = dict(fetch(arguments.cache, "v3/api__v1_openapi.json", DOCUMENTS["api__v1"])["components"]["schemas"][name])
        schema.pop("x-kubernetes-group-version-kind")
        schemas[name] = schema
    for name, schema in schemas.items():
        expected = dict(swagger[name])
        if name in SHARED:
            expected.pop("x-kubernetes-group-version-kind")
        if v2_schema(schema) != expected:
            raise ValueError(f"The v2 derivation of {name} differs from swagger.json")
    result = {"kubernetesVersion": VERSION, "sourceLicense": "Apache-2.0; Copyright The Kubernetes Authors",
              "sources": {name: {"url": f"{BASE}v3/{name}_openapi.json", "sha256": digest} for name, digest in DOCUMENTS.items()},
              "documents": documents, "schemas": schemas}
    output = ROOT / "schema/openapi-v1.json"
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"Wrote {len(schemas)} schemas for {len(documents)} documents ({output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
