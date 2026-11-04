#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Generate checksum-pinned apiextensions v1 protobuf descriptors and JSON tags."""
import argparse
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gr8s_schema", ROOT / "scripts/generate-podtemplate-schema.py")
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
EXTRA = {
    "crd.proto": ("apiextensions-apiserver/v0.36.0/pkg/apis/apiextensions/v1/generated.proto", "0e9f39d655cdd7587cc71558631b8fc2986248f26f26cf8eccb432f73198aca9"),
    "crd-types.go": ("apiextensions-apiserver/v0.36.0/pkg/apis/apiextensions/v1/types.go", "feee9541a03e6c0ed869d99c11480b2becf576556d35b8e66a79bb5732c7bf09"),
    "jsonschema-types.go": ("apiextensions-apiserver/v0.36.0/pkg/apis/apiextensions/v1/types_jsonschema.go", "330c14f80aaa33c5dd0de3f5eb0ecb88fe132069565e5b7b254bee0ca94a63b8"),
}
PACKAGE = "k8s.io.apiextensions_apiserver.pkg.apis.apiextensions.v1."


def main():
    """Lock actual wire field types, JSON spellings and non-pointer omission semantics."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "build/kubernetes-schema")
    args = parser.parse_args()
    shared.SOURCES.update(EXTRA)
    sources = shared.load_sources(args.cache)
    all_messages = shared.proto_messages(sources)
    pending = [PACKAGE + "CustomResourceDefinition", PACKAGE + "CustomResourceDefinitionList"]
    messages = {}
    while pending:
        name = pending.pop()
        if name in messages:
            continue
        messages[name] = all_messages[name]
        pending.extend(field["type"] for field in messages[name].values() if field["type"] not in shared.SCALARS)
    for filename in ["crd-types.go", "jsonschema-types.go"]:
        for structure in re.finditer(r"type (\w+) struct \{(.*?)^\}", sources[filename], re.S | re.M):
            fields = messages.get(PACKAGE + structure[1], {})
            for line in structure[2].splitlines():
                declaration = re.match(r"\s*\w+\s+(\S+)\s+`([^`]+)`", line)
                if not declaration:
                    continue
                number = re.search(r'protobuf:"[^,]+,(\d+),', declaration[2])
                tag = re.search(r'json:"([^\"]+)"', declaration[2])
                field = fields.get(number[1]) if number else None
                if not field or not tag or tag[1] == "-":
                    continue
                parts = tag[1].split(",")
                field["name"] = parts[0]
                if ("omitempty" in parts and not declaration[1].startswith("*")
                        and not field.get("repeated") and not field.get("mapKey")
                        and field["type"] in {"string", "bool", "int32", "int64", "float", "double"}):
                    field["omitEmpty"] = True
    result = {"kubernetesVersion": "v1.36.0", "sourceLicense": "Apache-2.0; Copyright The Kubernetes Authors",
              "sources": {name: {"url": shared.BASE + relative, "sha256": digest} for name, (relative, digest) in shared.SOURCES.items()},
              "messages": messages}
    output = ROOT / "schema/crd-wire-v1.json"
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"Wrote {len(messages)} reachable CRD wire messages ({output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
