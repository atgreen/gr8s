#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Generate typed storage schemas from checksum-pinned Kubernetes v1.36 inputs."""
import argparse
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gr8s_schema", ROOT / "scripts/generate-podtemplate-schema.py")
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
EXTRA_SOURCES = {
    "storage.proto": ("api/v0.36.0/storage/v1/generated.proto", "48e2d5a90d78c4c215b40c638ff5583308fd1c34ffac94e2c18ad3b7d3fad0fd"),
    "storage-types.go": ("api/v0.36.0/storage/v1/types.go", "73a547a11d4b350d4d31b6e8aaa63a003314509360388f45da66b07b86d7f5a8"),
}


def main():
    """Write the complete reachable storage wire and structural schema closure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "build/kubernetes-schema")
    args = parser.parse_args()
    shared.SOURCES.update(EXTRA_SOURCES)
    sources = shared.load_sources(args.cache)
    all_messages = shared.proto_messages(sources)
    roots = ["k8s.io.api.core.v1.PersistentVolume", "k8s.io.api.core.v1.PersistentVolumeClaim", "k8s.io.api.storage.v1.StorageClass",
             "k8s.io.api.storage.v1.CSIDriver", "k8s.io.api.storage.v1.CSINode", "k8s.io.api.storage.v1.VolumeAttachment",
             "k8s.io.api.storage.v1.CSIStorageCapacity"]
    pending = list(roots)
    messages = {}
    while pending:
        name = pending.pop()
        if name in messages:
            continue
        messages[name] = all_messages[name]
        pending.extend(field["type"] for field in messages[name].values() if field["type"] not in shared.SCALARS)
    for source, package in [("core-types.go", "k8s.io.api.core.v1."), ("storage-types.go", "k8s.io.api.storage.v1.")]:
        for structure in re.finditer(r"type (\w+) struct \{(.*?)^\}", sources[source], re.S | re.M):
            fields = messages.get(package + structure[1], {})
            for line in structure[2].splitlines():
                declaration = re.match(r"\s*\w+\s+(\S+)\s+`([^`]+)`", line)
                if not declaration or declaration[1].startswith("*"):
                    continue
                number = re.search(r'protobuf:"[^,]+,(\d+),', declaration[2])
                json_tag = re.search(r'json:"([^\"]+)"', declaration[2])
                if number and json_tag and "omitempty" in json_tag[1].split(","):
                    field = fields.get(number[1])
                    if field and not field.get("repeated") and not field.get("mapKey") and field["type"] in {"string", "bool", "int32", "int64"}:
                        field["omitEmpty"] = True
    all_definitions = json.loads(sources["swagger.json"])["definitions"]
    for name, fields in messages.items():
        properties = all_definitions.get(name.replace("k8s.io.", "io.k8s.", 1), {}).get("properties", {})
        for field in fields.values():
            if properties and field["name"] not in properties:
                child = all_messages.get(field["type"], {})
                if not child or not all(item["name"] in properties for item in child.values()):
                    raise ValueError(f"Unmapped JSON field: {name}.{field['name']}")
                field["inline"] = True
    definitions = {}
    pending = [name.replace("k8s.io.", "io.k8s.", 1) for name in roots]
    pending.extend(name + "List" for name in list(pending))
    while pending:
        name = pending.pop()
        if name in definitions:
            continue
        definitions[name] = shared.structural(all_definitions[name])
        pending.extend(shared.references(definitions[name]))
    result = {"kubernetesVersion": "v1.36.0", "sourceLicense": "Apache-2.0; Copyright The Kubernetes Authors", "sources": {name: {"url": shared.BASE + relative, "sha256": digest} for name, (relative, digest) in shared.SOURCES.items()}, "messages": messages, "definitions": definitions}
    output = ROOT / "schema/storage-v1.json"
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"Wrote {len(messages)} wire messages and {len(definitions)} storage definitions ({output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
