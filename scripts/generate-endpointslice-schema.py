#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Generate pinned discovery.k8s.io/v1 EndpointSlice schema additions."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
SOURCES = {
    "discovery.proto": ("api/v0.36.0/discovery/v1/generated.proto", "adec6d465b34c380ee3ec80f71d0b8104b743d8a1767434bacf5646d6607e4c7"),
    "discovery-types.go": ("api/v0.36.0/discovery/v1/types.go", "1b42067dbd371c28b1d9c1c5b5a25267e991e893d0fc781285409818f86eadd6"),
}


def main():
    """Verify source checksums and write only definitions absent from the core schema."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "build/kubernetes-endpoints")
    parser.add_argument("--core-cache", type=Path, default=ROOT / "build/kubernetes-schema")
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("core_generator", ROOT / "scripts/generate-podtemplate-schema.py")
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    sources = core.load_sources(args.core_cache)
    args.cache.mkdir(parents=True, exist_ok=True)
    for name, (relative, digest) in SOURCES.items():
        path = args.cache / name
        if not path.exists():
            path.write_bytes(urllib.request.urlopen(core.BASE + relative, timeout=60).read())
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Source checksum mismatch: " + name)
        sources[name] = data.decode()
    baseline = json.loads((ROOT / "schema/podtemplate-v1.json").read_text())
    all_messages = core.proto_messages(sources)
    roots = ["k8s.io.api.discovery.v1.EndpointSlice"]
    pending, messages = roots[:], {}
    while pending:
        name = pending.pop()
        if name in messages or name in baseline["messages"]:
            continue
        messages[name] = all_messages[name]
        pending.extend(f["type"] for f in messages[name].values() if f["type"] not in core.SCALARS)
    for source, package in [("discovery-types.go", "k8s.io.api.discovery.v1.")]:
        for structure in re.finditer(r"type (\w+) struct \{(.*?)^\}", sources[source], re.S | re.M):
            fields = messages.get(package + structure[1], {})
            for line in structure[2].splitlines():
                declaration = re.match(r"\s*\w+\s+(\S+)\s+`([^`]+)`", line)
                if not declaration or declaration[1].startswith("*"):
                    continue
                number = re.search(r'protobuf:"[^,]+,(\d+),', declaration[2])
                tag = re.search(r'json:"([^\"]+)"', declaration[2])
                if number and tag and "omitempty" in tag[1].split(","):
                    f = fields.get(number[1])
                    if f and not f.get("repeated") and not f.get("mapKey") and f["type"] in {"string", "bool", "int32", "int64"}:
                        f["omitEmpty"] = True
    all_definitions = json.loads(sources["swagger.json"])["definitions"]
    pending = [n.replace("k8s.io.", "io.k8s.", 1) for n in roots]
    pending += ["io.k8s.api.discovery.v1.EndpointSliceList"]
    definitions = {}
    while pending:
        name = pending.pop()
        if name in definitions or name in baseline["definitions"]:
            continue
        definitions[name] = core.structural(all_definitions[name])
        pending.extend(core.references(definitions[name]))
    result = {"kubernetesVersion": "v1.36.0", "sourceLicense": "Apache-2.0; Copyright The Kubernetes Authors",
              "sources": {n: {"url": core.BASE + p, "sha256": d} for n, (p, d) in SOURCES.items()},
              "messages": messages, "definitions": definitions}
    output = ROOT / "schema/endpointslices-v1.json"
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"Wrote {len(messages)} messages and {len(definitions)} definitions")


if __name__ == "__main__":
    main()
