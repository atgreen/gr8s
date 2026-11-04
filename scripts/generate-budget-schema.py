#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Generate pinned policy/v1 PodDisruptionBudget wire and structural schema additions."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
SOURCES = {
    "policy.proto": ("api/v0.36.0/policy/v1/generated.proto", "1914fbf0fd8915a7996ef49137561e8c4e27839673471b30fba6b47c99c5605a"),
    "policy-types.go": ("api/v0.36.0/policy/v1/types.go", "74b315b469f29db121b4ec9d3ac529e40c4a99ebc22bf521652357e9565ef856"),
}


def main():
    """Verify source checksums and write only definitions absent from the core schema."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "build/kubernetes-budget")
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
    roots = ["k8s.io.api.policy.v1.PodDisruptionBudget", "k8s.io.api.policy.v1.Eviction"]
    pending, messages = roots[:], {}
    while pending:
        name = pending.pop()
        if name in messages or name in baseline["messages"]:
            continue
        messages[name] = all_messages[name]
        pending.extend(f["type"] for f in messages[name].values() if f["type"] not in core.SCALARS)
    for source, package in [("policy-types.go", "k8s.io.api.policy.v1.")]:
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
    pending += ["io.k8s.api.policy.v1.PodDisruptionBudgetList", "io.k8s.api.policy.v1.Eviction"]
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
    output = ROOT / "schema/budget-v1.json"
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"Wrote {len(messages)} messages and {len(definitions)} definitions")


if __name__ == "__main__":
    main()
