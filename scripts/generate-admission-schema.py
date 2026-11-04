#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Generate pinned admissionregistration.k8s.io/v1 webhook wire and structural schema additions."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
SOURCES = {
    "admission.proto": ("api/v0.36.0/admissionregistration/v1/generated.proto", "b3e61003741775cbbde27473bb52b8b35a6191013bb8dd231a1e7d21d86b6b93"),
    "admission-types.go": ("api/v0.36.0/admissionregistration/v1/types.go", "35f58a673ffd825f9bf1ba7ac36795be353978e9d0db507eb7874b8d86bc9b74"),
}
PACKAGE = "k8s.io.api.admissionregistration.v1."
KINDS = ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"]


def main():
    """Verify source checksums and write only the webhook definitions absent from the core schema."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "build/kubernetes-admission")
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
    pending, messages = [PACKAGE + kind for kind in KINDS], {}
    while pending:
        name = pending.pop()
        if name in messages or name in baseline["messages"]:
            continue
        messages[name] = all_messages[name]
        pending.extend(f["type"] for f in messages[name].values() if f["type"] not in core.SCALARS)
    # The proto capitalizes this field although types.go serializes it as "webhooks".
    for kind in KINDS:
        messages[PACKAGE + kind]["2"]["name"] = "webhooks"
    # types.go declares the Rule embedded in RuleWithOperations with json:",inline".
    messages[PACKAGE + "RuleWithOperations"]["2"]["inline"] = True
    all_definitions = json.loads(sources["swagger.json"])["definitions"]
    pending = ["io.k8s.api.admissionregistration.v1." + kind + suffix for kind in KINDS for suffix in ("", "List")]
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
    output = ROOT / "schema/admissionregistration-v1.json"
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"Wrote {len(messages)} messages and {len(definitions)} definitions")


if __name__ == "__main__":
    main()
