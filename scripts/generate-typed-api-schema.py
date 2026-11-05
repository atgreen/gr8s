#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
"""Generate wire and structural schemas for the API-only and review resources from pinned v1.36 inputs."""
import argparse
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("gr8s_schema", ROOT / "scripts/generate-podtemplate-schema.py")
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
PREFIX = "api/v0.36.0/"
EXTRA_SOURCES = {
    "coordination.proto": (PREFIX + "coordination/v1/generated.proto", "ff9af484a3fc853e5bcad5c2daad8fb0bcb98f2e0d612fb4c05711c897d27047"),
    "coordination-types.go": (PREFIX + "coordination/v1/types.go", "bca731e4e1fb343905759f523f9a77ea5e78151f3f08d0e523adc6359ca863eb"),
    "flowcontrol.proto": (PREFIX + "flowcontrol/v1/generated.proto", "dac873d11fee3bcb2c842d63d818e5c649ee9cde7a71d8d0fa83cdad68762e25"),
    "flowcontrol-types.go": (PREFIX + "flowcontrol/v1/types.go", "ead33a57f173747a1afb7c5bc0dc8e46434fdb696f8b7edcddc80c3f9e9a894d"),
    "dra.proto": (PREFIX + "resource/v1/generated.proto", "fcd53dbac0eebd17c051e24b6d420469a8e17efec091bffdb0ed797e83f0dd88"),
    "dra-types.go": (PREFIX + "resource/v1/types.go", "1d8331bf115eb3a8d753ad8c5f73d30896db88bb45ec2c405c4f9b97fe3a89db"),
    "authorization.proto": (PREFIX + "authorization/v1/generated.proto", "94d3e85950038b33162c751c6d31ff72cd6b131946dfd70b77166747385cf7c6"),
    "authorization-types.go": (PREFIX + "authorization/v1/types.go", "64862e32b366bd7fa857d6a41e8ec27f9158e994c1ef9f7949ad12b2ae7f2c5e"),
    "authentication.proto": (PREFIX + "authentication/v1/generated.proto", "cf5ea7e838b8e0f9813b2de1fb92ca51980b48aaa5ac119cb67a317295b67c8e"),
    "authentication-types.go": (PREFIX + "authentication/v1/types.go", "f1c306a4db914b0582503120adfd902d1a24d4bff2674c487c90cae461d16b10"),
    "admission.proto": (PREFIX + "admissionregistration/v1/generated.proto", "b3e61003741775cbbde27473bb52b8b35a6191013bb8dd231a1e7d21d86b6b93"),
    "autoscaling1.proto": (PREFIX + "autoscaling/v1/generated.proto", "c3db74d68ab413a0413562da6e3951f7cb21198ef2ea2877bce24381bf9c756a"),
    "autoscaling1-types.go": (PREFIX + "autoscaling/v1/types.go", "ab10da716388987895cb94be11cf776b5632644128de7959cd97bc37b5b874c6"),
    "autoscaling2.proto": (PREFIX + "autoscaling/v2/generated.proto", "5685de748fa37900a21082f826e93f349a7e3203d4c6bfd2225ba893d5b9a01a"),
    "autoscaling2-types.go": (PREFIX + "autoscaling/v2/types.go", "68f36b28a6bb91cb0c9ca53591d8e5d52778f7f2ca69cea3120ba7eae95910aa"),
    "admission-types.go": (PREFIX + "admissionregistration/v1/types.go", "35f58a673ffd825f9bf1ba7ac36795be353978e9d0db507eb7874b8d86bc9b74"),
}
TYPES = [("core-types.go", "k8s.io.api.core.v1."), ("coordination-types.go", "k8s.io.api.coordination.v1."),
         ("flowcontrol-types.go", "k8s.io.api.flowcontrol.v1."), ("dra-types.go", "k8s.io.api.resource.v1."),
         ("authorization-types.go", "k8s.io.api.authorization.v1."), ("authentication-types.go", "k8s.io.api.authentication.v1."),
         ("admission-types.go", "k8s.io.api.admissionregistration.v1."),
         ("autoscaling1-types.go", "k8s.io.api.autoscaling.v1."), ("autoscaling2-types.go", "k8s.io.api.autoscaling.v2.")]
ROOTS = [package + kind for package, kinds in (
    ("k8s.io.api.core.v1.", ["NamespaceStatus"]),
    ("k8s.io.api.coordination.v1.", ["Lease"]),
    ("k8s.io.api.autoscaling.v1.", ["HorizontalPodAutoscaler"]),
    ("k8s.io.api.autoscaling.v2.", ["HorizontalPodAutoscaler"]),
    ("k8s.io.api.flowcontrol.v1.", ["PriorityLevelConfiguration", "FlowSchema"]),
    ("k8s.io.api.resource.v1.", ["DeviceClass", "ResourceClaim", "ResourceClaimTemplate", "ResourceSlice"]),
    ("k8s.io.api.admissionregistration.v1.", ["ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding",
                                              "MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding"]),
    ("k8s.io.api.authorization.v1.", ["SubjectAccessReview", "LocalSubjectAccessReview", "SelfSubjectAccessReview", "SelfSubjectRulesReview"]),
    ("k8s.io.api.authentication.v1.", ["TokenRequest", "TokenReview", "SelfSubjectReview"]),
) for kind in kinds]
REVIEWS = {"NamespaceStatus", "TokenRequest", "TokenReview", "SelfSubjectReview", "SubjectAccessReview", "LocalSubjectAccessReview",
           "SelfSubjectAccessReview", "SelfSubjectRulesReview"}


def resolve_full_sources(cache):
    """Complete the abbreviated digests from the admission generator's own lock entries."""
    for name, generator in (("admission", "generate-admission-schema.py"),):
        text = (ROOT / "scripts" / generator).read_text()
        for key in (name + ".proto", name + "-types.go"):
            EXTRA_SOURCES[key] = (EXTRA_SOURCES[key][0], re.search(r'"%s": \("[^"]+", "([0-9a-f]{64})"' % re.escape(key), text)[1])
    shared.SOURCES.update(EXTRA_SOURCES)
    return shared.load_sources(cache)


def leaf_names(all_messages, fields):
    """Name the JSON fields a message contributes once its nested inline members flatten."""
    names = set()
    for field in fields.values():
        names.add(field["name"])
        child = all_messages.get(field["type"], {})
        names |= {name for name in leaf_names(all_messages, child)} if child and field.get("inline") else set()
    return names


def main():
    """Write only the wire and structural closure the existing schema files lack."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "build/kubernetes-typed")
    args = parser.parse_args()
    sources = resolve_full_sources(args.cache)
    all_messages = shared.proto_messages(sources)
    existing_messages, existing_definitions = set(), set()
    output = ROOT / "schema/typed-apis-v1.json"
    for path in (ROOT / "schema").glob("*-v1.json"):
        if path != output:
            schema = json.loads(path.read_text())
            existing_messages |= set(schema.get("messages", {}))
            existing_definitions |= set(schema.get("definitions", {}))
    pending, messages = list(ROOTS), {}
    while pending:
        name = pending.pop()
        if name in messages or name in existing_messages:
            continue
        messages[name] = all_messages[name]
        pending.extend(field["type"] for field in messages[name].values() if field["type"] not in shared.SCALARS)
    for source, package in TYPES:
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
    # Inline innermost messages first, so an outer inline member sees its child's flattened names.
    for _ in range(3):
        for name, fields in messages.items():
            properties = all_definitions.get(name.replace("k8s.io.", "io.k8s.", 1), {}).get("properties", {})
            for field in fields.values():
                if properties and field["name"] not in properties and not field.get("inline"):
                    folded = {key.lower(): key for key in properties}
                    if field["name"].lower() in folded:
                        field["name"] = folded[field["name"].lower()]
                    else:
                        child = all_messages.get(field["type"], messages.get(field["type"], {}))
                        if child and leaf_names(all_messages, child) & set(properties):
                            field["inline"] = True
    for name, fields in messages.items():
        properties = all_definitions.get(name.replace("k8s.io.", "io.k8s.", 1), {}).get("properties", {})
        for field in fields.values():
            if properties and field["name"] not in properties and not field.get("inline"):
                raise ValueError(f"Unmapped JSON field: {name}.{field['name']}")
    pending = [root.replace("k8s.io.", "io.k8s.", 1) for root in ROOTS]
    pending.extend(name + "List" for name in list(pending) if name.rsplit(".", 1)[1] not in REVIEWS)
    definitions = {}
    while pending:
        name = pending.pop()
        if name in definitions or name in existing_definitions:
            continue
        definitions[name] = shared.structural(all_definitions[name])
        pending.extend(shared.references(definitions[name]))
    result = {"kubernetesVersion": "v1.36.0", "sourceLicense": "Apache-2.0; Copyright The Kubernetes Authors",
              "sources": {key: {"url": shared.BASE + path, "sha256": digest} for key, (path, digest) in EXTRA_SOURCES.items()},
              "messages": messages, "definitions": definitions}
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"Wrote {len(messages)} messages and {len(definitions)} definitions")


if __name__ == "__main__":
    main()
