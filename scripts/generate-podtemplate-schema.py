#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 gr8s contributors
# SPDX-License-Identifier: MIT
"""Generate PodTemplate wire and structural schemas from pinned Kubernetes sources."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
BASE = "https://raw.githubusercontent.com/kubernetes/"
SOURCES = {
    "core-types.go": ("api/v0.36.0/core/v1/types.go", "335f6d034eb92b6751e9fc3833e5c027aa0da8138de44acaaadf62c5cf25183a"),
    "core.proto": ("api/v0.36.0/core/v1/generated.proto", "b1879943525fb1b0d7055570ad1a9ff6ef7502b95ee7962e0fa99d2546c52760"),
    "meta.proto": ("apimachinery/v0.36.0/pkg/apis/meta/v1/generated.proto", "055dd5d588bbe7cff216d570ad0968833eddaea755701e47d01e59ad61625eba"),
    "resource.proto": ("apimachinery/v0.36.0/pkg/api/resource/generated.proto", "78274163443c9942fd5cfd41d2c0cb6d5bb06ff109f37c33be23147dcf63771a"),
    "intstr.proto": ("apimachinery/v0.36.0/pkg/util/intstr/generated.proto", "3595eaaeb57a233568c50c9e16d81efa50238f63e9f7d8d00f18b188fa8fdcb2"),
    "runtime.proto": ("apimachinery/v0.36.0/pkg/runtime/generated.proto", "19a098984ebde051f717387ef35ae0069104eab9c0534a4bb37470ea1d47fcc9"),
    "schema.proto": ("apimachinery/v0.36.0/pkg/runtime/schema/generated.proto", "f6c8cc582d36e639e022c9edc2faf213ab16fe07045fabf54f5edc2241eda3e5"),
    "swagger.json": ("kubernetes/v1.36.0/api/openapi-spec/swagger.json", "dcede2063da1d7ad62ecb5af8adb6d7fabd0b52385a7fa0048afb491dac90450"),
}
SCALARS = {"string", "bytes", "bool", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "float", "double"}


def load_sources(cache):
    """Read cached inputs or fetch them, rejecting any content that differs from the lock."""
    cache.mkdir(parents=True, exist_ok=True)
    result = {}
    for name, (relative, digest) in SOURCES.items():
        path = cache / name
        if not path.exists():
            path.write_bytes(urllib.request.urlopen(BASE + relative, timeout=60).read())
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"Source checksum mismatch: {name}")
        result[name] = data.decode()
    return result


def proto_messages(sources):
    """Extract flat go-to-protobuf message fields, checking every field declaration."""
    messages = {}
    for name, source in sources.items():
        if not name.endswith(".proto"):
            continue
        source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
        source = re.sub(r"//[^\n]*", "", source)
        package = re.search(r"package\s+([\w.]+);", source)[1]
        for match in re.finditer(r"message\s+(\w+)\s*\{([^{}]*)\}", source, re.S):
            fields = {}
            for declaration in match[2].split(";"):
                declaration = declaration.strip()
                if not declaration or declaration.startswith(("reserved ", "option ")):
                    continue
                item = re.fullmatch(r"(optional|repeated)\s+([.\w]+)\s+(\w+)\s*=\s*(\d+)(?:\s*\[.*\])?", declaration, re.S)
                mapping = re.fullmatch(r"map\s*<\s*(\w+)\s*,\s*([.\w]+)\s*>\s+(\w+)\s*=\s*(\d+)(?:\s*\[.*\])?", declaration, re.S)
                if not (item or mapping):
                    raise ValueError(f"Unsupported declaration in {match[1]}: {declaration}")
                cardinality, field_type, field_name, number = item.groups() if item else mapping.groups()
                if field_type not in SCALARS:
                    field_type = field_type.lstrip(".") if field_type.startswith(".") else package + "." + field_type
                field = {"name": field_name, "type": field_type}
                if item and cardinality == "repeated":
                    field["repeated"] = True
                if mapping:
                    field["mapKey"] = cardinality
                fields[number] = field
            messages[package + "." + match[1]] = fields
    return messages


def references(value):
    """Yield every OpenAPI definition referenced by a structural schema."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref":
                yield item.rsplit("/", 1)[-1]
            else:
                yield from references(item)
    elif isinstance(value, list):
        for item in value:
            yield from references(item)


def structural(value):
    """Keep machine-readable constraints and merge keys, omitting upstream prose."""
    if isinstance(value, list):
        return [structural(item) for item in value]
    if not isinstance(value, dict):
        return value
    keep = {"$ref", "type", "format", "required", "items", "additionalProperties", "allOf", "anyOf", "oneOf", "enum", "minimum", "maximum", "minLength", "maxLength", "pattern", "minItems", "maxItems", "nullable"}
    result = {key: structural(item) for key, item in value.items() if key in keep or key.startswith("x-kubernetes-")}
    if "properties" in value:
        result["properties"] = {key: structural(item) for key, item in value["properties"].items()}
    return result


def main():
    """Write deterministic schemas reachable from PodTemplate and PodTemplateList."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / "build/kubernetes-schema")
    args = parser.parse_args()
    sources = load_sources(args.cache)
    all_messages = proto_messages(sources)
    pending = ["k8s.io.api.core.v1.PodTemplate", "k8s.io.api.core.v1.Pod"]
    messages = {}
    while pending:
        name = pending.pop()
        if name in messages:
            continue
        messages[name] = all_messages[name]
        pending.extend(field["type"] for field in messages[name].values() if field["type"] not in SCALARS)
    # Generated Go protobuf writes non-pointer scalar zero values even where
    # the corresponding JSON field is omitted. Preserve pointer zero values.
    for structure in re.finditer(r"type (\w+) struct \{(.*?)^\}", sources["core-types.go"], re.S | re.M):
        fields = messages.get("k8s.io.api.core.v1." + structure[1], {})
        for line in structure[2].splitlines():
            declaration = re.match(r"\s*\w+\s+(\S+)\s+`([^`]+)`", line)
            if not declaration or declaration[1].startswith("*"):
                continue
            tags = declaration[2]
            number = re.search(r'protobuf:"[^,]+,(\d+),', tags)
            json_tag = re.search(r'json:"([^\"]+)"', tags)
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
    pending = ["io.k8s.api.core.v1.PodTemplate", "io.k8s.api.core.v1.PodTemplateList"]
    while pending:
        name = pending.pop()
        if name in definitions:
            continue
        definitions[name] = structural(all_definitions[name])
        pending.extend(references(definitions[name]))
    result = {"kubernetesVersion": "v1.36.0", "sourceLicense": "Apache-2.0; Copyright The Kubernetes Authors", "sources": {name: {"url": BASE + relative, "sha256": digest} for name, (relative, digest) in SOURCES.items()}, "messages": messages, "definitions": definitions}
    output = ROOT / "schema/podtemplate-v1.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"Wrote {len(messages)} wire messages and {len(definitions)} structural definitions ({output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
