#!/usr/bin/env python3
"""Rewrite facade GR8S::NAME / GR8S:NAME references in src/ to their owner package.

Companion to rewrite-test-refs.py, for the handful of implementation files that
still reach sibling symbols through the GR8S composition package.  Each
GR8S:NAME / GR8S::NAME is rewritten to <owner-package>::NAME from the live-image
ownership map (tools/refactor/gen/gr8s-accessible-owners.tsv).  Module-qualified
references (gr8s.foo:bar) and anything inside strings / comments / char literals
are left untouched.

The explicit FILES list excludes the facade machinery itself (compat.lisp,
stage1-declarations, foundation/declarations, src/package.lisp) -- those are
deleted outright, not rewritten.

Usage:
  rewrite-src-facade-refs.py            # dry run: counts + unmapped names
  rewrite-src-facade-refs.py --apply    # rewrite files in place
"""
import re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
MAP = ROOT / "tools/refactor/gen/gr8s-accessible-owners.tsv"
APPLY = "--apply" in sys.argv

FILES = [
    "src/agent/runtime.lisp",
    "src/apiserver/slynk-tunnel.lisp",
    "src/controllers/scheduler-controller.lisp",
    "src/controllers/scheduler.lisp",
    "src/ha/compaction.lisp",
    "src/ha/control-plane.lisp",
    "src/ha/maintenance.lisp",
    "src/ha/plane.lisp",
    "src/kubelet/resource-topology.lisp",
    "src/network/rtnetlink.lisp",
    "src/network/vxlan.lisp",
    "src/network/wireguard.lisp",
    "src/raft/transport/cluster.lisp",
    "src/raft/transport/member.lisp",
    "src/raft/transport/snapshot.lisp",
    "src/runtime/containerd/cri.lisp",
    "src/runtime/containerd/runtime.lisp",
    "src/server/state-ownership.lisp",
]

def owner_to_prefix(owner):
    return "cl" if owner == "COMMON-LISP" else owner.lower()

owners = {}
for line in MAP.read_text().splitlines():
    if "\t" in line:
        name, owner = line.split("\t", 1)
        owners[name.upper()] = owner_to_prefix(owner)

SYMCH = r"[A-Za-z0-9+*/<>=!?%&_.$^~@-]"
TOKEN = re.compile(r"(?<![A-Za-z0-9.-])([Gg][Rr]8[Ss])(::?)(" + SYMCH + r"+)")

def rewrite_code(segment, stats, unmapped, per_file):
    def repl(m):
        name = m.group(3)
        owner = owners.get(name.upper())
        if owner is None:
            unmapped[name.upper()] = unmapped.get(name.upper(), 0) + 1
            return m.group(0)
        if owner == "gr8s":
            unmapped["<GR8S-HOMED>:" + name.upper()] = unmapped.get("<GR8S-HOMED>:" + name.upper(), 0) + 1
            return m.group(0)
        stats[0] += 1
        per_file[0] += 1
        return f"{owner}::{name}"
    return TOKEN.sub(repl, segment)

def process(text, stats, unmapped, per_file):
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == ';':
            j = text.find('\n', i)
            if j == -1: j = n
            out.append(text[i:j]); i = j
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == '\\': j += 2; continue
                if text[j] == '"': j += 1; break
                j += 1
            out.append(text[i:j]); i = j
        elif c == '#' and i + 1 < n and text[i+1] == '\\':
            j = i + 2
            if j < n:
                j += 1
                while j < n and re.match(SYMCH, text[j]): j += 1
            out.append(text[i:j]); i = j
        elif c == '#' and i + 1 < n and text[i+1] == '|':
            depth = 1; j = i + 2
            while j < n and depth:
                if text[j:j+2] == '#|': depth += 1; j += 2
                elif text[j:j+2] == '|#': depth -= 1; j += 2
                else: j += 1
            out.append(text[i:j]); i = j
        else:
            j = i
            while j < n and text[j] not in ';"#':
                j += 1
            if j < n and text[j] == '#' and not (j+1 < n and text[j+1] in '\\|'):
                j += 1
                while j < n and text[j] not in ';"#':
                    j += 1
            out.append(rewrite_code(text[i:j], stats, unmapped, per_file)); i = j
    return "".join(out)

stats = [0]
unmapped = {}
changed_files = 0
for rel in FILES:
    f = ROOT / rel
    text = f.read_text()
    per_file = [0]
    new = process(text, stats, unmapped, per_file)
    if per_file[0] and APPLY:
        f.write_text(new)
    if per_file[0]:
        changed_files += 1

print(f"{'APPLIED' if APPLY else 'DRY RUN'}: {stats[0]} rewrites across {changed_files} files ({len(FILES)} scanned)")
if unmapped:
    print(f"UNMAPPED names ({len(unmapped)} distinct):")
    for k in sorted(unmapped, key=lambda x: -unmapped[x]):
        print(f"  {unmapped[k]:5d}  {k}")
