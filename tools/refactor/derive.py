#!/usr/bin/env python3
"""Derive, per module package, its full :export list (owned symbols) and its
:import-from needs (cross-package symbols its files reference), from the
final-ownership map + a scan of the module's source files."""
import os, re, sys, json, collections

ROOT = "/home/green/git/refactor-gr8s/gr8s"
MAP = {}
for line in open(f"{ROOT}/tools/refactor/gr8s-final-owners.tsv"):
    name, owner = line.rstrip("\n").split("\t")
    MAP[name] = owner            # NAME(upper) -> OWNER package

# 28 re-home overrides: file rel-key (no .lisp) -> package
REHOME = {
 "version":"GR8S.FOUNDATION","foundation/dns":"GR8S.FOUNDATION",
 "foundation/json":"GR8S.FOUNDATION","foundation/network-steering":"GR8S.FOUNDATION",
 "telemetry/cluster":"GR8S.TELEMETRY","generated/cri-wire-compat":"GR8S.GENERATED",
 "agent/pod-pool":"GR8S.AGENT","network/pod-host-ports":"GR8S.NETWORK",
 "controllers/scheduler":"GR8S.CONTROLLERS","server/notices":"GR8S.SERVER",
}
for f in ["container-probe-spec","container-resources","env-files","pod-conditions",
 "pod-deletion","pod-ephemeral","pod-finalizers","pod-host-settings","pod-parser-policy",
 "pod-runtime-model","pod-status-store","runtime-deletion","user-namespaces"]:
    REHOME[f"kubelet/{f}"]="GR8S.KUBELET"
for f in ["runtime-assets","runtime-addons","zstd","tar","runtime-install"]:
    REHOME[f"runtime/{f}"]="GR8S.RUNTIME"

INPKG = re.compile(r'^\(in-package\s+#?:?#?([A-Za-z0-9.+*/-]+)\)', re.M)
def file_package(path):
    rel = path[len(ROOT)+5:-5]   # strip ROOT/src/ ... .lisp
    if rel in REHOME: return REHOME[rel]
    txt = open(path, encoding="utf-8", errors="replace").read()
    m = INPKG.search(txt)
    return m.group(1).upper() if m else None

# gather all src lisp files per package
files_by_pkg = collections.defaultdict(list)
for dp, dn, fn in os.walk(f"{ROOT}/src"):
    for name in fn:
        if name.endswith(".lisp"):
            p = os.path.join(dp, name)
            pk = file_package(p)
            if pk: files_by_pkg[pk].append(p)

# token scanner: strip ; line comments and "..." strings crudely, then grab symbol tokens
TOK = re.compile(r"[A-Za-z%+*/<>=!?.-][A-Za-z0-9%+*/<>=!?._-]*")
def tokens(path):
    out=set()
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.split(';',1)[0]
        line = re.sub(r'"(\\.|[^"\\])*"', ' ', line)
        for t in TOK.findall(line):
            if ':' in t:   # package-qualified -> skip (already explicit)
                continue
            out.add(t.upper())
    return out

exports = {}   # pkg -> sorted owned names
imports = {}   # pkg -> {owner: set(names)}
for pkg, files in files_by_pkg.items():
    owned = sorted(n for n,o in MAP.items() if o==pkg)
    exports[pkg]=owned
    need = collections.defaultdict(set)
    seen=set()
    for f in files: seen |= tokens(f)
    for t in seen:
        o = MAP.get(t)
        if o and o!=pkg and o!="CL":
            need[o].add(t)
    imports[pkg]={k:sorted(v) for k,v in need.items()}

os.makedirs(f"{ROOT}/tools/refactor/gen", exist_ok=True)
json.dump({"exports":exports,"imports":imports},
          open(f"{ROOT}/tools/refactor/gen/derived.json","w"), indent=0)
# summary
for pkg in sorted(exports):
    imp = imports[pkg]
    print(f"{pkg:28} export={len(exports[pkg]):4}  import_from={len(imp):2} pkgs / {sum(len(v) for v in imp.values()):4} syms  files={len(files_by_pkg[pkg])}")
