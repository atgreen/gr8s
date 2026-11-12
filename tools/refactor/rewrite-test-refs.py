#!/usr/bin/env python3
"""Rewrite GR8S::NAME / GR8S:NAME references in test files to their owner package.

After the composition package is eliminated, GR8S no longer owns these symbols.
Each GR8S:NAME / GR8S::NAME is rewritten to <owner-package>::NAME, where the
owner is taken from the live image map (tools/refactor/gen/gr8s-accessible-owners.tsv:
NAME<TAB>OWNER-PACKAGE, i.e. exactly what GR8S::NAME resolves to today).

Token-aware: skips Lisp strings "...", line comments ; ..., block comments #| |#,
and character literals #\\x, so only real code tokens are rewritten. Already
module-qualified refs (gr8s.foo:bar) are left untouched.

Usage:
  rewrite-test-refs.py            # dry run: report counts + unmapped names
  rewrite-test-refs.py --apply    # rewrite files in place
"""
import re, sys, pathlib, glob

ROOT = pathlib.Path(__file__).resolve().parents[2]
MAP = ROOT / "tools/refactor/gen/gr8s-accessible-owners.tsv"
APPLY = "--apply" in sys.argv

def owner_to_prefix(owner):
    if owner == "COMMON-LISP":
        return "cl"
    return owner.lower()

owners = {}
for line in MAP.read_text().splitlines():
    if "\t" in line:
        name, owner = line.split("\t", 1)
        owners[name.upper()] = owner_to_prefix(owner)

# Match a gr8s: or gr8s:: package-qualified symbol, where 'gr8s' is NOT followed
# by a '.' (that would be gr8s.module:...). Case-insensitive package name.
# Symbol-name chars: letters, digits, and the usual Lisp constituent punctuation.
SYMCH = r"[A-Za-z0-9+*/<>=!?%&_.$^~@-]"
TOKEN = re.compile(r"(?<![A-Za-z0-9.-])([Gg][Rr]8[Ss])(::?)(" + SYMCH + r"+)")

def rewrite_code(segment, stats, unmapped, per_file):
    def repl(m):
        colons, name = m.group(2), m.group(3)
        key = name.upper()
        owner = owners.get(key)
        if owner is None:
            unmapped[key] = unmapped.get(key, 0) + 1
            return m.group(0)  # leave untouched
        if owner == "gr8s":
            # Resolves to a bare GR8S-homed symbol (reader junk, no real def) --
            # leave as-is and report; should not occur for real references.
            unmapped["<GR8S-HOMED>:" + key] = unmapped.get("<GR8S-HOMED>:" + key, 0) + 1
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
            # character literal: #\x or #\Newline -- consume #\ + following token
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
            # include a lone '#' that isn't a comment/char start
            if j < n and text[j] == '#' and not (j+1 < n and text[j+1] in '\\|'):
                j += 1
                while j < n and text[j] not in ';"#':
                    j += 1
            out.append(rewrite_code(text[i:j], stats, unmapped, per_file)); i = j
    return "".join(out)

files = sorted(glob.glob(str(ROOT / "tests" / "**" / "*.lisp"), recursive=True))
stats = [0]
unmapped = {}
changed_files = 0
for f in files:
    text = pathlib.Path(f).read_text()
    per_file = [0]
    new = process(text, stats, unmapped, per_file)
    if per_file[0] and APPLY:
        pathlib.Path(f).write_text(new)
    if per_file[0]:
        changed_files += 1

print(f"{'APPLIED' if APPLY else 'DRY RUN'}: {stats[0]} rewrites across {changed_files} files ({len(files)} scanned)")
if unmapped:
    print(f"UNMAPPED names ({len(unmapped)} distinct):")
    for k in sorted(unmapped, key=lambda x: -unmapped[x])[:40]:
        print(f"  {unmapped[k]:5d}  {k}")
