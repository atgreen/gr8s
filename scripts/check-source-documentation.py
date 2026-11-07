#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
"""Audit first-party source files for the gr8s documentation convention.

The checker keeps a repository-wide documentation sweep measurable.  It checks
SPDX metadata and file-level technical overviews in every supported source
language.  For Common Lisp it also parses enough S-expression structure to
find named top-level functions, macros, generic functions, and methods without
loading the system.  Python functions are checked with the standard AST.

Pass paths to check a subsystem while documentation is being landed in small
commits.  With no paths, the checker discovers the complete first-party source
set and acts as the final repository-wide gate.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
SPDX_COPYRIGHT = "SPDX-FileCopyrightText: 2026 Anthony Green"
SPDX_LICENSE = "SPDX-License-Identifier: Apache-2.0"
GENERATED = {
    Path("src/generated/cri-v1-generated.lisp"),
    Path("src/generated/node-v1-generated.lisp"),
}


@dataclass(frozen=True)
class Token:
    """Represent one structural Lisp token and its one-based source line."""

    kind: str
    value: str
    line: int


@dataclass(frozen=True)
class Form:
    """Represent a parsed Lisp list while retaining its opening source line."""

    items: tuple[Token | "Form", ...]
    line: int


def first_party_sources() -> list[Path]:
    """Return repository-relative source paths owned and maintained by gr8s."""

    paths = {Path("Makefile"), Path("gr8s.asd")}
    for directory, suffixes in (
        ("src", {".lisp"}),
        ("tests", {".lisp"}),
        ("network", {".lisp"}),
        ("scripts", {".lisp", ".py", ".sh"}),
        ("proto/gr8s", {".proto"}),
    ):
        for path in (ROOT / directory).rglob("*"):
            if path.is_file() and path.suffix in suffixes:
                paths.add(path.relative_to(ROOT))
    for name in ("scripts/gr8s",):
        path = Path(name)
        if (ROOT / path).is_file():
            paths.add(path)
    return sorted(paths)


def tokenize_lisp(text: str) -> list[Token]:
    """Tokenize parentheses, atoms, and strings while skipping Lisp comments."""

    tokens: list[Token] = []
    index = 0
    line = 1
    length = len(text)
    while index < length:
        character = text[index]
        if character == "\n":
            line += 1
            index += 1
        elif character.isspace():
            index += 1
        elif character == ";":
            newline = text.find("\n", index)
            index = length if newline < 0 else newline
        elif text.startswith("#|", index):
            depth = 1
            index += 2
            while index < length and depth:
                if text.startswith("#|", index):
                    depth += 1
                    index += 2
                elif text.startswith("|#", index):
                    depth -= 1
                    index += 2
                else:
                    if text[index] == "\n":
                        line += 1
                    index += 1
        elif character in "()":
            tokens.append(Token(character, character, line))
            index += 1
        elif character == '"':
            start_line = line
            index += 1
            value: list[str] = []
            while index < length:
                character = text[index]
                if character == "\\" and index + 1 < length:
                    value.extend((character, text[index + 1]))
                    index += 2
                elif character == '"':
                    index += 1
                    break
                else:
                    if character == "\n":
                        line += 1
                    value.append(character)
                    index += 1
            tokens.append(Token("string", "".join(value), start_line))
        else:
            start = index
            start_line = line
            while index < length and not text[index].isspace() and text[index] not in "();\"":
                index += 1
            tokens.append(Token("atom", text[start:index], start_line))
    return tokens


def parse_lisp(tokens: list[Token]) -> list[Token | Form]:
    """Build a lightweight S-expression tree from structural Lisp tokens."""

    root: list[Token | Form] = []
    stack: list[tuple[list[Token | Form], int]] = []
    current = root
    for token in tokens:
        if token.kind == "(":
            stack.append((current, token.line))
            current = []
        elif token.kind == ")":
            if not stack:
                continue
            parent, line = stack.pop()
            parent.append(Form(tuple(current), line))
            current = parent
        else:
            current.append(token)
    return root


def atom_value(item: Token | Form) -> str | None:
    """Return a lower-case atom value, or ``None`` for strings and lists."""

    if isinstance(item, Token) and item.kind == "atom":
        return item.value.lower()
    return None


def lisp_definitions(forms: list[Token | Form]) -> list[Form]:
    """Return named function-like definitions found anywhere in parsed forms."""

    definitions: list[Form] = []
    for item in forms:
        if not isinstance(item, Form):
            continue
        if item.items and atom_value(item.items[0]) in {
            "defun", "defmacro", "defgeneric", "defmethod"
        }:
            definitions.append(item)
        definitions.extend(lisp_definitions(list(item.items)))
    return definitions


def lisp_definition_name(form: Form) -> str:
    """Render the declared name of a Lisp definition for diagnostics."""

    if len(form.items) < 2:
        return "<missing-name>"
    name = form.items[1]
    if isinstance(name, Token):
        return name.value
    atoms = [item.value for item in name.items if isinstance(item, Token)]
    return "(" + " ".join(atoms) + ")"


def lisp_definition_has_docstring(form: Form) -> bool:
    """Return whether a parsed Lisp definition contains its standard doc form."""

    head = atom_value(form.items[0]) if form.items else None
    if head == "defgeneric":
        return any(
            isinstance(option, Form)
            and len(option.items) >= 2
            and atom_value(option.items[0]) == ":documentation"
            and isinstance(option.items[1], Token)
            and option.items[1].kind == "string"
            for option in form.items[3:]
        )
    lambda_index = next(
        (index for index, item in enumerate(form.items[2:], 2)
         if isinstance(item, Form)),
        None,
    )
    if lambda_index is None or lambda_index + 1 >= len(form.items):
        return False
    following = form.items[lambda_index + 1]
    return isinstance(following, Token) and following.kind == "string"


def check_header(path: Path, text: str) -> list[str]:
    """Return missing SPDX or technical-overview diagnostics for one file."""

    errors: list[str] = []
    first_lines = "\n".join(text.splitlines()[:50])
    if SPDX_COPYRIGHT not in first_lines:
        errors.append(f"{path}: missing {SPDX_COPYRIGHT}")
    if SPDX_LICENSE not in first_lines:
        errors.append(f"{path}: missing {SPDX_LICENSE}")
    if path.suffix == ".py":
        try:
            module = ast.parse(text, filename=str(path))
        except SyntaxError as condition:
            errors.append(f"{path}:{condition.lineno}: cannot parse Python source")
        else:
            if not ast.get_docstring(module, clean=False):
                errors.append(f"{path}: missing technical module docstring")
    elif "Purpose:" not in first_lines:
        errors.append(f"{path}: missing a Purpose: overview near the file header")
    return errors


def check_python(path: Path, text: str) -> list[str]:
    """Return diagnostics for Python functions and methods without docstrings."""

    try:
        module = ast.parse(text, filename=str(path))
    except SyntaxError:
        return []
    errors: list[str] = []
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not ast.get_docstring(node, clean=False):
                errors.append(f"{path}:{node.lineno}: {node.name} has no docstring")
    return errors


def check_lisp(path: Path, text: str) -> list[str]:
    """Return diagnostics for Lisp function-like definitions without docs."""

    errors: list[str] = []
    forms = parse_lisp(tokenize_lisp(text))
    for definition in lisp_definitions(forms):
        if not lisp_definition_has_docstring(definition):
            errors.append(
                f"{path}:{definition.line}: "
                f"{lisp_definition_name(definition)} has no docstring"
            )
    return errors


def check_path(path: Path) -> list[str]:
    """Run all documentation checks applicable to one repository-relative path."""

    absolute = ROOT / path
    if not absolute.is_file():
        return [f"{path}: file does not exist"]
    text = absolute.read_text(encoding="utf-8")
    errors = check_header(path, text)
    if path in GENERATED:
        return errors
    if path.suffix in {".lisp", ".asd"}:
        errors.extend(check_lisp(path, text))
    elif path.suffix == ".py":
        errors.extend(check_python(path, text))
    return errors


def parse_arguments() -> argparse.Namespace:
    """Parse optional repository-relative paths from the command line."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    return parser.parse_args()


def main() -> int:
    """Check selected paths, print actionable diagnostics, and return status."""

    arguments = parse_arguments()
    paths = arguments.paths or first_party_sources()
    errors = [error for path in paths for error in check_path(path)]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        print(f"documentation check failed with {len(errors)} issue(s)", file=sys.stderr)
        return 1
    print(f"documentation check passed for {len(paths)} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
