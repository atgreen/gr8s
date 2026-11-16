# Contributing to gr8s

Bug reports, questions, and pull requests are welcome through
[GitHub Issues](https://github.com/atgreen/gr8s/issues). gr8s is an
experimental, solo-maintained project, so responses are best-effort.

## Finding your way around

- The [source map and developer walkthrough](docs/development.md) explains
  how the code is organized.
- The [documentation style guide](docs/documentation-style.md) explains how
  the source is annotated; match it in changes.
- [Building, running & testing](docs/building-and-testing.md) covers the
  toolchain, `make test`, and the test matrix.

## Testing

`make test` runs the unit and HTTP suites and needs no privileges. Tests
that load eBPF programs or run real containers need root and a real
kernel — run those **only in a disposable VM** (see AGENTS.md, "Testing
eBPF and the native runtime as root"). Never on a machine you care about.

## Pull requests

- Keep changes focused; match the surrounding code's style and comment
  density.
- Add or extend tests for behavior changes.
- Note user-visible changes under **Unreleased** in
  [CHANGELOG.md](CHANGELOG.md).

## Security

Do not open public issues for exploitable bugs — see
[SECURITY.md](SECURITY.md) for private reporting.

## AI agents

AI coding agents working in this repository should start with
[AGENTS.md](AGENTS.md) and the project instructions it references.
