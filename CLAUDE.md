# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:1105d646 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->


## Testing eBPF as root

BPF and native runtime tests run as root in disposable VMs. See "Testing eBPF and the native runtime as root" in AGENTS.md.

## Build & Test

_Add your build and test commands here_

```bash
# Example:
# npm install
# npm test
```

## Architecture Overview

_Add a brief overview of your project architecture_

## Conventions & Patterns

### JSON usage and garbage minimization

gr8s moves a lot of JSON (every API request, watch event, status heartbeat).
jzon is fast; the garbage comes from intermediate copies around it. Rules:

- **Parse octets, not decoded strings.** `jzon:parse` accepts UTF-8 octet
  vectors, streams, and pathnames directly. Never write
  `(jzon:parse (trivial-utf-8:utf-8-bytes-to-string bytes))` — pass the bytes.
  Read request bodies with `(hunchentoot:raw-post-data :force-binary t)` when
  the body is only parsed; keep `:force-text` only where the text itself is
  used (the CRD duplicate-field scan, YAML, string patches).
- **Emit to streams, not strings.** Prefer `(jzon:stringify x :stream s)`;
  when the sink is a binary stream, wrap it once in a UTF-8 flexi-stream (see
  the watch event writer in `src/apiserver/podtemplate-watch.lisp`). When you
  genuinely need an octet vector, use `gr8s.resources:stringify-to-utf-8-bytes`
  — it skips the intermediate string and returns a simple array (ironclad
  requires simple octet vectors).
- **Deep-copy structurally.** Copy parsed-JSON values with
  `gr8s.resources:copy-core-object`, never by stringify-then-parse.
- **Measure without materializing.** For size limits on serialized JSON, use
  `trivial-utf-8:utf-8-byte-length` on the string rather than encoding to bytes.
- **Walk models, don't re-parse your own output.** Internal consumers of a
  response should use the parsed model (see `api-groups-object` in
  `src/apiserver/http.lisp`), not `jzon:parse` of the serialized response.
- **Stream big documents.** For large or incremental JSON, use
  `jzon:with-parser`/`parse-next` and `jzon:with-writer`/`write-value`
  (`src/resources/core-checkpoint-reader.lisp` is the house pattern).
