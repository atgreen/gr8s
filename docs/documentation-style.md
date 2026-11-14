<!--
SPDX-FileCopyrightText: 2026 Anthony Green
SPDX-License-Identifier: Apache-2.0
-->
# Source documentation style

This guide defines how gr8s documents its Common Lisp source. The codebase
already follows it closely. Humans and agents should use the same conventions.
When in doubt, read `src/network/host-firewall.lisp`. Its header and docstrings are the
reference.

The main rule is simple: **document what the reader cannot recover from the
code**. Explain the contract, invariant, reason, or tradeoff. Do not restate what
the code already says.

## File headers (`;;;;`)

Every `.lisp` file starts with the SPDX lines, then a prose block in `;;;;`
comments that answers *what this file is and why it exists*:

```lisp
;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; <One line: the file's job.>
;;;;
;;;; <A short paragraph: the concept it implements, the contract it upholds, the
;;;; key tradeoff or non-obvious decision, and -- when there is one -- the bead or
;;;; epic for traceability (e.g. podster-vwy).>
```

- Explain the *why*, not a table of contents of its functions (that rots).
- Name the design decision a maintainer would otherwise have to reverse-engineer
  (host-firewall.lisp explains *why kernel-route, not eBPF-redirect, for
  cross-node*, which is the detail you cannot read from the code).
- One authoritative reference URL is welcome when the file implements an external
  contract (see **References** below); more than one is usually noise.

## Docstrings

State the **contract, not the implementation**. The signature is already in the
code; the docstring is for what the caller can't see:

- what it returns / guarantees,
- its side effects,
- its failure modes (what it signals, or that it is fail-soft / a no-op when),
- any invariant the caller must respect (locks held, ordering, idempotency).

```lisp
(defun ensure-overlay-firewall (node-pod-cidr &key ...)
  "When an active firewalld is present, admit this node's overlay traffic through
   it (idempotent). A no-op otherwise ... Fail-soft. Returns T when rules were
   applied, NIL when no active firewalld."
  ...)
```

- Present-tense, declarative, prose. "Return the node record, or signal a 404."
- Do **not** paraphrase the body line by line, and do not just expand the name
  ("Takes X and returns Y" adds nothing).
- Scale effort to risk: a one-liner for a self-evident helper, a full contract for
  anything with edge cases, ordering constraints, or shared state.
- Common Lisp mechanics: the string goes *immediately after the lambda list* so
  `(documentation #'f 'function)` finds it. Put it on functions, macros, and any
  `defvar`/`defparameter`/`defstruct`/`defgeneric` whose purpose isn't obvious
  from its name.

## Comments (`;;` and `;`)

`;;` for a line/block above the code, `;` for a trailing note. Use them for the
non-obvious *why* — why this order, why this guard, what breaks without it:

```lisp
;; lpk is a variable (we setf its fields), so the key expr is not a literal make-
;; form -- lower-map-lookup can't see it is a struct pointer and would spill the
;; POINTER value as the key. Use map-lookup-ptr so R2 = &lpk (its contents).
```

Never echo the code (`(incf n) ; increment n`). A comment that restates the line
is worse than none because it's one more thing to keep true.

## ASCII diagrams for stable shapes

Draw one only when **the shape is the point and the shape is a contract**: a
byte/packet layout, a wire/protocol frame, a fixed topology, a state machine.
gr8s already does this for eBPF map value layouts — keep that. Do **not** diagram
call graphs or current control flow; those drift, and a drifted diagram is worse
than none because readers trust it. Keep diagrams small and in the file that owns
the mechanism.

## References (URLs)

Link the **authoritative source** when the code conforms to someone else's
contract and a reader would otherwise have to guess whose rules these are:
Kubernetes API semantics (kubernetes.io), the Raft paper for `raft*.lisp`, RFC
7348 for VXLAN, the eBPF helper docs for [Whistler](https://github.com/atgreen/Whistler) programs, nftables/firewalld
semantics for the host firewall. Two habits keep links useful:

- **Name the concept or section in prose** ("Raft §5.4, log matching"; "RFC 7348
  §4") so the reference survives link rot.
- Prefer canonical, stable URLs over deep anchors; one pointer per contract, not a
  bibliography. Don't link things the code already explains.

## Tone

- Precise, declarative, present tense. Reads like prose, not notes.
- Explain the *why* and the tradeoff; name the decision.
- **Honest about limits.** Distinguish implemented behavior, measured validation,
  and certification. State the tested build and topology for a conformance result;
  state remaining gaps plainly. Mark historical limitations as historical.
- Write for the next engineer who has to *change* this code, not for a tutorial
  reader.
- No bare `TODO`s (file a bead and reference it), no "updated by…" noise, no
  apology.

## Anti-patterns (don't)

- Restate the signature or echo the code.
- Document trivial private helpers at length.
- Diagram or link something that will rot faster than it helps.
- Leave a stale comment next to changed code — update or delete it.
