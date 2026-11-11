# cl-work-queue

`cl-work-queue` runs keyed background jobs in independently limited lanes. A
second submission for an active key joins the existing job instead of launching
duplicate work, and every waiter receives the same value or condition.

## Why use it?

A single global worker pool lets one slow dependency consume every worker. A
thread per job avoids that coupling but can grow without bound. Keyed lanes give
you a middle ground:

- each lane has its own concurrency limit;
- a stalled lane does not prevent unrelated lanes from progressing;
- duplicate work is coalesced by key;
- completion callbacks run outside queue locks;
- one failing callback does not kill a worker;
- stopping refuses new work and fails jobs that have not started; and
- callers can wait for already-running workers during orderly shutdown.

The library also provides per-key exponential retry backoff with a configurable
initial delay and maximum.

## How is this different from sento, lparallel, or a thread pool?

Those are general-purpose concurrency tools. `cl-work-queue` is a narrow
primitive for one pattern: keyed background jobs with per-key concurrency
isolation and coalescing.

- **[sento](https://mdbergmann.github.io/cl-gserver/) is an actor framework.**
  You model work as actors that exchange messages, and concurrency comes from
  dispatchers. The default dispatcher is a *shared* worker pool, so isolating one
  workload from another means setting up separate or pinned dispatchers and
  routing to them yourself. `cl-work-queue` is not an actor system: you submit a
  thunk under a key, and per-key lanes with independent limits are the core
  model, created and sized on demand. A slow lane cannot starve unrelated lanes
  by construction.
- **lparallel or a bare `bordeaux-threads` pool** give you a shared pool of
  workers. They do not isolate by key and do not coalesce duplicate work.
  `cl-work-queue` adds both.
- **Request coalescing is built in.** A second submission for a key that is
  already running joins the existing job, and every waiter gets the same value or
  condition. This is the single-flight pattern — N concurrent callers, one
  execution. Actor and pool libraries run N submissions N times.
- **It is small and has one dependency.** About 140 lines on
  `bordeaux-threads`, with no actors, mailboxes, state machines, or event
  streams to adopt.

Reach for sento when you want actors, supervision, state machines, or an event
stream. Reach for `cl-work-queue` when you specifically need keyed,
lane-isolated, coalesced background work with a deterministic retry backoff, and
nothing more.

## Installation

Load the ASDF system:

```lisp
(asdf:load-system "cl-work-queue")
```

Dependencies are locked in `ocicl.csv`.

## Submit work

```lisp
(defparameter *queue*
  (cl-work-queue:make-work-queue
   :name "fetch"
   :lane-limit (lambda (host)
                 (if (string= host "slow.example") 1 4))))

(cl-work-queue:work-queue-submit
 *queue* "artifact-42" "fast.example"
 (lambda () (fetch-artifact "artifact-42"))
 :on-done (lambda (value condition)
            (if condition
                (format *error-output* "fetch failed: ~A~%" condition)
                (cache-artifact value))))
```

`work-queue-submit` returns true when it creates a job and `nil` when it joins
an existing key. `on-done` runs on a worker thread and receives `(value nil)` on
success or `(nil condition)` on failure.

Lane limits are evaluated when a lane first appears. A lane is removed after its
last worker exits, so a later submission can pick up a changed limit.

## Shutdown

```lisp
(cl-work-queue:work-queue-stop *queue*)
(unless (cl-work-queue:work-queue-wait *queue* :timeout 10)
  (warn "workers are still running"))
```

Running Common Lisp calls cannot be safely killed. `work-queue-stop` therefore
abandons only pending jobs; running thunks finish normally. Pending callbacks
receive a `work-queue-stopped` condition.

## Retry backoff

```lisp
(defparameter *backoff*
  (cl-work-queue:make-retry-backoff :initial 1 :maximum 60))

(when (cl-work-queue:retry-backoff-ready-p *backoff* key now)
  (if (try-operation key)
      (cl-work-queue:retry-backoff-clear *backoff* key)
      (cl-work-queue:retry-backoff-failed *backoff* key now)))
```

The caller supplies the clock value, which makes retry policy deterministic in
tests and usable with seconds, milliseconds, or another monotonic unit.

## Run the tests and example

```sh
sbcl --noinform --non-interactive \
  --eval '(require "asdf")' \
  --eval '(asdf:load-asd (truename "cl-work-queue.asd"))' \
  --eval '(asdf:test-system "cl-work-queue")'

sbcl --noinform --script examples/basic.lisp
```

## Author

Anthony Green <green@moxielogic.com>

## License

MIT. See [LICENSE](LICENSE).
