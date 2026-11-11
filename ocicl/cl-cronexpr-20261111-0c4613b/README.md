# cl-cronexpr

`cl-cronexpr` parses five-field cron expressions and finds the next or most recent
matching instant. It also reads named time zones from TZif files, including the
recurring POSIX rules used when a compact zone file stops listing transitions.

## Why use it?

Scheduling becomes surprisingly subtle once wall-clock time enters the picture.
Daylight-saving transitions can repeat or skip local times, the day-of-month and
day-of-week fields have unusual OR semantics, and a process that was offline
often needs the most recent missed occurrence rather than every historical one.

`cl-cronexpr` keeps those rules in a small, testable library. It supports:

- five-field expressions with lists, ranges, steps, month names, and weekday
  names;
- `@yearly`, `@monthly`, `@weekly`, `@daily`, `@hourly`, and `@every`;
- next-time and most-recent-time queries;
- named TZif v1/v2/v3 zones and recurring POSIX transition rules;
- RFC 3339 formatting with the correct offset at a given instant; and
- a dedicated `invalid-cron-schedule` condition for input errors.

The scheduler works in Common Lisp universal time. It advances through absolute
time and re-evaluates local fields at every candidate, so offset changes do not
silently skip matches.

## Installation

Load the ASDF system:

```lisp
(asdf:load-system "cl-cronexpr")
```

Dependencies are locked in `ocicl.csv`.

## Example

```lisp
(let* ((schedule (cl-cronexpr:parse-cron "30 9 * * mon-fri"))
       (zone (cl-cronexpr:load-cron-zone "America/Toronto"))
       (next (cl-cronexpr:next-cron-time schedule (get-universal-time) zone)))
  (cl-cronexpr:format-cron-time next zone))
```

`next-cron-time` returns `nil` if no matching calendar time exists in its
five-year search window. `most-recent-cron-time` searches `(earliest, now]` and
is useful when a scheduler resumes after downtime.

Pass no zone (or load `UTC`) for UTC. Named-zone loading defaults to
`/usr/share/zoneinfo/`; the `cl-cronexpr::*zoneinfo-directory*` special variable can
be rebound when zone files live elsewhere.

## Run the tests and example

```sh
sbcl --noinform --non-interactive \
  --eval '(require "asdf")' \
  --eval '(asdf:load-asd (truename "cl-cronexpr.asd"))' \
  --eval '(asdf:test-system "cl-cronexpr")'

sbcl --noinform --script examples/basic.lisp
```

## Author

Anthony Green <green@moxielogic.com>

## License

MIT. See [LICENSE](LICENSE).
