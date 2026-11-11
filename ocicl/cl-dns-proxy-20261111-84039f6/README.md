# cl-dns-proxy

`cl-dns-proxy` is a small caching DNS proxy for SBCL. It serves both UDP and
TCP, supports caller-provided authoritative answers, forwards everything else,
and contains upstream failures so the listener remains available.

## Why use it?

Embedding a resolver is useful when an application needs local names, split DNS,
or a controlled forwarding boundary without running a separate daemon. The
difficult parts are not just opening port 53: UDP and TCP must share a port,
transaction identifiers must survive caching, TTLs must age, negative answers
need bounded lifetimes, and a silent upstream must not kill the server loop.

This library provides:

- replaceable local-resolution and upstream-forwarding callbacks;
- bounded, thread-safe positive and negative response caching;
- transaction-ID replacement and TTL aging on cache hits;
- longest-suffix conditional forwarding rules;
- real UDP and DNS-over-TCP listeners on the same port;
- bounded retry across upstreams and SERVFAIL conversion;
- resolver configuration parsing;
- process-local Prometheus text metrics; and
- deterministic start/stop ownership with complete socket cleanup.

The core has no built-in zones or records. Policy belongs in the resolver
callback supplied by the embedding application.

## Installation

Load the ASDF system:

```lisp
(asdf:load-system "cl-dns-proxy")
```

Dependencies are locked in `ocicl.csv`.

## Local answers

A resolver receives one decoded `0conf` question and returns three values:
answers, whether it handled the question, and an optional DNS response code.

```lisp
(defun local-resolver (question)
  (if (and (= (0conf:question-qtype question) 0conf:+type-a+)
           (string-equal (0conf:question-name question) "app.internal"))
      (values
       (list (make-instance '0conf:a-record
                            :name "app.internal"
                            :address #(192 0 2 40)
                            :ttl 30))
       t 0)
      (values nil nil nil)))
```

When handled is false, the original wire packet is forwarded unchanged. A
handled response is authoritative and retains the query ID, question, and
recursion-desired bit.

## Run a proxy

```lisp
(defparameter *server*
  (cl-dns-proxy:start-dns-server
   :address "127.0.0.1"
   :port 0
   :upstreams '(("1.1.1.1" . 53) ("8.8.8.8" . 53))
   :resolver #'local-resolver
   :forward-rules '(("corp.example" ("192.0.2.53" . 53)))))

(cl-dns-proxy:dns-server-port *server*)
(cl-dns-proxy:stop-dns-server *server*)
```

Port zero selects an available port and retries bounded cross-protocol races
until both listeners own the same number. `stop-dns-server` joins both worker
threads before releasing their sockets.

`call-with-dns-server` provides unwind-protected lifecycle management when a
function-scoped server is more convenient.

## Cache and forwarding

The cache stores complete wire responses. Positive responses use the smallest
TTL across their records. Negative responses use authority-record TTLs. A hit
gets the current query ID and every record TTL is reduced by its age.

Conditional forwarding rules are `(zone . upstreams)` pairs. The longest zone
matching the question name wins; otherwise the default upstream list is used.

## Metrics

`dns-metrics-text` reports query and response counts, cache hits and misses,
forwarding outcomes, and forwarding duration. Pass a separate
`make-dns-metrics` instance to each server when metrics must be isolated.

## Run the tests and example

```sh
sbcl --noinform --non-interactive \
  --eval '(require "asdf")' \
  --eval '(asdf:load-asd (truename "cl-dns-proxy.asd"))' \
  --eval '(asdf:test-system "cl-dns-proxy")'

sbcl --noinform --script examples/basic.lisp
```

## Author

Anthony Green <green@moxielogic.com>

## License

MIT. See [LICENSE](LICENSE).
