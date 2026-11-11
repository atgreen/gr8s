# cl-wireguard-overlay

`cl-wireguard-overlay` is the decision-making layer for a WireGuard overlay
network — the part that decides, not the part that configures WireGuard. It
answers two questions for a fleet of nodes:

1. **Topology — who should be a WireGuard peer of whom?** Given your node
   records, it plans the peering graph: a full mesh while the network is small,
   and bounded per-zone and per-region rings with deterministic gateways once it
   grows, so the peer count does not explode. It also answers neighbor and
   next-hop queries for routing across that graph.
2. **Path selection — when a peer is reachable several ways, which path is
   active now?** Given per-path observations (handshake age, recent successes
   and failures, trial latency, MTU probes), it picks a path with deliberate
   hysteresis: move off an unhealthy path immediately, but demand repeated
   evidence before switching merely to optimize. It also runs a bounded MTU
   search and applies MTU changes conservatively (shrink now, grow only after
   repeated confirmation).

It is a **pure policy library**. It computes decisions from the data you give it
and never touches the network itself: no key exchange, no sockets, no netlink,
no `wg` commands. You supply node records and path observations plus two
callbacks — `observe`, which returns a peer's current candidate paths, and
`apply`, which enacts a chosen one — so the same planner can drive a netlink
client (such as [`cl-rtnetlink`](https://github.com/atgreen/cl-rtnetlink)), a
privileged `wg` helper, a cloud API, or a simulator. Reconciliation is
idempotent: `apply` runs only when the selected path actually changes.

## When would you use it?

Reach for it when you are building the **control plane of a multi-node WireGuard
overlay** and want the topology and failover decisions to be deterministic and
unit-testable, kept out of the privileged code that actually brings tunnels up.
For example:

- a coordinator for a mesh VPN across regions and zones — the policy role a
  Tailscale or Nebula control plane plays — where you already have a way to
  apply WireGuard configuration and want a tested brain to decide the peering
  graph and route choices;
- multi-homed or mobile peers reachable several ways, needing stable,
  flap-resistant failover between a direct path and a relay;
- anywhere you are tempted to encode "which peer connects to which, and which
  path wins" in shell scripts, and would rather have it as a library you can
  test.

It is **not** a WireGuard implementation or configurator. It does no crypto,
opens no tunnel, and sends no netlink; it decides, and your code enforces. If
you only need to configure a single WireGuard peer, or you want the tunnel and
key exchange themselves, this is the layer above that, not that.

## What it expects

- **Node records** (`make-overlay-node`): a name, region, and zone per node;
  optionally `:transit-node-names` when only some nodes should forward traffic.
- **Path observations** (`make-wireguard-path-observation`): per-candidate
  telemetry — handshake age, consecutive successes and failures, trial latency,
  and MTU probe results — which you collect however you measure your network.
- **Two controller callbacks**: `observe (peer) -> candidate observations` and
  `apply (peer path reason)`.
- **An MTU probe** for `discover-wireguard-path-mtu`, and whatever cadence you
  reconcile on. The library reads neither the clock nor the network, which is
  what keeps its decisions reproducible in tests.

## Why use it?

A full mesh is simple and robust for a small network, but its peer count grows
quadratically.  Larger networks usually need a sparse topology, while mobile,
multi-homed, and firewalled peers may need several candidate paths with
different latency, MTU, and reliability.

This library keeps those policy decisions deterministic and testable:

- Small overlays use a full mesh; larger overlays use bounded zone and region
  rings with deterministic gateways.
- Weighted shortest-path routing prefers local links and stable transit nodes.
- Recovering nodes can remain reachable without becoming transit nodes.
- Path selection fails over immediately from an unhealthy path, but requires
  repeated evidence before making an optimization.
- MTU decreases take effect immediately; increases require repeated successful
  probes.
- A path named `relay` is treated as a last-resort candidate behind healthy
  direct paths.

The library does not execute commands or configure an interface.  That boundary
is deliberate: the same planner can drive a netlink client, a privileged helper,
an API, or a simulator.

## Installation

Load the system through ASDF:

```lisp
(asdf:load-system "cl-wireguard-overlay")
```

The dependency lock is recorded in `ocicl.csv`.

## Plan a topology

```lisp
(let* ((nodes (list
               (cl-wireguard-overlay:make-overlay-node
                :name "alpha" :region "east" :zone "east-a")
               (cl-wireguard-overlay:make-overlay-node
                :name "bravo" :region "east" :zone "east-b")
               (cl-wireguard-overlay:make-overlay-node
                :name "charlie" :region "west" :zone "west-a")))
       (plan (cl-wireguard-overlay:plan-wireguard-topology
              nodes :full-mesh-limit 2)))
  (cl-wireguard-overlay:wireguard-topology-neighbors plan "alpha")
  (cl-wireguard-overlay:wireguard-topology-next-hop
   plan "alpha" "charlie"))
```

Pass `:transit-node-names` when only a subset of nodes should forward traffic.
Other nodes remain destinations and attach to up to two nearby stable nodes.

## Observe and apply paths

An `overlay-controller` has two replaceable callbacks.  `observe` returns the
current candidates for a peer.  `apply` receives the selected observation only
when the choice changes.

```lisp
(let* ((direct
         (cl-wireguard-overlay:make-wireguard-path-observation
          :name "direct" :address "198.51.100.8" :port 51820
          :handshake-age-seconds 8 :consecutive-successes 4
          :trial-latency-milliseconds 12))
       (relay
         (cl-wireguard-overlay:make-wireguard-path-observation
          :name "relay" :address "203.0.113.20" :port 51820
          :handshake-age-seconds 5 :consecutive-successes 5
          :trial-latency-milliseconds 20))
       (controller
         (cl-wireguard-overlay:make-overlay-controller
          :observe (lambda (peer-id)
                     (declare (ignore peer-id))
                     (list direct relay))
          :apply (lambda (peer-id path reason)
                   (format t "Configure ~A through ~A (~A)~%"
                           peer-id
                           (cl-wireguard-overlay:wireguard-path-observation-name
                            path)
                           reason)))))
  (cl-wireguard-overlay:reconcile-overlay-peer controller "peer-7"))
```

The callback may translate the chosen address, port, and safe MTU into whatever
configuration mechanism the application owns.  Reconciliation is idempotent:
the apply callback is not called again while the selected observation is the
same object.

## MTU discovery

`discover-wireguard-path-mtu` performs a bounded binary search using a caller
provided probe.  Feed its result to `update-wireguard-path-mtu`; reductions are
immediate and increases require three confirmations by default.

## Run the tests and example

```sh
sbcl --noinform --non-interactive \
  --eval '(asdf:load-asd (truename "cl-wireguard-overlay.asd"))' \
  --eval '(asdf:test-system "cl-wireguard-overlay")'

sbcl --noinform --script examples/basic.lisp
```

## Author

Anthony Green <green@moxielogic.com>

## License

MIT. See [LICENSE](LICENSE).
