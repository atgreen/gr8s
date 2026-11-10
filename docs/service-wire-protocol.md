# Experimental Service identity envelope

The standalone codec in `src/network/service-wire.lisp` is a prerequisite for
`podster-p9c.14`. It is not installed by CNI or the node agent. The existing
crossed-Service probe still reproduces the bug in the unmodified NAT graph.

Two independent Service requests can have inverse translated transport tuples.
If both nodes emit before either request arrives, neither node's local history
can establish whether the incoming packet is a new request or a reply. Recording
incoming tuples alone cannot resolve this case. The proposed envelope carries
the frontend and endpoint incarnations through the packet path so that policy
and translation can distinguish the two directions explicitly.

The codec preserves the complete inner Ethernet/IP packet, including all IPv4
options. The routable outer source and destination copy the inner addresses.
Noncolliding inner source addresses and transport ports are unchanged. The
receiver retains the outer Ethernet addresses after decapsulation because its
host routing has selected those addresses for the destination link.

## Encoding

All scalar framing fields use network byte order. Epochs are opaque16-byte
strings copied from the existing NAT map ABI; no truncation or hashing is used.

| Offset in frame | Bytes | Field |
| --- | ---: | --- |
| 0 | 14 | Outer Ethernet |
| 14 | 20 | Outer IPv4, IHL5, DF, UDP, initial TTL64 |
| 34 | 8 | UDP, source49152, destination6081, UDP checksum zero |
| 42 | 8 | Geneve version0, option length13 words, critical bit, Ethernet payload, VNI0x677238 |
| 50 | 4 | Experimental option class0xfffe, critical type0x80, data length12 words |
| 54 | 4 | Magic `GR8S` |
| 58 | 1 | Version1 |
| 59 | 1 | Direction: request1, reply2 |
| 60 | 2 | Metadata length48 |
| 62 | 4 | Original frontend IPv4 address |
| 66 | 2 | Original frontend port |
| 68 | 1 | Inner transport protocol: TCP6 or UDP17 |
| 69 | 1 | Reserved, zero |
| 70 | 16 | Client endpoint incarnation |
| 86 | 16 | Backend endpoint incarnation |
| 102 | variable | Complete original Ethernet frame |

The additional overhead is102 bytes. Frames exceeding the outer IPv4 length
limit are rejected. The prototype accepts only unfragmented IPv4 TCP/UDP inner
packets and unfragmented outer IPv4. It checks framing lengths, protocol,
addresses, option identity, reserved fields and the outer IP checksum. A codec
fixture compares all48 metadata bytes against a read-only expected row. This
fixture is not an authorization mechanism for an attached network path.

The outer DSCP/ECN initially copies the inner value. When decapsulating an outer
CE mark, the codec marks an ECN-capable inner packet CE and updates its IP
checksum; outer CE with an inner Not-ECT packet drops. Inner DSCP is preserved.
The wrapper supplies Linux's UDP tunnel and inner Ethernet flags to
`bpf_skb_adjust_room`; the standalone packet tests do not prove real offload
behavior.

The experimental class range and critical-option semantics come from
[RFC8926](https://www.rfc-editor.org/rfc/rfc8926.html). Helper flags and packet
pointer invalidation are defined by the
[Linux BPF API](https://github.com/torvalds/linux/blob/v6.19/include/uapi/linux/bpf.h).

## Integration contract

An attached implementation must reject forged reserved envelopes originating
from Pods. Received metadata must agree with authoritative endpoint identities,
the receiving local incarnation, and the actual owned flow; structural validity
alone grants no permission. Both full epochs and the frontend must be checked
again when policy-approved state is committed. Keeping metadata in the packet
through policy avoids a stale short callback context authorizing replacement
state after an endpoint or flow changes.

Request delivery must create backend reply ownership only after ingress policy
allows it. Backend reply classification occurs before Service destination
translation, so a separately initiated Service request can retain its request
identity. Client reply restoration must require explicit reply metadata and
matching ownership. Reservation, capacity, expiry, restart and retained-map
handling apply to this additional state too.

Backend ownership must also account for application-visible direct tuples. An
incoming Service request can overlap an existing direct outbound connection on
the receiving Pod. Preserving its source unchanged in that case would make a
server reply indistinguishable from traffic on the direct connection. A backend
implementation therefore needs to reserve both its visible reply tuple and the
original wire tuple. On a collision it can expose the validated client's private
alias (and a reserved port if necessary) to the server, then restore the original
wire destination before emitting the typed reply. This additional translation
is a collision case; noncolliding requests keep their source. The envelope does
not itself implement this ownership or reverse mapping.

Native socket steering must preserve enough original destination identity to
participate in the same protocol. An ambiguous socket reverse row must never be
overwritten. CNI readiness must gate compatible receivers and retained writer
upgrades. MTU negotiation/ICMP, nested VXLAN/WireGuard forwarding, segmentation
and checksum offloads require real disposable-VM network tests before this
profile can be enabled. The codec results alone do not establish those behaviors.

The experimental graph uses a distinct wire-ready identity flag8. An alias-ready
flag4 alone does not identify a compatible receiver. Local typed stages require
enabled1, alias-ready4 and wire-ready8 together; complete-history2 remains a
separate source-selection property. This is an enforcement check in the graph,
not a claim that the node agent publishes or acknowledges these flags yet.

The graph has explicit packet-format boundaries. Generation, selection, NAT
commit, request wrapping, initial reply classification and maintenance accept
plain packets only and reject reserved envelopes before changing flow state.
The egress root also rejects Pod-originated envelopes. Reply classification can
wrap a backend response before egress policy; reply-commit validates that
envelope and sends it directly to delivery, bypassing ordinary NAT commit.
Ingress preparation, policy, restoration and request reception retain the
envelope until the authorized translation or reply reservation is complete.
These boundaries avoid unnecessary parsing and stack use in plain stages while
preserving the metadata across both policy checks.

## Receiver collection

The experimental graph includes `gr8s_wire_gc`, a maintenance program invoked
only through `BPF_PROG_TEST_RUN`. Its private52-byte control frame uses IPv4
protocol253, a direction byte at34 (visible reply0, incoming wire1), and a16-byte
tuple at36. Return values are unchanged0, reclaimed1, busy/helper failure2, and
invalid or unknown schema3. These control frames must never be sent on a network.

Receiver rows contain metadata48, original incoming tuple16, visible incoming
tuple16, last-seen time8, schema4 and active flag4. Collection takes the same
forward, reverse and wire-tuple reservations as packet writers. It preserves
foreign index/receiver entries and unknown row schemas. Fully published UDP
ownership expires after180 idle seconds; TCP uses7200 seconds. Unfinished or
orphaned receiver publication gets five seconds. An endpoint incarnation mismatch
allows immediate reclamation of its owned state.

The standalone userspace scanner visits at most128 keys per receiver/index map
per tick, resumes both cursors, defers busy keys and advances before reporting a
syscall or schema failure. It is not called by the node agent. Retained-writer
and profile compatibility must be verified before enabling it.

The current incoming index is keyed by the wire tuple alone. A receiver entry
can outlive its sender's collected flow, so a different Service reusing that
tuple is currently dropped. `probe-service-receiver-reuse.py` reproduces this
case; `podster-p9c.19` tracks qualifying the index by Service and full endpoint
incarnations before activation. The kernel collector tests do not establish
that the entire Service graph or this reuse case is correct.
