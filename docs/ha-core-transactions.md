# Core-resource transactions in HA

A member prepares a key-level core-resource delta under its local store lock,
then proposes it through Raft after releasing that lock. Other members may have
committed a change between those steps. Unrelated resource keys merge in log
order. A version 2 delta also carries the expected prior object for each changed
key, so concurrent creates, updates and deletes at the same key can be rejected
at committed apply.

Every replica checks all conditions before changing any resource, controller
state map, encryption policy, history or revision. Comparison includes UID and
object content, with case-sensitive JSON equality. It excludes the object's
`metadata.resourceVersion`. Every member gives an object the same version, but
members that ran an earlier release may still differ until a round has brought
them together, and a version must not decide whether a write applies meanwhile
(see [HA consistency](high-availability.md)). Controller-map changes have
per-key presence and value conditions too.

A rejected entry is a committed no-op, returning `(:core-conflict)`. This lets
Raft advance its applied boundary normally. The proposing writer maps that result
to Kubernetes HTTP 409, including when a follower forwards its proposal to the
leader. Retrying requires reading current state and preparing a fresh transaction.
The successful apply result is the small readable value `(:core-ok)`.

Expected Secret objects use the same authenticated encryption as replacement
objects. Adding preconditions does not put old Secret data in the WAL as
plaintext when encryption is enabled. A transaction authored under an outdated
encryption policy is rejected before decrypting its conditions or changing local
policy. Deltas contain only changed keys and their prior values, not a full
cluster checkpoint.

Version 1 entries remain readable for existing WAL replay. These checks require
all members to run the new apply implementation. They do not provide mixed-version
protocol negotiation. UID comparison prevents a stale delete from removing a
new object created at the same name. Content comparison alone does not detect an
object changing away and back to exactly the same content while retaining its
UID. A replicated per-object mutation token would be needed to enforce that
stronger history-sensitive condition independently of local resource versions.
