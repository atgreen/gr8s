%% SPDX-License-Identifier: MIT
%%
%% Findings that need more than one resource. Each fact carries the
%% observation that established it as its last argument, and a finding lists
%% the observations behind its premises.

:- dynamic service_selector/2, selection_count/3, selected_any/2, selected_pod/3.
:- dynamic awaits_label/4.               % awaits_label(Service, Pods, Labels, Proof)
:- dynamic never_labelled/7.             % never_labelled(Service, Label, Application, Pod, ConfigMap, Proof, Configuration)
:- dynamic service_port/4, missing_named_port/4.
:- dynamic routing_requires_ready/2, no_ready_endpoints/2.
:- dynamic claim_awaits_binding/2, claim_binding_mode/3, consumes_claim/3, pod_node_name/3.
:- dynamic hpa_utilization/3, hpa_selects/4, missing_request/4.
:- dynamic rollout_deficit/2, active_replicaset/3, replica_creation_failed/2.
:- dynamic quota_rejection/3, quota_present/2.
:- dynamic current_zero_disruptions/2, budget_selects/3, healthy_pod/2.
:- dynamic control_plane/1.              % control_plane(Proof): the kubernetes Service has several members
:- dynamic pod_on_node/3, node_absent/2. % pod_on_node(Pod, Node, Proof), node_absent(Node, Proof)
:- dynamic member_says/3.                % member_says(Member, ResourceVersion, Proof), of Namespace default; the version a number when it is one

%% related(?Code, ?Details, ?Proof)
related("service-selector-empty", [Service], [Root, Pods]) :-
    service_selector(Service, Root),
    selection_count(Service, 0, Pods).
related("service-waits-for-label", [Service, Near, Labels], [Root, Proof]) :-
    service_selector(Service, Root),
    awaits_label(Service, Near, Labels, Proof).
related("service-label-never-set", [Service, Label, Application, Pod, ConfigMap], [Root, Proof, Configuration]) :-
    service_selector(Service, Root),
    never_labelled(Service, Label, Application, Pod, ConfigMap, Proof, Configuration).
related("service-named-port-missing", [Service, Port, Protocol, Pod], [Root, Pods]) :-
    service_port(Service, Port, Protocol, Root),
    selected_pod(Service, Pod, Pods),
    missing_named_port(Pod, Port, Protocol, Pods).
related("service-no-ready-backends", [Service], [Root, Pods, Slices]) :-
    routing_requires_ready(Service, Root),
    selected_any(Service, Pods),
    no_ready_endpoints(Service, Slices).
related("pvc-consumer-bypasses-binding", [Claim, Pod, Node], [Root, Class, Pods]) :-
    claim_awaits_binding(Claim, Root),
    claim_binding_mode(Claim, "WaitForFirstConsumer", Class),
    consumes_claim(Pod, Claim, Pods),
    pod_node_name(Pod, Node, Pods).
related("hpa-missing-resource-request", [Hpa, Metric, Pod, Container, Metric], [Root, Workload, Pods]) :-
    hpa_utilization(Hpa, Metric, Root),
    hpa_selects(Hpa, Pod, Workload, Pods),
    missing_request(Pod, Container, Metric, Pods).
related("rollout-quota-rejection", [Deployment, ReplicaSet, Quota], [Root, Sets, Event, QuotaProof]) :-
    rollout_deficit(Deployment, Root),
    active_replicaset(Deployment, ReplicaSet, Sets),
    replica_creation_failed(ReplicaSet, Sets),
    quota_rejection(ReplicaSet, Quota, Event),
    quota_present(Quota, QuotaProof).
%% A Pod bound to a Node that no longer exists: a browser node's tab closed, or a
%% Node was deleted, and the Pod was never collected (podster-k988).
related(Code, [Pod, Node], [Root, Proof]) :-
    pod_on_node(Pod, Node, Root),
    node_absent(Node, Proof),
    ( string_concat("browser-", _, Node) -> Code = "pod-browser-node-gone" ; Code = "pod-node-gone" ).
related("pdb-blocks-healthy-eviction", [Budget, Pod], [Root, Pods]) :-
    current_zero_disruptions(Budget, Root),
    budget_selects(Budget, Pod, Pods),
    healthy_pod(Pod, Pods).

%% Every API server must give an object the same resourceVersion: a client
%% reads through one and writes through another. One finding names the member
%% that is furthest on and every member that differs from it.
related("members-disagree", [Ahead, Version, Others], [Root, Proof|Proofs]) :-
    control_plane(Root),
    findall(view(V, M, P), member_says(M, V, P), Views),
    msort(Views, Sorted),
    last(Sorted, view(Version, Ahead, Proof)),
    findall(Text-P,
            ( member(view(V, M, P), Sorted), V \== Version, differs(M, V, Text) ),
            Differing),
    Differing \== [],
    findall(Text, member(Text-_, Differing), Others),
    findall(P, member(_-P, Differing), Proofs).

differs(Member, Version, Text) :-
    shown(Version, Shown),
    string_concat(Member, " gives ", Start),
    string_concat(Start, Shown, Text).

shown(Version, Shown) :- number(Version), !, number_string(Version, Shown).
shown(Version, Version).

%% relation(?Code, ?Severity, ?Summary, ?Step): Summary takes the details.
relation("members-disagree", "warning",
         "Control-plane members do not agree: ~A gives Namespace default resourceVersion ~A, and ~{~A~^, ~}. A client that reads through one member and writes through another is refused as a conflict, and a program that watches through a member that is behind is told that its resourceVersion is newer than storage.",
         "This is a fault in the control plane, not in a workload, so fix it before anything listed under it. See which member leads and whether each is in contact, and bring every member to the same gr8s release. A member that still differs after that is removed and joined again.").
relation("service-selector-empty", "warning",
         "Service ~A selects no Pods in the observed namespace.",
         "Compare the Service selector with the intended workload labels.").
relation("service-waits-for-label", "warning",
         "Service ~A selects no Pods: ~A would match its selector but for the label ~A, which is not set.",
         "Find what sets that label. Some applications label a Pod only once it reaches a certain state, so fix the Pod's own problems first.").
relation("service-label-never-set", "warning",
         "Service ~A selects no Pods: it selects the label ~A, which ~A sets on its own Pods only when its configuration has a service_registration block. Pod ~A is configured by ConfigMap ~A, which has none.",
         "Add a service_registration \"kubernetes\" {} block to the server configuration, or remove the Service if nothing needs it.").
relation("service-named-port-missing", "warning",
         "Service ~A targets named port ~A/~A, which selected Pod ~A does not declare.",
         "Align the named targetPort with a declared container port and protocol.").
relation("service-no-ready-backends", "warning",
         "Service ~A selects Pods, but no ready endpoints were observed across all associated EndpointSlices.",
         "Inspect selected Pod readiness and EndpointSlice reconciliation; this can be transient.").
relation("pvc-consumer-bypasses-binding", "warning",
         "Pending claim ~A uses WaitForFirstConsumer, while consuming Pod ~A already has nodeName ~A.",
         "Check whether explicit nodeName bypassed scheduler-assisted binding; use node selection constraints instead.").
relation("hpa-missing-resource-request", "warning",
         "HPA ~A uses ~A utilization; selected Pod ~A container ~A has no ~A request.",
         "Set the resource request required for this utilization calculation; other metrics may still scale the workload.").
relation("rollout-quota-rejection", "warning",
         "Deployment ~A has a replica deficit; active ReplicaSet ~A reports FailedCreate and a recent Event reports quota ~A exceeded.",
         "Inspect the named quota and current usage before increasing replicas or adjusting quota.").
relation("pod-node-gone", "warning",
         "Pod ~A is bound to node ~A, which no longer exists, so nothing runs it and nothing reports on it.",
         "Delete the Pod; its controller makes a replacement that the scheduler places elsewhere. gr8s deletes such Pods itself once the Node has been gone 40 s, so one that stays means an older gr8s or a failed deletion.").
relation("pod-browser-node-gone", "warning",
         "Pod ~A is bound to browser node ~A, whose tab has closed, so nothing runs it and nothing reports on it.",
         "Delete the Pod; its controller makes a replacement for another node, or another browser tab. gr8s deletes such Pods itself once the node has been gone 40 s, so one that stays means an older gr8s or a failed deletion.").
relation("pdb-blocks-healthy-eviction", "advisory",
         "PDB ~A currently permits zero disruptions and selects healthy Pod ~A; voluntary eviction would be blocked by this budget.",
         "Restore redundancy or review the disruption policy before draining; do not bypass the budget blindly.").

%% relation_command(?Code, ?Command): what to run for the step.
relation_command("members-disagree", "gr8s member list").
