%% SPDX-License-Identifier: MIT
%%
%% How findings explain one another.

%% symptom(?Rule): the rule says something beneath a resource is unhealthy,
%% without saying what. Another warning on the resource, or on one it depends
%% on, explains it.
symptom("pod-Ready-False").
symptom("pod-ContainersReady-False").
symptom("pod-Ready-Unknown").
symptom("pod-Initialized-False").
symptom("deployment-Available-False").
symptom("deployment-Progressing-False").
symptom("service-no-ready-backends").
symptom("service-waits-for-label").
symptom("endpointslice-all-unready").
symptom("endpointslice-empty").
symptom(Rule) :- string_concat(_, "-deficit", Rule).

%% refines(?Why, ?What): on one resource, a finding of rule Why says why and
%% a finding of rule What only says what, so What is listed beneath Why.
refines(Why, What) :- restart_cause(Why), restart_effect(What).
%% What a program wrote before it died says more than that it died.
refines(Why, What) :-
    ( log_explanation(Why, _, _) ; access_explanation(Why, _, _) ),
    ( What = "restarts-crash" ; restart_effect(What) ).
refines("restarts-liveness-kill", "restarts-crash").
refines("pod-unschedulable", "pod-PodScheduled-False").
refines("pod-unschedulable", "event-FailedScheduling").
refines("openbao-uninitialized", "readiness-probe-failing").
refines("openbao-sealed", "readiness-probe-failing").

restart_cause("restarts-crash").
restart_cause("restarts-oom").
restart_cause("restarts-liveness-kill").

restart_effect("container-restarts-five").
restart_effect("waiting-CrashLoopBackOff").
restart_effect("event-BackOff").
restart_effect("event-Unhealthy").
restart_effect("readiness-probe-failing").
restart_effect("startup-probe-pending").

%% What explains an unhealthy resource. Resources are numbered for the question.
:- dynamic depends/2.                    % depends(Resource, On): a workload on its Pods, a Pod on its Node
:- dynamic hint/2.                       % hint(Resource, On): a looser link that suggests a connection
:- dynamic open/1.                       % open(Resource): a search may pass through it
:- dynamic cause_at/2.                   % cause_at(Resource, Cause): the resource first, to be found by it
:- dynamic symptom_target/1.

%% verdict(?Resource, ?Verdict): for a resource that shows a symptom, the
%% causes that explain it. A cause on the resource itself, or on one it
%% depends on, explains it for certain; one found only by following a hint is
%% possible. With neither, the verdict carries what lies beneath the resource,
%% so that the deepest unexplained symptom can stand for those above it.
verdict(Resource, Verdict) :-
    symptom_target(Resource),
    within(Resource, strict, Near),
    causes_among(Near, Certain),
    (   Certain \== []
    ->  Verdict = certain(Certain)
    ;   within(Resource, loose, Far),
        causes_among(Far, Possible),
        (   Possible \== []
        ->  Verdict = possible(Possible)
        ;   Verdict = unexplained(Near)
        )
    ).

causes_among(Resources, Causes) :-
    findall(Cause, (member(Resource, Resources), cause_at(Resource, Cause)), Causes).

%% within(+Start, +Links, -Resources): Start and everything reached from it.
%% The search goes on from a resource only if it is Start or is open, so a
%% healthy resource on the way ends that path.
within(Start, Links, Resources) :-
    spread([Start], [Start], Start, Links, Resources).

spread([], Seen, _, _, Seen).
spread([Resource|Queue], Seen, Start, Links, Resources) :-
    findall(Next,
            ( passable(Resource, Start),
              link(Links, Resource, Next),
              \+ memberchk(Next, Seen) ),
            Found),
    sort(Found, New),
    append(Seen, New, Seen1),
    append(Queue, New, Queue1),
    spread(Queue1, Seen1, Start, Links, Resources).

passable(Start, Start) :- !.
passable(Resource, _) :- open(Resource).

link(_, Resource, Next) :- depends(Resource, Next).
link(loose, Resource, Next) :- hint(Resource, Next).

%% Causes that are themselves caused. leads_to(?Why, ?What): a finding of rule
%% Why on a resource brings about a finding of rule What on the same resource
%% or on one that depends on it. This is knowledge of how one fault produces
%% another, so only pairs that are reliably so belong here.
leads_to(Why, What) :- node_down(Why), on_a_node_that_is_down(What).
leads_to("node-NetworkUnavailable-True", What) :-
    memberchk(What, ["event-NetworkNotReady", "event-FailedCreatePodSandBox", "readiness-probe-failing"]).
leads_to(Why, What) :- node_pressure(Why), memberchk(What, ["pod-Evicted", "terminated-Evicted"]).
leads_to(Why, What) :-
    memberchk(Why, ["missing-resource", "missing-key"]),
    memberchk(What, ["waiting-CreateContainerConfigError", "event-Failed", "event-FailedMount"]).
leads_to(Why, What) :-
    memberchk(Why, ["pvc-Pending", "pvc-Lost"]),
    memberchk(What, ["pod-PodScheduled-False", "event-FailedScheduling", "event-FailedMount", "pod-unschedulable"]).
leads_to("pv-Failed", What) :- memberchk(What, ["pvc-Pending", "pvc-Lost"]).

node_down("node-Ready-False").
node_down("node-Ready-Unknown").

on_a_node_that_is_down(What) :-
    memberchk(What, ["readiness-probe-failing", "startup-probe-pending", "pod-NodeLost",
                     "event-NetworkNotReady", "event-FailedCreatePodSandBox", "event-Unhealthy"]).

node_pressure("node-DiskPressure-True").
node_pressure("node-MemoryPressure-True").
node_pressure("node-PIDPressure-True").

:- dynamic rule_of/2.                    % rule_of(Cause, Rule)

%% consequence(?Cause): a cause that another cause, on its resource or beneath
%% it, leads to. It is then listed under that one instead of beside it.
consequence(Cause) :-
    cause_at(Resource, Cause),
    rule_of(Cause, Rule),
    once(leads_to(_, Rule)),
    within(Resource, strict, Near),
    member(Other, Near),
    cause_at(Other, Deeper),
    Deeper \== Cause,
    rule_of(Deeper, Why),
    leads_to(Why, Rule).
