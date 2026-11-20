%% SPDX-License-Identifier: MIT
%%
%% What stops working when a resource goes away: a node drained or lost, a
%% Secret or ConfigMap deleted, a workload removed. The same links the
%% diagnosis follows downwards are followed upwards here.

:- dynamic removed/1.                    % the resource asked about
:- dynamic pod/1, ready/1.
:- dynamic runs_on/2.                    % runs_on(Pod, Node)
:- dynamic needs/2.                      % needs(Pod, Resource): a Secret, ConfigMap or claim it requires
:- dynamic workload/1.
:- dynamic has_pod/2.                    % has_pod(Workload, Pod): the top owner of each Pod
:- dynamic service/1.
:- dynamic routes_to/2.                  % routes_to(Service, Pod)
:- dynamic guards/2.                     % guards(Budget, Pod)
:- dynamic permits/2.                    % permits(Budget, Disruptions)

%% gone(?Resource): it does not survive the removal.
gone(Resource) :- removed(Resource).
gone(Pod) :- runs_on(Pod, Node), removed(Node).
gone(Pod) :- has_pod(Workload, Pod), removed(Workload).

%% stranded(?Pod, ?On): it keeps running, but could not be started again.
stranded(Pod, On) :- needs(Pod, On), removed(On), \+ gone(Pod).

%% effect(?Resource, ?Effect)
effect(Workload, Effect) :-
    workload(Workload),
    \+ removed(Workload),
    findall(Pod, ( has_pod(Workload, Pod), ready(Pod) ), Ready),
    findall(Pod, ( member(Pod, Ready), gone(Pod) ), Lost),
    length(Ready, Have), length(Lost, Lose),
    Lose > 0,
    ( Lose =:= Have -> Effect = stops(Have) ; Effect = shrinks(Lose, Have) ).
effect(Service, silent(Have)) :-
    service(Service),
    \+ removed(Service),
    findall(Pod, ( routes_to(Service, Pod), ready(Pod) ), Ready),
    Ready \== [],
    \+ ( member(Pod, Ready), \+ gone(Pod) ),
    length(Ready, Have).
effect(Workload, cannot_restart(Count, On)) :-
    workload(Workload),
    removed(On),
    findall(Pod, ( has_pod(Workload, Pod), stranded(Pod, On) ), Stranded),
    Stranded \== [],
    length(Stranded, Count).
effect(Pod, cannot_restart(1, On)) :-
    stranded(Pod, On),
    \+ has_pod(_, Pod).
effect(Pod, alone) :-
    pod(Pod), gone(Pod), \+ removed(Pod),
    \+ has_pod(_, Pod).
effect(Pod, refused(Budget)) :-
    runs_on(Pod, Node), removed(Node),
    guards(Budget, Pod),
    permits(Budget, 0).

%% effect_text(+Effect, ?Group, ?Text, ?Arguments)
effect_text(stops(1), stops, "its only ready Pod goes", []) :- !.
effect_text(stops(Count), stops, "all ~D of its ready Pods go", [Count]).
effect_text(silent(_), stops, "every Pod it sends traffic to goes", []).
effect_text(alone, stops, "nothing owns it, so nothing starts it again", []).
effect_text(shrinks(1, Have), shrinks, "1 of its ~D ready Pods goes", [Have]) :- !.
effect_text(shrinks(Lose, Have), shrinks, "~D of its ~D ready Pods go", [Lose, Have]).
effect_text(cannot_restart(1, _), cannot_restart, "its Pod keeps running, but cannot be started again without it", []) :- !.
effect_text(cannot_restart(Count, _), cannot_restart, "~D of its Pods keep running, but none can be started again without it", [Count]).
effect_text(refused(Budget), refused, "its eviction would be refused: ~A allows no disruption now", [Budget]).

%% group_heading(?Group, ?Heading), in the order they are reported.
group_heading(stops, "Stops, until its Pods run somewhere else:").
group_heading(shrinks, "Runs on fewer Pods:").
group_heading(cannot_restart, "Keeps running but could not restart:").
group_heading(refused, "A drain would stop at:").
