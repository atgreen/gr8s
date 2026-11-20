%% SPDX-License-Identifier: MIT
%%
%% Why a Pod that waits for a node has none. The scheduler says only that no
%% node fits; these rules try each node and name the first thing that rules it
%% out. They cover what most often does: readiness, cordons, taints, node
%% selectors, required node affinity and room for what the Pod requests.

%% The nodes. Amounts are in thousandths, so that 100m of CPU is 100.
:- dynamic node/1, not_ready/1, cordoned/1.
:- dynamic taint/4.                      % taint(Node, Key, Value, Effect)
:- dynamic label/3.                      % label(Node, Key, Value)
:- dynamic allocatable/3.                % allocatable(Node, Resource, Amount)
:- dynamic used/3.                       % used(Node, Resource, Amount): requested by the Pods on it
:- dynamic usage_unknown/0.              % the Pods on the nodes could not be read

%% The Pod.
:- dynamic tolerates/4.                  % tolerates(Key, Operator, Value, Effect); "" matches any
:- dynamic selects/2.                    % selects(Key, Value): nodeSelector
:- dynamic asks_for/2.                   % asks_for(Resource, Amount)
:- dynamic term/1, expression/4.         % required node affinity: any term, all of its expressions

%% placement(?Verdict): nowhere(Rejections) when every node is ruled out, with
%% one [Node, Reason] for each. A node these rules do not rule out may still
%% be refused by the scheduler for a reason they do not model, so nothing is
%% concluded unless all are ruled out.
placement(nowhere(Rejections)) :-
    once(node(_)),
    \+ fits(_),
    findall([Node, Reason], ( node(Node), once(rejects(Node, Reason)) ), Rejections).

fits(Node) :- node(Node), \+ rejects(Node, _).

%% rejects(+Node, ?Reason), most telling reason first.
rejects(Node, not_ready) :- not_ready(Node).
rejects(Node, cordoned) :- cordoned(Node).
rejects(Node, taint(Key, Value, Effect)) :-
    taint(Node, Key, Value, Effect),
    repels(Effect),
    \+ tolerated(Key, Value, Effect).
rejects(Node, selector(Key, Value)) :-
    selects(Key, Value),
    \+ label(Node, Key, Value).
rejects(Node, affinity) :-
    once(term(_)),
    \+ ( term(Term), satisfied(Term, Node) ).
rejects(Node, lacks(Resource)) :-
    asks_for(Resource, Wanted), Wanted > 0,
    \+ allocatable(Node, Resource, _).
rejects(Node, short(Resource, Wanted, Free)) :-
    \+ usage_unknown,
    asks_for(Resource, Wanted),
    allocatable(Node, Resource, Total),
    in_use(Node, Resource, Used),
    Free is Total - Used,
    Wanted > Free.

in_use(Node, Resource, Used) :- used(Node, Resource, Used), !.
in_use(_, _, 0).

%% PreferNoSchedule is a preference, not a refusal.
repels("NoSchedule").
repels("NoExecute").

tolerated(Key, Value, Effect) :-
    tolerates(Tolerated, Operator, Wanted, Against),
    ( Against == "" ; Against == Effect ),
    matches_taint(Operator, Tolerated, Wanted, Key, Value),
    !.

matches_taint("Exists", "", _, _, _).
matches_taint("Exists", Key, _, Key, _).
matches_taint("Equal", Key, Value, Key, Value).

satisfied(Term, Node) :-
    \+ ( expression(Term, Key, Operator, Values), \+ holds(Operator, Key, Values, Node) ).

holds("In", Key, Values, Node) :- label(Node, Key, Value), memberchk(Value, Values).
holds("NotIn", Key, Values, Node) :- \+ ( label(Node, Key, Value), memberchk(Value, Values) ).
holds("Exists", Key, _, Node) :- label(Node, Key, _).
holds("DoesNotExist", Key, _, Node) :- \+ label(Node, Key, _).

%% reason_text(+Reason, ?Text, ?Arguments): Text is a format string. An
%% amount among the arguments is written as amount(Resource, Thousandths).
reason_text(not_ready, "is not ready", []).
reason_text(cordoned, "is cordoned", []).
reason_text(taint(Key, "", Effect), "has the taint ~A:~A, which the Pod does not tolerate", [Key, Effect]) :- !.
reason_text(taint(Key, Value, Effect), "has the taint ~A=~A:~A, which the Pod does not tolerate", [Key, Value, Effect]).
reason_text(selector(Key, Value), "does not have the label ~A=~A that the Pod's nodeSelector asks for", [Key, Value]).
reason_text(affinity, "matches none of the Pod's required node affinity terms", []).
reason_text(lacks(Resource), "offers no ~A, which the Pod requests", [Resource]).
reason_text(short(Resource, Wanted, Free), "has ~A of ~A free and the Pod requests ~A",
            [amount(Resource, Free), Resource, amount(Resource, Wanted)]).

placement_explanation("pod-unschedulable",
                      "Pod ~A cannot be placed: ~[none of the ~D nodes~;the only node~:;none of the ~D nodes~] will take it.",
                      "Clear what rules out at least one node, or change what the Pod asks for.").
