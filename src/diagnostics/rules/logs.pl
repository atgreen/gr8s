%% SPDX-License-Identifier: MIT
%%
%% What the last lines of a run that crashed say. A program usually states
%% why it is giving up; these rules recognise the common statements. Some need
%% a fact only the cluster can supply, and ask for it.

:- dynamic crashed_container/1.
:- dynamic wrote/2.                      % wrote(Container, Line)
:- dynamic kind_unserved/1.              % the API did not list this kind when asked
:- dynamic api_address/1.                % the address of the kubernetes Service

%% asks(?Question): a fact these rules need before they can conclude.
asks(serves(Kind)) :- watches(_, Kind).
asks(api_address) :- wrote(_, Line), mentions(Line, "connection refused").

%% log_finding(?Code, ?Container, ?Details): at most one of each per container.
log_finding(Code, Container, Details) :-
    crashed_container(Container),
    log_explanation(Code, _, _),
    once(evidence(Code, Container, Details)).

evidence("watches-unserved-kind", Container, [Kind]) :-
    watches(Container, Kind),
    kind_unserved(Kind).
evidence("cannot-reach-api", Container, [Address]) :-
    wrote(Container, Line),
    mentions(Line, "connection refused"),
    about_api(Line),
    dialled(Line, Address).
evidence("connection-refused", Container, [Address]) :-
    wrote(Container, Line),
    mentions(Line, "connection refused"),
    \+ about_api(Line),
    dialled(Line, Address).
evidence("api-answered-behind", Container, []) :-
    wrote(Container, Line),
    behind(Line).
evidence("name-not-resolved", Container, [Host]) :-
    wrote(Container, Line),
    mentions(Line, "no such host"),
    after(Line, "lookup ", Rest),
    split_string(Rest, " ", ":", [Host|_]).
evidence("port-in-use", Container, []) :-
    wrote(Container, Line),
    mentions(Line, "address already in use").
evidence("disk-full", Container, []) :-
    wrote(Container, Line),
    mentions(Line, "no space left on device").
evidence("wrong-architecture", Container, []) :-
    wrote(Container, Line),
    mentions(Line, "exec format error").

%% watches(?Container, ?Kind): the program reads objects of Kind and said it could not.
watches(Container, Kind) :-
    wrote(Container, Line),
    names_kind(Line, Kind).

%% client-go: failed to list *v1alpha1.AlertmanagerConfig: the server could not find the requested resource
%% A list can fail for other reasons, so the line must say the kind was not found.
names_kind(Line, Kind) :-
    after(Line, "failed to list *", Rest),
    not_found(Rest),
    split_string(Rest, ":", "", [Type|_]),
    split_string(Type, ".", "", Parts),
    last(Parts, Kind),
    real_kind(Kind).
%% controller-runtime and others: failed to sync cache for AlertmanagerConfig informer
names_kind(Line, Kind) :-
    after(Line, "failed to sync cache for ", Rest),
    split_string(Rest, " ", "\"", [Kind, Next|_]),
    string_concat("informer", _, Next),
    real_kind(Kind).

%% An API server refuses a read that asks for a state newer than the one it
%% holds. The client learned of that state from another server.
%% gr8s: Requested resourceVersion is newer than storage
%% kube-apiserver: Too large resource version: 85041, current: 77942
behind(Line) :- mentions(Line, "resourceVersion is newer than storage"), !.
behind(Line) :- mentions(Line, "Too large resource version"), !.

not_found(Text) :- mentions(Text, "could not find the requested resource"), !.
not_found(Text) :- mentions(Text, "route not found"), !.
not_found(Text) :- mentions(Text, "no matches for kind"), !.

%% Types a client uses to read any kind are not kinds the API serves.
real_kind(Kind) :- \+ memberchk(Kind, ["PartialObjectMetadata", "Unstructured"]).

about_api(Line) :- mentions(Line, "apiserver"), !.
about_api(Line) :- mentions(Line, "kubernetes.default"), !.
about_api(Line) :- api_address(Address), mentions(Line, Address), !.

%% Go: dial tcp 10.96.0.1:443: connect: connection refused
dialled(Line, Address) :-
    after(Line, "dial tcp ", Rest),
    split_string(Rest, " ", ":", [Address|_]),
    !.
dialled(_, "an address it did not name").

mentions(Line, Text) :- once(sub_string(Line, _, _, _, Text)).

%% after(+Line, +Marker, -Rest): what follows the first Marker in Line.
after(Line, Marker, Rest) :-
    once(sub_string(Line, _, _, Length, Marker)),
    sub_string(Line, _, Length, 0, Rest).

%% log_explanation(?Code, ?Summary, ?Step): Summary takes the Pod's name, the
%% container and the details.
log_explanation("watches-unserved-kind",
                "Pod ~A: container ~S gives up because it watches ~A objects and the API does not serve that kind.",
                "Install the CustomResourceDefinition for that kind, which usually ships with the program's chart, or turn off the feature that needs it.").
log_explanation("cannot-reach-api",
                "Pod ~A: container ~S exits because it cannot reach the Kubernetes API at ~A: the connection is refused.",
                "Check that the control plane is up and that the kubernetes Service in namespace default has ready endpoints. A program that starts while every API server is restarting fails this way.").
log_explanation("api-answered-behind",
                "Pod ~A: container ~S gives up because an API server answered it from a state older than one it had already been given.",
                "This is a fault in the control plane, not in the program: its API servers do not hold the same state. Run `gr8s member list` to see which member leads and whether each is in contact, then run the doctor again to see whether the members still disagree.").
log_explanation("connection-refused",
                "Pod ~A: container ~S exits because a connection it needs, to ~A, is refused.",
                "Check that what listens at that address is running and ready, and that the address is the right one.").
log_explanation("name-not-resolved",
                "Pod ~A: container ~S exits because it cannot resolve the name ~A.",
                "Check the name, that a Service of that name exists, and that cluster DNS is running.").
log_explanation("port-in-use",
                "Pod ~A: container ~S exits because the address it listens on is already in use.",
                "Look for another container in the Pod, or another Pod on the host network, that listens on the same port.").
log_explanation("disk-full",
                "Pod ~A: container ~S exits because a filesystem it writes to is full.",
                "Find which volume is full and free or enlarge it.").
log_explanation("wrong-architecture",
                "Pod ~A: container ~S cannot start because its image was built for a different processor architecture.",
                "Use an image built for the node's architecture, or schedule the Pod on a node that matches the image.").
