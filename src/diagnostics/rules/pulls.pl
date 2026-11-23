%% SPDX-License-Identifier: MIT
%%
%% What a failed image pull says. The kubelet's own findings, a back-off and a
%% Failed event, only say that the pull failed; the error it reports names
%% why. These rules recognise the common errors, most specific first.

:- dynamic pull_container/1.             % the container waits for an image that would not pull
:- dynamic pull_failed/2.                % pull_failed(Container, Error)

%% pull_finding(?Code, ?Container, ?Details): one per container.
pull_finding(Code, Container, Details) :-
    pull_container(Container),
    once((pull_failed(Container, Error), pull_cause(Code, Error, Details))).

%% containerd reaches a registry through gr8s's mirror on 127.0.0.1, and an
%% answer from it is about the mirror, not the registry.
pull_cause("image-mirror-unavailable", Error, [Address]) :-
    after(Error, "http://127.0.0.1:", Rest),
    mentions(Rest, "/v2/"),
    split_string(Rest, "/", "", [Port|_]),
    string_concat("127.0.0.1:", Port, Address).
pull_cause("registry-tls-untrusted", Error, []) :- mentions(Error, "x509:").
pull_cause("registry-tls-untrusted", Error, []) :- mentions(Error, "failed to verify certificate").
pull_cause("image-pull-rate-limited", Error, []) :- mentions(Error, "toomanyrequests").
pull_cause("image-pull-rate-limited", Error, []) :- mentions(Error, "429 Too Many Requests").
pull_cause("image-pull-unauthorized", Error, []) :- mentions(Error, "unauthorized").
pull_cause("image-pull-unauthorized", Error, []) :- mentions(Error, "authorization failed").
pull_cause("image-pull-unauthorized", Error, []) :- mentions(Error, "401 Unauthorized").
pull_cause("image-pull-unauthorized", Error, []) :- mentions(Error, "403 Forbidden").
pull_cause("image-not-found", Error, []) :- mentions(Error, "manifest unknown").
pull_cause("image-not-found", Error, []) :- mentions(Error, ": not found").
pull_cause("registry-name-not-resolved", Error, [Host]) :-
    mentions(Error, "no such host"),
    after(Error, "lookup ", Rest),
    split_string(Rest, " ", ":", [Host|_]).
pull_cause("registry-unreachable", Error, []) :- mentions(Error, "connection refused").
pull_cause("registry-unreachable", Error, []) :- mentions(Error, "i/o timeout").
pull_cause("registry-unreachable", Error, []) :- mentions(Error, "no route to host").

%% pull_explanation(?Code, ?Summary, ?Step): Summary takes the Pod's name, the
%% container and the details.
pull_explanation("image-mirror-unavailable",
                 "Pod ~A: container ~S cannot start because the gr8s image mirror on its node, at ~A, could not supply its image.",
                 "Read that node's gr8s log, and the error below for the mirror's reason: it fetches each blob from the registry, or from a peer node, and answers 503 when it cannot.").
pull_explanation("registry-tls-untrusted",
                 "Pod ~A: container ~S cannot start because its image's registry presents a certificate the node does not trust.",
                 "Trust the registry's CA: a ClusterTrustBundle annotated gr8s.io/registries, or --registry-ca on each node (docs/runtime.md, \"Private registries and TLS trust\").").
pull_explanation("image-pull-rate-limited",
                 "Pod ~A: container ~S cannot start because its image's registry refuses more pulls for now.",
                 "Wait, or pull with an account the registry allows more pulls: add an imagePullSecret.").
pull_explanation("image-pull-unauthorized",
                 "Pod ~A: container ~S cannot start because its image's registry refuses to serve it without the right credentials.",
                 "Check that the image name is right, and that the Pod's imagePullSecrets name a Secret with credentials the registry accepts for it.").
pull_explanation("image-not-found",
                 "Pod ~A: container ~S cannot start because its image does not exist in the registry.",
                 "Correct the image name or tag in the workload's template.").
pull_explanation("registry-name-not-resolved",
                 "Pod ~A: container ~S cannot start because its node cannot resolve the registry's name, ~A.",
                 "Check the image's registry name and the node's DNS.").
pull_explanation("registry-unreachable",
                 "Pod ~A: container ~S cannot start because its node cannot reach the image's registry.",
                 "Check the node's network route and any proxy to the registry, and that the registry is up.").
