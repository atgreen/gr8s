%% SPDX-License-Identifier: MIT
%%
%% Why a running Pod is not ready, and why a container keeps restarting.
%% Facts come from container status and the probe definitions in the Pod
%% spec, and from the Pod's recent Events when they have been read.

:- dynamic pod_not_ready/0, gate_unmet/1.
:- dynamic container_running/1, container_started/1, container_not_started/1, container_unready/1.
:- dynamic probe/3.                      % probe(Container, Kind, Description)
:- dynamic restarting/2.                 % restarting(Container, Restarts)
:- dynamic crashed/3.                    % crashed(Container, ExitCode, FinishedAt)
:- dynamic out_of_memory/3.              % out_of_memory(Container, FinishedAt, MemoryLimit)
:- dynamic killed_by_signal/1, liveness_failed/1, liveness_kill_reported/1.

%% unready(?Code, ?Details): Details fill the explanation after the Pod's name.
unready("readiness-probe-failing", [Container, Check]) :-
    pod_not_ready,
    container_running(Container),
    container_started(Container),
    container_unready(Container),
    probe(Container, "readiness", Check).
unready("startup-probe-pending", [Container, Check]) :-
    container_running(Container),
    container_not_started(Container),
    probe(Container, "startup", Check).
unready("readiness-gate-unmet", [Gate]) :-
    pod_not_ready,
    gate_unmet(Gate).
unready("restarts-crash", [Container, Code, Finished, Restarts]) :-
    restarting(Container, Restarts),
    crashed(Container, Code, Finished).
unready("restarts-oom", [Container, Finished, Limit, Restarts]) :-
    restarting(Container, Restarts),
    out_of_memory(Container, Finished, Limit).
%% A failed liveness check alone does not show that it restarted the
%% container: the kubelet must say so, or the last run must have died by signal.
unready("restarts-liveness-kill", [Container, Check]) :-
    restarting(Container, _),
    probe(Container, "liveness", Check),
    liveness_killed(Container).

liveness_killed(Container) :- liveness_kill_reported(Container), !.
liveness_killed(Container) :- liveness_failed(Container), killed_by_signal(Container).

%% explanation(?Code, ?Summary, ?Step): Summary is a format string that takes
%% the Pod's name and then the rule's details.
explanation("readiness-probe-failing",
            "Pod ~A: container ~S is running but not ready: its readiness check ~A, and that check is not passing.",
            "Run the check by hand to see why it fails, then read the container log.").
explanation("startup-probe-pending",
            "Pod ~A: container ~S is running but has not finished starting: its startup check ~A, and that check has not passed yet.",
            "Read the container log to see how far startup got; a slow start may only need a more patient startup check.").
explanation("readiness-gate-unmet",
            "Pod ~A waits for readiness gate ~S, and nothing has set that condition to True.",
            "Check the controller that is responsible for this readiness gate.").
explanation("restarts-crash",
            "Pod ~A: container ~S keeps crashing: its last run exited with code ~D at ~A, and it has restarted ~D time~:P.",
            "Read the log of the run that crashed.").
explanation("restarts-oom",
            "Pod ~A: container ~S keeps being killed for running out of memory: its last run was killed at ~A with a memory limit of ~A, and it has restarted ~D time~:P.",
            "Compare the memory limit with what the program needs, then raise the limit or reduce its use.").
explanation("restarts-liveness-kill",
            "Pod ~A: container ~S keeps being restarted because its liveness check ~A, and that check fails.",
            "Find why the check fails or times out. If the program is healthy but slow, give the check a longer timeout.").
