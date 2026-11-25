%% SPDX-License-Identifier: MIT
%%
%% Single-resource rules. A check names what one resource must show for a
%% finding: its kind, and premises that all hold at one location of it (the
%% object, or one of its containers). A premise tests normalized observations,
%% never message text. A check reports what was observed, not a guessed cause.

%% Asserted for the resource under examination. A value is what the API holds:
%% a string, a number, true or false, or count(N) for a list of N items.
:- dynamic kind/1, observed/3.

%% finding(?Id, ?Location, ?Summary, ?Step)
finding(Id, Location, Summary, Step) :-
    check(Id, Kind, Premises, Summary, Step),
    kind(Kind),
    holds(Premises, Location).

holds([], _).
holds([Premise|Premises], Location) :-
    premise(Premise, Location),
    holds(Premises, Location).

%% premise(+Premise, ?Location). A field that was not observed satisfies
%% nothing: a missing counter is unknown, not zero.
premise(has(Path, Value), Location) :-
    observed(Location, Path, Value).
premise(below(Lower, Upper), Location) :-
    observed(Location, Lower, A), number(A),
    observed(Location, Upper, B), number(B),
    A < B.
premise(positive(Path), Location) :-
    premise(at_least(Path, 1), Location).
premise(at_least(Path, Least), Location) :-
    observed(Location, Path, N), number(N),
    N >= Least.
premise(nonempty(Path), Location) :-
    observed(Location, Path, count(N)),
    N > 0.
premise(empty(Path), Location) :-
    observed(Location, Path, count(0)).
%% unless(Premise): Premise does not hold at a location the others have bound.
premise(unless(Premise), Location) :-
    \+ premise(Premise, Location).

%% premise_path(+Premise, ?Path): the fields a premise reads.
premise_path(has(Path, _), Path).
premise_path(below(Path, _), Path).
premise_path(below(_, Path), Path).
premise_path(positive(Path), Path).
premise_path(at_least(Path, _), Path).
premise_path(nonempty(Path), Path).
premise_path(empty(Path), Path).
premise_path(unless(Premise), Path) :- premise_path(Premise, Path).

%% reads(?Kind, ?Path): a check of resources of Kind reads the field Path.
reads(Kind, Path) :-
    check(_, Kind, Premises, _, _),
    member(Premise, Premises),
    premise_path(Premise, Path).

%% Findings that describe configuration or history rather than a present fault.
advisory(Id) :- string_concat("previous-", _, Id).
advisory("waiting-ContainerCreating").
advisory("waiting-PodInitializing").
advisory("node-cordoned").
advisory("cronjob-suspended").
advisory("container-restarts").
advisory("job-failed-attempts").
advisory("pod-hostNetwork").
advisory("pod-hostPID").
advisory("pod-hostIPC").
advisory("container-privileged").
advisory("container-runAsUser").
advisory("container-allowPrivilegeEscalation").
advisory("container-readOnlyRootFilesystem").
advisory("container-never-pull").
advisory("service-publishes-unready").
advisory("service-local-external-traffic").

%% check(?Id, ?Kind, ?Premises, ?Summary, ?Step)
% Event
check("event-FailedScheduling", "Event", [has("reason", "FailedScheduling"), has("type", "Warning")],
      "The scheduler could not find a node for the Pod. This is a past report and may no longer be true.",
      "Inspect scheduler constraints, requests, taints and volume topology.").
check("event-FailedMount", "Event", [has("reason", "FailedMount"), has("type", "Warning")],
      "A volume could not be mounted into the Pod. This is a past report and may no longer be true.",
      "Check volume sources and node mount diagnostics.").
check("event-FailedAttachVolume", "Event", [has("reason", "FailedAttachVolume"), has("type", "Warning")],
      "A volume could not be attached to the node. This is a past report and may no longer be true.",
      "Check storage attachment limits and the CSI controller.").
check("event-FailedMapVolume", "Event", [has("reason", "FailedMapVolume"), has("type", "Warning")],
      "A block volume could not be mapped on the node. This is a past report and may no longer be true.",
      "Inspect block device mapping and CSI node logs.").
check("event-FailedCreatePodSandBox", "Event", [has("reason", "FailedCreatePodSandBox"), has("type", "Warning")],
      "The node could not set up the Pod's sandbox (its network and namespaces). This is a past report and may no longer be true.",
      "Inspect container runtime and CNI sandbox setup.").
check("event-FailedPodSandBoxStatus", "Event", [has("reason", "FailedPodSandBoxStatus"), has("type", "Warning")],
      "The node could not read the state of the Pod's sandbox. This is a past report and may no longer be true.",
      "Inspect runtime sandbox status and runtime logs.").
check("event-FailedKillPod", "Event", [has("reason", "FailedKillPod"), has("type", "Warning")],
      "The node could not stop the Pod. This is a past report and may no longer be true.",
      "Inspect runtime cleanup and node connectivity.").
check("event-FailedCreatePodContainer", "Event", [has("reason", "FailedCreatePodContainer"), has("type", "Warning")],
      "The node could not create one of the Pod's containers. This is a past report and may no longer be true.",
      "Inspect runtime container creation diagnostics.").
check("event-NetworkNotReady", "Event", [has("reason", "NetworkNotReady"), has("type", "Warning")],
      "The node's Pod network was not ready. This is a past report and may no longer be true.",
      "Inspect node network initialization and CNI configuration.").
check("event-FailedSync", "Event", [has("reason", "FailedSync"), has("type", "Warning")],
      "The kubelet could not bring the Pod to its wanted state. This is a past report and may no longer be true.",
      "Inspect kubelet reconciliation logs for this Pod.").
check("event-FailedValidation", "Event", [has("reason", "FailedValidation"), has("type", "Warning")],
      "The kubelet rejected the Pod's specification. This is a past report and may no longer be true.",
      "Inspect Pod validation details and the submitted specification.").
check("event-FailedPostStartHook", "Event", [has("reason", "FailedPostStartHook"), has("type", "Warning")],
      "A container's postStart hook failed. This is a past report and may no longer be true.",
      "Inspect the postStart command and its dependencies.").
check("event-FailedPreStopHook", "Event", [has("reason", "FailedPreStopHook"), has("type", "Warning")],
      "A container's preStop hook failed. This is a past report and may no longer be true.",
      "Inspect the preStop command and termination timing.").
check("event-Unhealthy", "Event", [has("reason", "Unhealthy"), has("type", "Warning")],
      "A container failed a health check (probe). This is a past report and may no longer be true.",
      "Inspect probe configuration and application health.").
check("event-ProbeWarning", "Event", [has("reason", "ProbeWarning"), has("type", "Warning")],
      "A health check (probe) passed with a warning. This is a past report and may no longer be true.",
      "Inspect probe responses and probe execution diagnostics.").
check("event-BackOff", "Event", [has("reason", "BackOff"), has("type", "Warning")],
      "Kubernetes is waiting before it retries a failed image pull or container start. This is a past report and may no longer be true.",
      "Inspect the Event details to distinguish image retries from container restarts.").
check("event-Failed", "Event", [has("reason", "Failed"), has("type", "Warning")],
      "A container or image operation failed. This is a past report and may no longer be true.",
      "Inspect the reporting component and Event details before identifying a cause.").
check("event-InspectFailed", "Event", [has("reason", "InspectFailed"), has("type", "Warning")],
      "The node could not inspect a container image. This is a past report and may no longer be true.",
      "Inspect the image reference and runtime image inspection.").
check("event-ErrImageNeverPull", "Event", [has("reason", "ErrImageNeverPull"), has("type", "Warning")],
      "The image is not on the node, and the pull policy forbids pulling it. This is a past report and may no longer be true.",
      "Load the image onto the node or revise the pull policy.").
check("event-ExceededGracePeriod", "Event", [has("reason", "ExceededGracePeriod"), has("type", "Warning")],
      "A container did not stop within its grace period and was killed. This is a past report and may no longer be true.",
      "Inspect shutdown hooks and termination grace periods.").
check("event-FailedMountOnFilesystemMismatch", "Event", [has("reason", "FailedMountOnFilesystemMismatch"), has("type", "Warning")],
      "A volume holds a different filesystem than the Pod asked for. This is a past report and may no longer be true.",
      "Compare the requested filesystem with the volume filesystem.").
check("event-FailedPrepareDynamicResources", "Event", [has("reason", "FailedPrepareDynamicResources"), has("type", "Warning")],
      "The node could not prepare a device or resource claim for the Pod. This is a past report and may no longer be true.",
      "Inspect ResourceClaims and resource driver preparation.").
check("event-ResizeDeferred", "Event", [has("reason", "ResizeDeferred"), has("type", "Warning")],
      "A resource resize is waiting because the node has no room for it now. This is a past report and may no longer be true.",
      "Inspect available node capacity before retrying the resize.").
check("event-ResizeInfeasible", "Event", [has("reason", "ResizeInfeasible"), has("type", "Warning")],
      "A resource resize cannot fit on this node. This is a past report and may no longer be true.",
      "Compare resize requirements with node capacity and resize policy.").
check("event-ResizeError", "Event", [has("reason", "ResizeError"), has("type", "Warning")],
      "A resource resize failed. This is a past report and may no longer be true.",
      "Inspect the reported resize failure and runtime support.").
check("event-FailedNodeDeclaredFeaturesCheck", "Event", [has("reason", "FailedNodeDeclaredFeaturesCheck"), has("type", "Warning")],
      "The Pod needs a feature that its node does not declare. This is a past report and may no longer be true.",
      "Compare requested features with the assigned node capabilities.").
check("event-SecurityProfilePullFailed", "Event", [has("reason", "SecurityProfilePullFailed"), has("type", "Warning")],
      "A security profile could not be fetched. This is a past report and may no longer be true.",
      "Inspect profile availability and registry access.").
check("event-VolumeResizeFailed", "Event", [has("reason", "VolumeResizeFailed"), has("type", "Warning")],
      "A volume could not be resized. This is a past report and may no longer be true.",
      "Inspect CSI expansion support and controller diagnostics.").
check("event-FileSystemResizeFailed", "Event", [has("reason", "FileSystemResizeFailed"), has("type", "Warning")],
      "The filesystem on a volume could not be grown. This is a past report and may no longer be true.",
      "Inspect filesystem expansion support and node diagnostics.").
check("event-FailedToRetrieveImagePullSecret", "Event", [has("reason", "FailedToRetrieveImagePullSecret"), has("type", "Warning")],
      "An image pull secret named by the Pod could not be read. This is a past report and may no longer be true.",
      "Check imagePullSecrets names and access in the Pod namespace.").

% Pod
check("waiting-CrashLoopBackOff", "Pod", [has("container.waiting.reason", "CrashLoopBackOff")],
      "The container keeps crashing, and Kubernetes is waiting before it restarts it again.",
      "Read the logs of the previous run (kubectl logs --previous) and its exit code.").
check("waiting-ImagePullBackOff", "Pod", [has("container.waiting.reason", "ImagePullBackOff")],
      "The image could not be pulled, and Kubernetes is waiting before it tries again.",
      "Check image reference, registry connectivity and pull credentials.").
check("waiting-ErrImagePull", "Pod", [has("container.waiting.reason", "ErrImagePull")],
      "The image could not be pulled.",
      "Inspect registry access and the referenced image tag or digest.").
check("waiting-InvalidImageName", "Pod", [has("container.waiting.reason", "InvalidImageName")],
      "The image name is not valid.",
      "Correct the container image reference in its workload template.").
check("waiting-CreateContainerConfigError", "Pod", [has("container.waiting.reason", "CreateContainerConfigError")],
      "The container cannot be created because its configuration is wrong, often a missing Secret or ConfigMap.",
      "Inspect required configuration and runtime configuration diagnostics.").
check("waiting-CreateContainerError", "Pod", [has("container.waiting.reason", "CreateContainerError")],
      "The node's container runtime could not create the container.",
      "Inspect runtime creation diagnostics and security settings.").
check("waiting-RunContainerError", "Pod", [has("container.waiting.reason", "RunContainerError")],
      "The container was created but could not be started.",
      "Inspect runtime startup diagnostics and the container command.").
check("previous-DeadlineExceeded", "Pod", [has("container.last-terminated.reason", "DeadlineExceeded")],
      "The container's previous run was stopped for exceeding its deadline. That run is over; the current one may be fine.",
      "Inspect previous logs and compare the termination time with the current container state.").
check("waiting-ErrImageNeverPull", "Pod", [has("container.waiting.reason", "ErrImageNeverPull")],
      "The image is not on the node, and the pull policy forbids pulling it.",
      "Ensure the image is already present on the assigned node.").
check("previous-OOMKilled", "Pod", [has("container.last-terminated.reason", "OOMKilled")],
      "The container's previous run was killed for running out of memory. That run is over; the current one may be fine.",
      "Inspect previous logs and compare the termination time with the current container state.").
check("waiting-PodInitializing", "Pod", [has("container.waiting.reason", "PodInitializing")],
      "The container is waiting for the Pod's init containers to finish.",
      "Inspect init container progress before the application container.").
check("waiting-ContainerCreating", "Pod", [has("container.waiting.reason", "ContainerCreating")],
      "The container is still being created.",
      "Inspect mount, image and sandbox progress; this may be normal startup.").
check("previous-Error", "Pod", [has("container.last-terminated.reason", "Error")],
      "The container's previous run exited with an error. That run is over; the current one may be fine.",
      "Inspect previous logs and compare the termination time with the current container state.").
check("previous-StartError", "Pod", [has("container.last-terminated.reason", "StartError")],
      "The container's previous run failed to start. That run is over; the current one may be fine.",
      "Inspect previous logs and compare the termination time with the current container state.").
check("previous-ContainerCannotRun", "Pod", [has("container.last-terminated.reason", "ContainerCannotRun")],
      "The runtime could not run the command of the container's previous run. That run is over; the current one may be fine.",
      "Inspect previous logs and compare the termination time with the current container state.").
check("terminated-OOMKilled", "Pod", [has("container.terminated.reason", "OOMKilled")],
      "The container was killed for running out of memory.",
      "Inspect memory usage, limits and node memory pressure.").
check("terminated-Error", "Pod", [has("container.terminated.reason", "Error")],
      "The container exited with an error.",
      "Inspect container logs and the exit code.").
check("terminated-ContainerCannotRun", "Pod", [has("container.terminated.reason", "ContainerCannotRun")],
      "The runtime could not run the container's command.",
      "Inspect command, permissions and image architecture.").
check("terminated-StartError", "Pod", [has("container.terminated.reason", "StartError")],
      "The container failed to start.",
      "Inspect runtime startup diagnostics.").
check("terminated-DeadlineExceeded", "Pod", [has("container.terminated.reason", "DeadlineExceeded")],
      "The container was stopped for exceeding its deadline.",
      "Inspect execution deadlines and workload duration.").
check("terminated-Evicted", "Pod", [has("container.terminated.reason", "Evicted")],
      "The container was stopped because the Pod was evicted.",
      "Inspect eviction diagnostics and resource pressure.").
check("terminated-ContainerStatusUnknown", "Pod", [has("container.terminated.reason", "ContainerStatusUnknown")],
      "The node lost track of the container's state.",
      "Inspect node connectivity and runtime state.").
check("terminated-exit-137", "Pod", [has("container.terminated.exitCode", 137)],
      "The container exited with code 137: it was killed with SIGKILL. That alone does not prove it ran out of memory.",
      "Inspect termination reason, node pressure and signals sent to the process.").
check("pod-PodScheduled-False", "Pod", [has("condition.PodScheduled", "False")],
      "The Pod has not been placed on a node.",
      "Inspect scheduling Events and node eligibility.").
check("pod-PodScheduled-Unknown", "Pod", [has("condition.PodScheduled", "Unknown")],
      "It is not known whether the Pod has been placed on a node.",
      "Check scheduler and control-plane observations.").
check("pod-Initialized-False", "Pod", [has("condition.Initialized", "False")],
      "The Pod's init containers have not finished.",
      "Inspect init container status and logs.").
%% A finished Pod is not ready by design; a failed one has findings of its own (podster-191).
check("pod-Ready-False", "Pod", [has("condition.Ready", "False"),
                                 unless(has("status.phase", "Succeeded")), unless(has("status.phase", "Failed"))],
      "The Pod is not ready, so Services do not send it traffic.",
      "Find the container or readiness gate that is holding the Pod back.").
check("pod-Ready-Unknown", "Pod", [has("condition.Ready", "Unknown")],
      "The Pod's readiness is unknown, usually because its node stopped reporting.",
      "Check node reachability and status reporting.").
check("pod-ContainersReady-False", "Pod", [has("condition.ContainersReady", "False"),
                                           unless(has("status.phase", "Succeeded")), unless(has("status.phase", "Failed"))],
      "At least one container in the Pod is not ready.",
      "Check each container's state and its readiness check.").
check("pod-PodReadyToStartContainers-False", "Pod", [has("condition.PodReadyToStartContainers", "False")],
      "The Pod's sandbox and network are not set up yet, so no container can start.",
      "Inspect sandbox creation and network setup.").
check("pod-DisruptionTarget-True", "Pod", [has("condition.DisruptionTarget", "True")],
      "The Pod is about to be removed by an eviction, a preemption or a node shutdown.",
      "Inspect the disruption reason and replacement capacity.").
check("pod-Evicted", "Pod", [has("status.reason", "Evicted")],
      "The Pod was evicted from its node.",
      "Inspect eviction reason and resource requests.").
check("pod-NodeLost", "Pod", [has("status.reason", "NodeLost")],
      "The Pod's node stopped responding.",
      "Inspect node health before replacing the workload.").
check("pod-DeadlineExceeded", "Pod", [has("status.reason", "DeadlineExceeded")],
      "The Pod ran longer than its activeDeadlineSeconds and was stopped.",
      "Review activeDeadlineSeconds and workload duration.").
check("pod-Shutdown", "Pod", [has("status.reason", "Shutdown")],
      "The Pod was stopped because its node shut down.",
      "Inspect node shutdown and replacement scheduling.").

% Node
check("node-Ready-False", "Node", [has("condition.Ready", "False")],
      "The node is not ready, so it cannot run new Pods.",
      "Inspect kubelet, runtime and node health.").
check("node-Ready-Unknown", "Node", [has("condition.Ready", "Unknown")],
      "The node has stopped reporting, so its state is unknown.",
      "Check node heartbeat and control-plane connectivity.").
check("node-MemoryPressure-True", "Node", [has("condition.MemoryPressure", "True")],
      "The node is low on memory.",
      "Inspect node memory consumption and eviction thresholds.").
check("node-DiskPressure-True", "Node", [has("condition.DiskPressure", "True")],
      "The node is low on disk space.",
      "Inspect node filesystem space and inode usage.").
check("node-PIDPressure-True", "Node", [has("condition.PIDPressure", "True")],
      "The node is running too many processes.",
      "Inspect process counts and PID limits.").
check("node-NetworkUnavailable-True", "Node", [has("condition.NetworkUnavailable", "True")],
      "The node's network is not set up.",
      "Inspect node routes and network plugin readiness.").
check("node-cordoned", "Node", [has("spec.unschedulable", true)],
      "The node is cordoned: no new Pods will be scheduled on it.",
      "Check maintenance intent before considering uncordoning.").
check("taint-unreachable", "Node", [has("taint.key", "node.kubernetes.io/unreachable")],
      "The node carries the unreachable taint, which keeps Pods away from it.",
      "Inspect the node condition and taint effect before changing scheduling policy.").
check("taint-not-ready", "Node", [has("taint.key", "node.kubernetes.io/not-ready")],
      "The node carries the not-ready taint, which keeps Pods away from it.",
      "Inspect the node condition and taint effect before changing scheduling policy.").
check("taint-out-of-service", "Node", [has("taint.key", "node.kubernetes.io/out-of-service")],
      "The node carries the out-of-service taint, which keeps Pods away from it.",
      "Inspect the node condition and taint effect before changing scheduling policy.").

% PersistentVolumeClaim
check("pvc-Pending", "PersistentVolumeClaim", [has("status.phase", "Pending")],
      "The claim is still waiting for a volume.",
      "Inspect binding, provisioning and the referenced storage class.").
check("pvc-Lost", "PersistentVolumeClaim", [has("status.phase", "Lost")],
      "The claim has lost the volume it was bound to.",
      "Inspect binding, provisioning and the referenced storage class.").
check("pvc-Resizing", "PersistentVolumeClaim", [has("condition.Resizing", "True")],
      "The claim's volume is being resized.",
      "Inspect storage controller and node expansion or modification diagnostics.").
check("pvc-FileSystemResizePending", "PersistentVolumeClaim", [has("condition.FileSystemResizePending", "True")],
      "The volume was resized; its filesystem will grow when a Pod next mounts it.",
      "Inspect storage controller and node expansion or modification diagnostics.").
check("pvc-ControllerResizeError", "PersistentVolumeClaim", [has("condition.ControllerResizeError", "True")],
      "The storage controller failed to resize the volume.",
      "Inspect storage controller and node expansion or modification diagnostics.").
check("pvc-NodeResizeError", "PersistentVolumeClaim", [has("condition.NodeResizeError", "True")],
      "The node failed to grow the filesystem on the volume.",
      "Inspect storage controller and node expansion or modification diagnostics.").
check("pvc-ModifyVolumeError", "PersistentVolumeClaim", [has("condition.ModifyVolumeError", "True")],
      "The storage controller failed to modify the volume.",
      "Inspect storage controller and node expansion or modification diagnostics.").

% Deployment
check("deployment-Available-False", "Deployment", [has("condition.Available", "False")],
      "The Deployment does not have enough available Pods.",
      "Inspect desired replicas and Pod readiness.").
check("deployment-Progressing-False", "Deployment", [has("condition.Progressing", "False"), has("condition-reason.Progressing", "ProgressDeadlineExceeded")],
      "The rollout has stalled: it made no progress before its deadline.",
      "Inspect rollout Pods and progressDeadlineSeconds.").
check("deployment-ReplicaFailure-True", "Deployment", [has("condition.ReplicaFailure", "True")],
      "The Deployment could not create or delete a Pod.",
      "Inspect ReplicaSet creation failures, quota and admission.").
check("deployment-Progressing-Unknown", "Deployment", [has("condition.Progressing", "Unknown")],
      "It is not known whether the rollout is progressing.",
      "Inspect deployment controller observations.").
check("deployment-Available-Unknown", "Deployment", [has("condition.Available", "Unknown")],
      "It is not known whether the Deployment is available.",
      "Inspect deployment controller and Pod status updates.").

% Job
check("job-BackoffLimitExceeded", "Job", [has("condition.Failed", "True"), has("condition-reason.Failed", "BackoffLimitExceeded")],
      "The Job failed: its Pods failed more times than the Job allows.",
      "Inspect failed Pods and Job retry limits.").
check("job-DeadlineExceeded", "Job", [has("condition.Failed", "True"), has("condition-reason.Failed", "DeadlineExceeded")],
      "The Job failed: it ran longer than its deadline.",
      "Inspect activeDeadlineSeconds and execution time.").
check("job-PodFailurePolicy", "Job", [has("condition.FailureTarget", "True"), has("condition-reason.FailureTarget", "PodFailurePolicy")],
      "The Job is failing because a Pod failure matched its failure policy.",
      "Inspect the Pod failure policy and matching exit status.").
check("job-Suspended", "Job", [has("condition.Suspended", "True")],
      "The Job is suspended and runs no Pods.",
      "Check whether suspension was intentional before resuming.").
check("job-FailedIndexes", "Job", [has("condition.Failed", "True"), has("condition-reason.Failed", "FailedIndexes")],
      "The Job failed: some of its indexes failed.",
      "Inspect failed indexed completions and per-index retry limits.").

% HorizontalPodAutoscaler
check("hpa-AbleToScale-False", "HorizontalPodAutoscaler", [has("condition.AbleToScale", "False")],
      "The autoscaler cannot change the replica count of its target.",
      "Inspect scale target access and autoscaler Events.").
check("hpa-ScalingActive-False", "HorizontalPodAutoscaler", [has("condition.ScalingActive", "False")],
      "The autoscaler is not scaling, usually because it cannot read its metrics.",
      "Inspect metric availability and target configuration.").
check("hpa-ScalingLimited-True", "HorizontalPodAutoscaler", [has("condition.ScalingLimited", "True")],
      "The autoscaler wants a replica count outside its minimum and maximum.",
      "Compare desired replicas with minReplicas and maxReplicas.").
check("hpa-AbleToScale-Unknown", "HorizontalPodAutoscaler", [has("condition.AbleToScale", "Unknown")],
      "It is not known whether the autoscaler can scale its target.",
      "Inspect autoscaler status reporting.").

% PersistentVolume
check("pv-Failed", "PersistentVolume", [has("status.phase", "Failed")],
      "The volume could not be reclaimed automatically.",
      "Inspect the persistent volume failure message and storage backend.").
check("pv-Released", "PersistentVolume", [has("status.phase", "Released")],
      "The volume's claim was deleted, but the volume has not been reclaimed.",
      "Check reclaim policy and previous claim before reusing storage.").

% CertificateSigningRequest
check("csr-Denied", "CertificateSigningRequest", [has("condition.Denied", "True")],
      "The certificate request was denied.",
      "Inspect signer policy and request conditions; do not bypass approval policy.").
check("csr-Failed", "CertificateSigningRequest", [has("condition.Failed", "True")],
      "The certificate request could not be signed.",
      "Inspect signer policy and request conditions; do not bypass approval policy.").

% Deployment
check("deployment-available-deficit", "Deployment", [below("status.availableReplicas", "spec.replicas")],
      "Fewer Pods are available than the replica count asks for.",
      "Diagnose one of the Pods that is not available; a rollout in progress also looks like this.").
check("deployment-ready-deficit", "Deployment", [below("status.readyReplicas", "spec.replicas")],
      "Fewer Pods are ready than the replica count asks for.",
      "Diagnose one of the Pods that is not ready; a rollout in progress also looks like this.").
check("deployment-updated-deficit", "Deployment", [below("status.updatedReplicas", "spec.replicas")],
      "Not all Pods run the latest version yet.",
      "Check whether the rollout is still moving; if it is stuck, diagnose one of the new Pods.").

% ReplicaSet
check("replicaset-available-deficit", "ReplicaSet", [below("status.availableReplicas", "spec.replicas")],
      "Fewer Pods are available than the replica count asks for.",
      "Diagnose one of the Pods that is not available; a rollout in progress also looks like this.").
check("replicaset-ready-deficit", "ReplicaSet", [below("status.readyReplicas", "spec.replicas")],
      "Fewer Pods are ready than the replica count asks for.",
      "Diagnose one of the Pods that is not ready; a rollout in progress also looks like this.").

% StatefulSet
check("statefulset-ready-deficit", "StatefulSet", [below("status.readyReplicas", "spec.replicas")],
      "Fewer Pods are ready than the replica count asks for.",
      "Diagnose one of the Pods that is not ready; a rollout in progress also looks like this.").
check("statefulset-updated-deficit", "StatefulSet", [below("status.updatedReplicas", "spec.replicas")],
      "Not all Pods run the latest version yet.",
      "Check whether the rollout is still moving; if it is stuck, diagnose one of the new Pods.").
check("statefulset-current-deficit", "StatefulSet", [below("status.currentReplicas", "spec.replicas")],
      "Fewer Pods of the current revision exist than the replica count asks for.",
      "Check whether a rollout is still moving; if it is stuck, diagnose the next Pod it is waiting for.").

% DaemonSet
check("daemonset-numberReady-deficit", "DaemonSet", [below("status.numberReady", "status.desiredNumberScheduled")],
      "Fewer Pods are ready than the nodes that should run one.",
      "Inspect eligible nodes, placement constraints and DaemonSet Pod status.").
check("daemonset-numberAvailable-deficit", "DaemonSet", [below("status.numberAvailable", "status.desiredNumberScheduled")],
      "Fewer Pods are available than the nodes that should run one.",
      "Inspect eligible nodes, placement constraints and DaemonSet Pod status.").
check("daemonset-updatedNumberScheduled-deficit", "DaemonSet", [below("status.updatedNumberScheduled", "status.desiredNumberScheduled")],
      "Not all nodes run the latest version of the Pod yet.",
      "Inspect eligible nodes, placement constraints and DaemonSet Pod status.").
check("daemonset-currentNumberScheduled-deficit", "DaemonSet", [below("status.currentNumberScheduled", "status.desiredNumberScheduled")],
      "Some nodes that should run a Pod do not have one.",
      "Inspect eligible nodes, placement constraints and DaemonSet Pod status.").

% Deployment
check("deployment-status-behind-generation", "Deployment", [below("status.observedGeneration", "metadata.generation")],
      "The controller has not yet acted on the latest change to this object, so its status may be out of date.",
      "Wait for reconciliation and inspect controller availability before treating old conditions as current.").

% ReplicaSet
check("replicaset-status-behind-generation", "ReplicaSet", [below("status.observedGeneration", "metadata.generation")],
      "The controller has not yet acted on the latest change to this object, so its status may be out of date.",
      "Wait for reconciliation and inspect controller availability before treating old conditions as current.").

% StatefulSet
check("statefulset-status-behind-generation", "StatefulSet", [below("status.observedGeneration", "metadata.generation")],
      "The controller has not yet acted on the latest change to this object, so its status may be out of date.",
      "Wait for reconciliation and inspect controller availability before treating old conditions as current.").

% DaemonSet
check("daemonset-status-behind-generation", "DaemonSet", [below("status.observedGeneration", "metadata.generation")],
      "The controller has not yet acted on the latest change to this object, so its status may be out of date.",
      "Wait for reconciliation and inspect controller availability before treating old conditions as current.").

% HorizontalPodAutoscaler
check("horizontalpodautoscaler-status-behind-generation", "HorizontalPodAutoscaler", [below("status.observedGeneration", "metadata.generation")],
      "The controller has not yet acted on the latest change to this object, so its status may be out of date.",
      "Wait for reconciliation and inspect controller availability before treating old conditions as current.").

% Job
check("job-status-behind-generation", "Job", [below("status.observedGeneration", "metadata.generation")],
      "The controller has not yet acted on the latest change to this object, so its status may be out of date.",
      "Wait for reconciliation and inspect controller availability before treating old conditions as current.").
check("job-failed-attempts", "Job", [positive("status.failed")],
      "At least one of the Job's Pods has failed.",
      "Inspect failed Pod logs; retries may still succeed.").

% CronJob
check("cronjob-suspended", "CronJob", [has("spec.suspend", true)],
      "The CronJob is suspended and starts no new Jobs.",
      "Confirm maintenance intent before resuming schedules.").

% Service
check("service-publishes-unready", "Service", [has("spec.publishNotReadyAddresses", true)],
      "The Service also sends traffic to Pods that are not ready.",
      "Confirm this is intentional for discovery; clients must handle unready backends.").
check("service-local-external-traffic", "Service", [has("spec.externalTrafficPolicy", "Local")],
      "External traffic only reaches Pods on the node that received it.",
      "Check backend placement on each receiving node when investigating uneven availability.").
check("service-loadbalancer-pending", "Service", [empty("status.loadBalancer.ingress"), has("spec.type", "LoadBalancer")],
      "The Service has not been given a load balancer address.",
      "Inspect the load balancer controller and Service Events.").

% EndpointSlice
check("endpointslice-empty", "EndpointSlice", [empty("endpoints")],
      "The slice lists no endpoints.",
      "Inspect the Service selector and matching Pods; other slices may contain endpoints.").
check("endpointslice-all-unready", "EndpointSlice", [has("derived.all-endpoints-unready", true)],
      "No endpoint in this slice is ready.",
      "Inspect readiness of these backends and other slices for the Service.").

% Namespace
check("namespace-terminating", "Namespace", [has("status.phase", "Terminating")],
      "The namespace is being deleted.",
      "Inspect remaining objects and finalizers before considering manual intervention.").
check("namespace-NamespaceDeletionDiscoveryFailure", "Namespace", [has("condition.NamespaceDeletionDiscoveryFailure", "True")],
      "Deletion is stuck: the cluster could not list every resource type in the namespace.",
      "Inspect the condition details and responsible controller; do not remove finalizers blindly.").
check("namespace-NamespaceDeletionContentFailure", "Namespace", [has("condition.NamespaceDeletionContentFailure", "True")],
      "Deletion is stuck: some objects in the namespace could not be deleted.",
      "Inspect the condition details and responsible controller; do not remove finalizers blindly.").
check("namespace-NamespaceContentRemaining", "Namespace", [has("condition.NamespaceContentRemaining", "True")],
      "Deletion is waiting: objects remain in the namespace.",
      "Inspect the condition details and responsible controller; do not remove finalizers blindly.").
check("namespace-NamespaceFinalizersRemaining", "Namespace", [has("condition.NamespaceFinalizersRemaining", "True")],
      "Deletion is waiting: objects in the namespace still have finalizers.",
      "Inspect the condition details and responsible controller; do not remove finalizers blindly.").

% ReplicaSet
check("replicaset-replica-failure", "ReplicaSet", [has("condition.ReplicaFailure", "True")],
      "The ReplicaSet could not create or delete a Pod.",
      "Inspect quota, admission and ReplicaSet Events.").

% StatefulSet
check("statefulset-revision-collision", "StatefulSet", [positive("status.collisionCount")],
      "The controller reports name collisions between its revisions.",
      "Inspect revision objects and controller logs; the count may be historical.").

% DaemonSet
check("daemonset-revision-collision", "DaemonSet", [positive("status.collisionCount")],
      "The controller reports name collisions between its revisions.",
      "Inspect revision objects and controller logs; the count may be historical.").

% Pod
check("container-restarts", "Pod", [positive("container.restartCount")],
      "The container has restarted before.",
      "Inspect previous termination reasons and logs; the counter is cumulative.").
check("container-restarts-five", "Pod", [at_least("container.restartCount", 5)],
      "The container has restarted at least five times.",
      "Compare restart timestamps and logs to determine whether failures are continuing.").
check("pod-finalizing", "Pod", [has("derived.deleting-with-finalizers", true)],
      "The Pod is being deleted but is held back by finalizers.",
      "Inspect the finalizer owners and shutdown progress.").
check("pod-scheduling-gates", "Pod", [nonempty("spec.schedulingGates")],
      "The Pod is held back from scheduling by scheduling gates.",
      "Inspect the controller responsible for clearing the gates before expecting placement.").
check("pod-hostNetwork", "Pod", [has("spec.hostNetwork", true)],
      "The Pod uses the node's network directly. This is a configuration note.",
      "Confirm host networking is intended and check port conflicts.").
check("pod-hostPID", "Pod", [has("spec.hostPID", true)],
      "The Pod can see the node's processes. This is a configuration note.",
      "Confirm host process visibility is required by this workload.").
check("pod-hostIPC", "Pod", [has("spec.hostIPC", true)],
      "The Pod shares the node's inter-process communication. This is a configuration note.",
      "Confirm host IPC sharing is required by this workload.").
check("container-privileged", "Pod", [has("container.securityContext.privileged", true)],
      "The container runs privileged, with full access to the node. This is a configuration note.",
      "Confirm the container needs privileged access.").
check("container-runAsUser", "Pod", [has("container.securityContext.runAsUser", 0)],
      "The container runs as root (UID 0). This is a configuration note.",
      "Confirm running as UID 0 is required.").
check("container-allowPrivilegeEscalation", "Pod", [has("container.securityContext.allowPrivilegeEscalation", true)],
      "The container may gain more privileges than it starts with. This is a configuration note.",
      "Review whether privilege escalation is needed.").
check("container-readOnlyRootFilesystem", "Pod", [has("container.securityContext.readOnlyRootFilesystem", false)],
      "The container's root filesystem is writable. This is a configuration note.",
      "Review whether the container needs a writable root filesystem.").
check("container-never-pull", "Pod", [has("container.imagePullPolicy", "Never")],
      "The container's image is never pulled; it must already be on the node.",
      "Verify image availability on every eligible node.").
check("pod-no-restart-after-error", "Pod", [has("spec.restartPolicy", "Never"), has("derived.current-container-error", true)],
      "A container failed and the Pod's restart policy is Never, so it will not be restarted.",
      "Inspect the owning Job or controller for replacement behavior.").

% Node
check("taint-disk-pressure", "Node", [has("taint.key", "node.kubernetes.io/disk-pressure")],
      "The node carries the disk-pressure taint, which keeps Pods away from it.",
      "Inspect node conditions and taint effects before changing placement.").
check("taint-memory-pressure", "Node", [has("taint.key", "node.kubernetes.io/memory-pressure")],
      "The node carries the memory-pressure taint, which keeps Pods away from it.",
      "Inspect node conditions and taint effects before changing placement.").
check("taint-pid-pressure", "Node", [has("taint.key", "node.kubernetes.io/pid-pressure")],
      "The node carries the pid-pressure taint, which keeps Pods away from it.",
      "Inspect node conditions and taint effects before changing placement.").
check("taint-network-unavailable", "Node", [has("taint.key", "node.kubernetes.io/network-unavailable")],
      "The node carries the network-unavailable taint, which keeps Pods away from it.",
      "Inspect node conditions and taint effects before changing placement.").
