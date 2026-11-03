#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(dirname -- "$script_directory")
work_directory=$(mktemp -d "${TMPDIR:-/tmp}/gr8s-smoke.XXXXXX")
port=${GR8S_PORT:-18083}
server_pid=

policy_pin_count() {
  count=0
  for pin in "$work_directory/state/containerd/bpf/"*/rejected_spoofs \
             "$work_directory/state/containerd/bpf/"*/tcx-egress; do
    [ -e "$pin" ] || continue
    count=$((count + 1))
  done
  echo "$count"
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -f "$work_directory/kubeconfig" ]; then
    kubectl --kubeconfig "$work_directory/kubeconfig" --request-timeout=2s \
      delete pod gr8s-smoke --ignore-not-found >/dev/null 2>&1 || true
  fi
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if { [ "$status" -ne 0 ] && [ -f "$work_directory/server.log" ]; } ||
     [ "${GR8S_SMOKE_KEEP_WORKDIR:-0}" -eq 1 ]; then
    if [ -f "$work_directory/server.log" ]; then
      echo "--- gr8s server log ---" >&2
      cat "$work_directory/server.log" >&2
    fi
    if [ -f "$work_directory/state/containerd/containerd.log" ]; then
      echo "--- containerd log ---" >&2
      tail -200 "$work_directory/state/containerd/containerd.log" >&2
    fi
    echo "gr8s smoke diagnostics preserved at $work_directory" >&2
  else
    rm -rf -- "$work_directory"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in kubectl curl; do
  command -v "$command" >/dev/null
done

if [ "$(id -u)" -ne 0 ]; then
  echo "gr8s managed smoke requires root for mounts, cgroups, and namespaces" >&2
  exit 1
fi

[ -x "$project_root/build/gr8s" ]

cat >"$work_directory/pod.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: gr8s-smoke
spec:
  containers:
    - name: main
      image: docker.io/library/busybox:1.37.0
      command: ["sh", "-c"]
      args: ["echo gr8s-smoke; sleep 30"]
YAML

"$project_root/build/gr8s" serve \
  --state-directory "$work_directory/state" \
  --port "$port" \
  --runtime containerd \
  --containerd-log-root "$work_directory/logs/" \
  --kubeconfig "$work_directory/kubeconfig" \
  >"$work_directory/server.log" 2>&1 &
server_pid=$!

attempt=0
until curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$work_directory/server.log"
    exit 1
  fi
  if [ "$attempt" -ge 600 ]; then
    cat "$work_directory/server.log"
    exit 1
  fi
  sleep 0.1
done

kubectl --kubeconfig "$work_directory/kubeconfig" apply -f "$work_directory/pod.yaml"
if [ "${GR8S_SMOKE_FAIL_AFTER_CREATE:-0}" -eq 1 ]; then
  exit 99
fi
kubectl --kubeconfig "$work_directory/kubeconfig" get pods

attempt=0
while :; do
  if ! pod_status=$(kubectl --kubeconfig "$work_directory/kubeconfig" \
    --request-timeout=10s \
    get pod gr8s-smoke \
    -o jsonpath='{.status.phase}{"\n"}{.status.reason}{"\n"}{.status.message}'); then
    echo "timed out waiting for gr8s to report Pod status" >&2
    exit 1
  fi
  phase=$(printf '%s\n' "$pod_status" | sed -n '1p')
  if [ "$attempt" -eq 0 ] && [ "$phase" != Running ]; then
    echo "initial Pod status:" >&2
    printf '%s\n' "$pod_status" >&2
  fi
  [ "$phase" = Running ] && break
  attempt=$((attempt + 1))
  if [ "$phase" = Failed ] || [ "$attempt" -ge 10 ]; then
    echo "Pod did not reach Running; phase=${phase:-unknown}" >&2
    kubectl --kubeconfig "$work_directory/kubeconfig" \
      get pod gr8s-smoke -o yaml >&2
    kubectl --kubeconfig "$work_directory/kubeconfig" \
      describe pod gr8s-smoke >&2
    exit 1
  fi
  sleep 0.1
done

kubectl --kubeconfig "$work_directory/kubeconfig" describe pod gr8s-smoke >/dev/null
kubectl --kubeconfig "$work_directory/kubeconfig" logs gr8s-smoke -c main | grep -q gr8s-smoke
kubectl --kubeconfig "$work_directory/kubeconfig" \
  exec gr8s-smoke -c main -- sh -c 'printf "gr8s-exec\n"' | grep -qx gr8s-exec
kubectl --kubeconfig "$work_directory/kubeconfig" \
  exec gr8s-smoke -c main -- grep -q '^nameserver 10\.88\.0\.1$' /etc/resolv.conf
kubectl --kubeconfig "$work_directory/kubeconfig" \
  exec gr8s-smoke -c main -- nslookup kubernetes.default.svc.cluster.local \
  | grep -q '10\.96\.0\.1'
kubectl --kubeconfig "$work_directory/kubeconfig" \
  exec gr8s-smoke -c main -- nslookup example.com >/dev/null
if [ "$(policy_pin_count)" -ne 2 ]; then
  echo "expected a pinned Whistler map and TCX link for the running Pod" >&2
  exit 1
fi
kubectl --kubeconfig "$work_directory/kubeconfig" delete pod gr8s-smoke
if kubectl --kubeconfig "$work_directory/kubeconfig" get pod gr8s-smoke >/dev/null 2>&1; then
  echo "deleted Pod is still present" >&2
  exit 1
fi

attempt=0
while [ "$(policy_pin_count)" -ne 0 ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ]; then
    echo "Whistler policy pins remain after Pod deletion" >&2
    exit 1
  fi
  sleep 0.1
done

echo "gr8s embedded managed-containerd smoke test passed"
