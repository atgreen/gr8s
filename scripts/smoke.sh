#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(dirname -- "$script_directory")
work_directory=$(mktemp -d "${TMPDIR:-/tmp}/gr8s-smoke.XXXXXX")
port=${GR8S_PORT:-18083}
server_pid=

policy_pin_count() {
  count=0
  for pin in "$work_directory/state/agent/containerd/bpf/"*/rejected_spoofs \
             "$work_directory/state/agent/containerd/bpf/"*/endpoint_identity \
             "$work_directory/state/agent/containerd/bpf/"*/traffic_stats \
             "$work_directory/state/agent/containerd/bpf/"*/tcx-ingress; do
    [ -e "$pin" ] || continue
    count=$((count + 1))
  done
  echo "$count"
}

workload_state_present() {
  [ "$(policy_pin_count)" -ne 0 ] && return 0
  for namespace in "$work_directory/state/agent/containerd/run/io.containerd.grpc.v1.cri/netns/"*; do
    [ ! -e "$namespace" ] || return 0
  done
  ps -eo comm=,args= | awk -v state="$work_directory/state/" '
    $1 ~ /^containerd-shim/ && index($0, state) { found = 1 }
    END { exit !found }'
}

wait_for_workload_cleanup() {
  cleanup_attempt=0
  while workload_state_present; do
    cleanup_attempt=$((cleanup_attempt + 1))
    if [ "$cleanup_attempt" -ge 300 ]; then
      echo "Pod policy, namespace, or containerd shim remains after deletion" >&2
      return 1
    fi
    sleep 0.1
  done
}

wait_for_counter() {
  metric=$1
  counter_attempt=0
  until curl -fsS "http://127.0.0.1:$port/metrics" | awk -v metric="$metric" '
    index($1, metric "{") == 1 && $2 > 0 { found = 1 }
    END { exit !found }'; do
    counter_attempt=$((counter_attempt + 1))
    if [ "$counter_attempt" -ge 300 ]; then
      echo "expected a positive $metric sample from the agent" >&2
      return 1
    fi
    sleep 0.1
  done
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -f "$work_directory/kubeconfig" ]; then
    kubectl --kubeconfig "$work_directory/kubeconfig" --request-timeout=2s \
      delete pod gr8s-smoke --ignore-not-found >/dev/null 2>&1 || true
    wait_for_workload_cleanup || status=1
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
    if [ -f "$work_directory/state/agent/containerd/containerd.log" ]; then
      echo "--- containerd log ---" >&2
      tail -200 "$work_directory/state/agent/containerd/containerd.log" >&2
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

for command in kubectl curl ip nsenter ping ps awk base64; do
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
      args: ["echo gr8s-smoke; sleep 300"]
YAML

# Allow overriding the Pod pool CIDR so the smoke can run on a host that already
# carries a conflicting route (e.g. a leaked route from an aborted prior run).
pod_cidr_arg=""
if [ -n "${GR8S_SMOKE_POD_CIDR:-}" ]; then
  pod_cidr_arg="--cluster-pod-cidr $GR8S_SMOKE_POD_CIDR"
fi

# shellcheck disable=SC2086
"$project_root/build/gr8s" serve \
  --state-directory "$work_directory/state" \
  --port "$port" \
  --runtime containerd \
  --containerd-log-root "$work_directory/logs/" \
  --kubeconfig "$work_directory/kubeconfig" \
  $pod_cidr_arg \
  >"$work_directory/server.log" 2>&1 &
server_pid=$!

attempt=0
# gr8s serves the API (and /readyz) over authenticated TLS, not plain HTTP, so
# probe readiness through the generated kubeconfig (client cert over https).
# Health paths are granted to any authenticated identity, so this returns ok
# once the store is ready, without needing a plain-HTTP or anonymous endpoint.
until kubectl --kubeconfig "$work_directory/kubeconfig" get --raw='/readyz' >/dev/null 2>&1; do
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
  if [ "$phase" = Failed ] || [ "$attempt" -ge 600 ]; then
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
if kubectl --kubeconfig "$work_directory/kubeconfig" \
  exec gr8s-smoke -c main -- sh -c 'exit 7' >"$work_directory/exec-failure.log" 2>&1; then
  echo "kubectl exec lost the container's nonzero exit status" >&2
  exit 1
fi
grep -q 'exit code 7' "$work_directory/exec-failure.log"
kubectl --kubeconfig "$work_directory/kubeconfig" \
  exec gr8s-smoke -c main -- ping -c 1 -W 2 169.254.1.1 >/dev/null
kubectl --kubeconfig "$work_directory/kubeconfig" \
  exec gr8s-smoke -c main -- grep -q '^nameserver 169\.254\.1\.1$' /etc/resolv.conf
kubectl --kubeconfig "$work_directory/kubeconfig" \
  exec gr8s-smoke -c main -- nslookup kubernetes.default.svc.cluster.local \
  | grep -q '10\.96\.0\.1'
kubectl --kubeconfig "$work_directory/kubeconfig" \
  exec gr8s-smoke -c main -- nslookup example.com >/dev/null
if [ "$(policy_pin_count)" -ne 4 ]; then
  echo "expected three pinned Whistler maps and a TCX link for the running Pod" >&2
  exit 1
fi
# Inject a source address from the host: ordinary containers do not have
# CAP_NET_ADMIN. A failed ping plus an incremented policy counter proves the
# attached hook rejected the packet, rather than merely losing a reply route.
set -- "$work_directory/state/agent/containerd/run/io.containerd.grpc.v1.cri/netns/"*
if [ "$#" -ne 1 ] || [ ! -e "$1" ]; then
  echo "expected one live Pod network namespace" >&2
  exit 1
fi
pod_namespace=$1
nsenter --net="$pod_namespace" ip address add 192.0.2.123/32 dev eth0
if nsenter --net="$pod_namespace" ping -I 192.0.2.123 -c 1 -W 1 169.254.1.1 >/dev/null 2>&1; then
  echo "spoofed Pod source reached the gateway" >&2
  exit 1
fi
nsenter --net="$pod_namespace" ip address del 192.0.2.123/32 dev eth0
wait_for_counter gr8s_endpoint_allowed_packets_total
wait_for_counter gr8s_endpoint_rejected_spoofs_total

# --- Gateway API: host/path request routes end-to-end to a Pod (podster-43k.10) ---
# A backend web Pod + Service, a Gateway listener and an HTTPRoute. The in-agent
# L7 proxy must terminate an HTTP request on the gateway port and proxy it to the
# backend Pod, proving the JIT-compiled-router data plane end to end. Runs before
# the default-deny egress policy below, which would otherwise block the backend.
cat >"$work_directory/gw-web.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: gw-web
  labels:
    app: gw-web
spec:
  containers:
    - name: web
      image: docker.io/library/busybox:1.37.0
      command: ["sh", "-c"]
      args: ["mkdir -p /www && printf 'gateway-backend-ok\\n' > /www/index.html && httpd -f -p 8080 -h /www"]
---
apiVersion: v1
kind: Service
metadata:
  name: gw-web
  namespace: default
spec:
  publishNotReadyAddresses: true
  selector:
    app: gw-web
  ports:
    - port: 8080
      targetPort: 8080
YAML
kubectl --kubeconfig "$work_directory/kubeconfig" apply -f "$work_directory/gw-web.yaml"

attempt=0
until [ "$(kubectl --kubeconfig "$work_directory/kubeconfig" get pod gw-web \
  -o jsonpath='{.status.phase}' 2>/dev/null)" = Running ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 600 ]; then echo "gw-web backend Pod did not reach Running" >&2; exit 1; fi
  sleep 0.1
done

gw_server=$(kubectl --kubeconfig "$work_directory/kubeconfig" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
gw_post() {
  gw_code=$(curl -s -o "$work_directory/gw-create.out" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/json' --data @"$2" "$gw_server$1")
  if [ "$gw_code" != "201" ] && [ "$gw_code" != "200" ]; then
    echo "Gateway API create $1 failed: HTTP $gw_code" >&2; cat "$work_directory/gw-create.out" >&2; exit 1
  fi
}
cat >"$work_directory/gatewayclass.json" <<'JSON'
{"apiVersion":"gateway.networking.k8s.io/v1","kind":"GatewayClass","metadata":{"name":"gr8s"},"spec":{"controllerName":"gr8s.io/gateway-controller"}}
JSON
cat >"$work_directory/gateway.json" <<'JSON'
{"apiVersion":"gateway.networking.k8s.io/v1","kind":"Gateway","metadata":{"name":"web-gw","namespace":"default"},"spec":{"gatewayClassName":"gr8s","listeners":[{"name":"http","port":18088,"protocol":"HTTP"}]}}
JSON
cat >"$work_directory/httproute.json" <<'JSON'
{"apiVersion":"gateway.networking.k8s.io/v1","kind":"HTTPRoute","metadata":{"name":"web-route","namespace":"default"},"spec":{"parentRefs":[{"name":"web-gw"}],"hostnames":["gw.example.com"],"rules":[{"backendRefs":[{"name":"gw-web","port":8080}]}]}}
JSON
gw_post "/apis/gateway.networking.k8s.io/v1/gatewayclasses" "$work_directory/gatewayclass.json"
gw_post "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways" "$work_directory/gateway.json"
gw_post "/apis/gateway.networking.k8s.io/v1/namespaces/default/httproutes" "$work_directory/httproute.json"

# The agent converges the Gateway into an L7 listener on 127.0.0.1:18088. Retry
# until the route serves the backend body through the proxy.
gw_routed=0
for attempt in $(seq 1 60); do
  if curl -fsS -H 'Host: gw.example.com' "http://127.0.0.1:18088/" 2>/dev/null | grep -qx gateway-backend-ok; then
    gw_routed=1; break
  fi
  sleep 0.5
done
if [ "$gw_routed" -ne 1 ]; then
  echo "Gateway did not route host/path to the backend Pod" >&2
  curl -sS -H 'Host: gw.example.com' "http://127.0.0.1:18088/" >&2 || true
  exit 1
fi
gw_unmatched=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: nope.example.com' "http://127.0.0.1:18088/")
if [ "$gw_unmatched" != "404" ]; then
  echo "Gateway did not 404 an unmatched host (got $gw_unmatched)" >&2; exit 1
fi
echo "Gateway API routed host/path to the backend Pod through the in-agent L7 proxy"

# --- cert-manager: a Certificate issues a kubernetes.io/tls Secret (podster-045) ---
# A selfSigned ClusterIssuer + a Certificate; the control-plane controller must
# mint a leaf and write a kubernetes.io/tls Secret, proving cert-manager end to
# end in the native binary. (Serving that Secret from a Gateway HTTPS listener
# additionally needs node projection of Gateway-referenced Secrets, tracked
# separately.)
cat >"$work_directory/clusterissuer.json" <<'JSON'
{"apiVersion":"cert-manager.io/v1","kind":"ClusterIssuer","metadata":{"name":"selfsigned"},"spec":{"selfSigned":{}}}
JSON
cat >"$work_directory/certificate.json" <<'JSON'
{"apiVersion":"cert-manager.io/v1","kind":"Certificate","metadata":{"name":"web-cert","namespace":"default"},"spec":{"secretName":"web-tls","issuerRef":{"name":"selfsigned","kind":"ClusterIssuer"},"dnsNames":["gw.example.com"],"duration":"24h"}}
JSON
gw_post "/apis/cert-manager.io/v1/clusterissuers" "$work_directory/clusterissuer.json"
gw_post "/apis/cert-manager.io/v1/namespaces/default/certificates" "$work_directory/certificate.json"

cm_crt=
for attempt in $(seq 1 60); do
  cm_crt=$(kubectl --kubeconfig "$work_directory/kubeconfig" -n default \
    get secret web-tls -o jsonpath='{.data.tls\.crt}' 2>/dev/null || true)
  [ -n "$cm_crt" ] && break
  sleep 0.5
done
if [ -z "$cm_crt" ]; then
  echo "cert-manager did not issue the web-tls Secret" >&2; exit 1
fi
cm_type=$(kubectl --kubeconfig "$work_directory/kubeconfig" -n default get secret web-tls -o jsonpath='{.type}')
if [ "$cm_type" != "kubernetes.io/tls" ]; then
  echo "cert-manager Secret has wrong type: $cm_type" >&2; exit 1
fi
if ! printf '%s' "$cm_crt" | base64 -d 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
  echo "cert-manager tls.crt is not a PEM certificate" >&2; exit 1
fi
echo "cert-manager issued a kubernetes.io/tls Secret from a selfSigned Certificate"
curl -s -o /dev/null -X DELETE "$gw_server/apis/cert-manager.io/v1/namespaces/default/certificates/web-cert" || true
curl -s -o /dev/null -X DELETE "$gw_server/apis/cert-manager.io/v1/clusterissuers/selfsigned" || true
kubectl --kubeconfig "$work_directory/kubeconfig" -n default delete secret web-tls --ignore-not-found >/dev/null

# Tear the gateway scenario down and wait for the backend Pod's network state to
# drain, restoring the single-Pod baseline for the sections that follow.
kubectl --kubeconfig "$work_directory/kubeconfig" delete pod gw-web --ignore-not-found >/dev/null
kubectl --kubeconfig "$work_directory/kubeconfig" delete service gw-web --ignore-not-found >/dev/null
for gw_url in \
  "/apis/gateway.networking.k8s.io/v1/namespaces/default/httproutes/web-route" \
  "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways/web-gw" \
  "/apis/gateway.networking.k8s.io/v1/gatewayclasses/gr8s"; do
  curl -s -o /dev/null -X DELETE "$gw_server$gw_url" || true
done
attempt=0
until [ "$(ls -1 "$work_directory/state/agent/containerd/run/io.containerd.grpc.v1.cri/netns/" 2>/dev/null | wc -l)" -le 1 ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 600 ]; then echo "gw-web network state did not drain" >&2; exit 1; fi
  sleep 0.1
done

# --- NetworkPolicy compiled-firewall enforcement on the real Pod ---
# The Pod could reach its gateway above (no policy). Apply an egress policy that
# allows only an unrelated CIDR: once the agent converges and attaches the
# compiled classifier at the Pod's host veth, the gateway must become
# unreachable (default-deny egress), proving the compiled NetworkPolicy enforces
# on a real Pod. (Detach-on-removal is covered by unit tests.)
cat >"$work_directory/netpol.json" <<'JSON'
{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy",
 "metadata":{"name":"smoke-egress","namespace":"default"},
 "spec":{"podSelector":{},"policyTypes":["Egress"],
         "egress":[{"to":[{"ipBlock":{"cidr":"10.123.0.0/16"}}]}]}}
JSON
np_path=/apis/networking.k8s.io/v1/namespaces/default/networkpolicies
# POST directly with an explicit JSON content-type: the resource is served by the
# generic router (not yet advertised in discovery, and kubectl --raw does not set
# a content-type the server accepts). The API is plain HTTP on localhost.
np_server=$(kubectl --kubeconfig "$work_directory/kubeconfig" config view --minify -o jsonpath='{.clusters[0].cluster.server}')
np_code=$(curl -s -o "$work_directory/netpol-create.out" -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' \
  --data @"$work_directory/netpol.json" "$np_server$np_path")
if [ "$np_code" != "201" ] && [ "$np_code" != "200" ]; then
  echo "NetworkPolicy create failed: HTTP $np_code" >&2
  cat "$work_directory/netpol-create.out" >&2
  exit 1
fi
enforced=0
for attempt in $(seq 1 25); do
  if ! kubectl --kubeconfig "$work_directory/kubeconfig" \
       exec gr8s-smoke -c main -- ping -c 1 -W 1 169.254.1.1 >/dev/null 2>&1; then
    enforced=1; break
  fi
  sleep 1
done
if [ "$enforced" -ne 1 ]; then
  echo "NetworkPolicy did not enforce: gateway still reachable after egress-deny policy" >&2
  exit 1
fi
echo "NetworkPolicy compiled firewall enforced on real Pod: gateway blocked by egress policy"

kubectl --kubeconfig "$work_directory/kubeconfig" delete pod gr8s-smoke
if kubectl --kubeconfig "$work_directory/kubeconfig" get pod gr8s-smoke >/dev/null 2>&1; then
  echo "deleted Pod is still present" >&2
  exit 1
fi

wait_for_workload_cleanup

echo "gr8s embedded managed-containerd smoke test passed"
