#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(dirname -- "$script_directory")
executable=${GR8S_CORE_API_EXECUTABLE:-$project_root/scripts/gr8s}
port=${GR8S_CORE_API_PORT:-18189}
work_directory=$(mktemp -d "${TMPDIR:-/tmp}/gr8s-core-api.XXXXXX")
server_pid=
node_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ] || [ "${GR8S_CORE_API_KEEP_WORKDIR:-0}" -eq 1 ]; then
    tail -100 "$work_directory/server.log" >&2 || true
    echo "core API diagnostics preserved at $work_directory" >&2
  else
    rm -rf -- "$work_directory"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for command in kubectl curl python3; do
  command -v "$command" >/dev/null
done

start_server() {
  "$executable" serve --runtime fake --disable-agent --port "$port" --node-port "$node_port" \
    --state-directory "$work_directory/state/" --kubeconfig "$work_directory/kubeconfig" \
    >>"$work_directory/server.log" 2>&1 &
  server_pid=$!
  attempt=0
  until curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if ! kill -0 "$server_pid" 2>/dev/null || [ "$attempt" -ge 600 ]; then
      echo "core API server failed to become ready" >&2
      exit 1
    fi
    sleep 0.1
  done
}

export KUBECONFIG="$work_directory/kubeconfig"
start_server
kubectl -n alpha create configmap settings --from-literal=mode=first
kubectl -n alpha create secret generic credentials --from-literal=password=first
[ "$(kubectl -n alpha get configmap settings -o jsonpath='{.data.mode}')" = first ]
[ "$(kubectl -n alpha get secret credentials -o jsonpath='{.data.password}')" = Zmlyc3Q= ]
kubectl -n alpha label configmap settings app=test
[ "$(kubectl -n alpha get configmaps -l app=test -o jsonpath='{.items[0].metadata.name}')" = settings ]
kubectl -n alpha patch configmap settings --type=merge -p '{"data":{"mode":"patched"}}'
kubectl -n alpha get configmap settings -o json >"$work_directory/replacement.json"
python3 - "$work_directory/replacement.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path) as stream:
    obj = json.load(stream)
obj['data']['mode'] = 'replaced'
with open(path, 'w') as stream:
    json.dump(obj, stream)
PY
kubectl replace -f "$work_directory/replacement.json"
cat >"$work_directory/apply.yaml" <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
  namespace: alpha
data:
  mode: applied
YAML
kubectl apply -f "$work_directory/apply.yaml"
[ "$(kubectl -n alpha get configmap settings -o jsonpath='{.data.mode}')" = applied ]
kubectl -n alpha patch secret credentials --type=json \
  -p '[{"op":"add","path":"/stringData","value":{"password":"updated"}}]'
kubectl -n beta create configmap settings --from-literal=mode=isolated
[ "$(kubectl get configmaps -A -o jsonpath='{.items[*].metadata.namespace}')" = 'alpha beta' ]

kill "$server_pid"
wait "$server_pid"
server_pid=
start_server
[ "$(kubectl -n alpha get configmap settings -o jsonpath='{.data.mode}')" = applied ]
[ "$(kubectl -n beta get configmap settings -o jsonpath='{.data.mode}')" = isolated ]
[ "$(kubectl -n alpha get secret credentials -o jsonpath='{.data.password}')" = dXBkYXRlZA== ]
kubectl -n alpha delete secret credentials --dry-run=server
kubectl -n alpha get secret credentials >/dev/null
kubectl -n alpha delete configmap settings
kubectl -n beta delete configmap settings
kubectl -n alpha delete secret credentials
[ -z "$(kubectl get configmaps -A -o jsonpath='{.items[*].metadata.name}')" ]
[ -z "$(kubectl get secrets -A -o jsonpath='{.items[*].metadata.name}')" ]
echo "gr8s ConfigMap/Secret kubectl CRUD, patch, apply, dry-run, and restart smoke passed"
