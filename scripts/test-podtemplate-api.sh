#!/bin/sh
# SPDX-FileCopyrightText: 2026 gr8s contributors
# SPDX-License-Identifier: MIT
#
# Purpose:
# Exercise PodTemplate OpenAPI and client-side apply through real kubectl,
# including named-list ordering, restart persistence and paginated lists.
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(dirname -- "$script_directory")
executable=${GR8S_PODTEMPLATE_EXECUTABLE:-$project_root/build/gr8s.bin}
port=${GR8S_PODTEMPLATE_PORT:-18191}
node_port=${GR8S_PODTEMPLATE_NODE_PORT:-17448}
work_directory=$(mktemp -d "${TMPDIR:-/tmp}/gr8s-podtemplate-api.XXXXXX")
server_pid=

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ] || [ "${GR8S_PODTEMPLATE_KEEP_WORKDIR:-0}" -eq 1 ]; then
    echo "PodTemplate API diagnostics: $work_directory" >&2
  else
    rm -rf -- "$work_directory"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_server() {
  "$executable" serve --runtime fake --disable-agent --state-directory "$work_directory/state" \
    --port "$port" --node-port "$node_port" --kubeconfig "$work_directory/kubeconfig" \
    >>"$work_directory/server.log" 2>&1 &
  server_pid=$!
  attempt=0
  until curl -fsS "http://127.0.0.1:$port/readyz" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if ! kill -0 "$server_pid" 2>/dev/null || [ "$attempt" -ge 300 ]; then
      echo "PodTemplate API did not become ready" >&2
      exit 1
    fi
    sleep .1
  done
}

export KUBECONFIG="$work_directory/kubeconfig"
start_server
kubectl create namespace template-smoke
cat >"$work_directory/template.json" <<'JSON'
{"apiVersion":"v1","kind":"PodTemplate","metadata":{"name":"web","namespace":"template-smoke","labels":{"app":"api-smoke"}},"template":{"spec":{"containers":[{"name":"main","image":"example.invalid/web:v1","env":[{"name":"KEEP","value":"yes"}],"resources":{"requests":{"cpu":"250m"}},"readinessProbe":{"httpGet":{"path":"/ready","port":8080}}},{"name":"sidecar","image":"example.invalid/sidecar:v1"}],"initContainers":[{"name":"init","image":"example.invalid/init:v1"}]}}}
JSON
kubectl apply --validate=strict -f "$work_directory/template.json"
python3 - "$work_directory/template.json" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
obj = json.loads(path.read_text())
obj['template']['spec']['containers'][0]['image'] = 'example.invalid/web:v2'
obj['template']['spec']['containers'].reverse()
path.write_text(json.dumps(obj))
PY
kubectl apply --validate=strict -f "$work_directory/template.json"
kill "$server_pid"
wait "$server_pid"
server_pid=
start_server
kubectl -n template-smoke get podtemplate web -o json >"$work_directory/observed.json"
python3 - "$work_directory/observed.json" <<'PY'
import json
import sys
obj = json.load(open(sys.argv[1]))
containers = obj['template']['spec']['containers']
assert [item['name'] for item in containers] == ['sidecar', 'main']
assert containers[1]['image'] == 'example.invalid/web:v2'
assert containers[1]['env'][0] == {'name': 'KEEP', 'value': 'yes'}
assert containers[1]['resources']['requests']['cpu'] == '250m'
PY
kubectl -n template-smoke get podtemplates --chunk-size=1
kubectl -n template-smoke delete podtemplates -l app=api-smoke
[ "$(kubectl -n template-smoke get podtemplates -o jsonpath='{.items}')" = '[]' ]
echo "PodTemplate kubectl apply, ordering, validation and restart checks passed"
