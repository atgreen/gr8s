# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: MIT
#
# Purpose:
# Define reproducible developer entry points for generating protocol bindings,
# running unit and privileged networking tests, assembling the embedded runtime,
# and producing the dumped gr8s executable.

SBCL ?= sbcl
STATE_DIR ?= /tmp/gr8s-state
PORT ?= 8080
RUNTIME ?= containerd
CONTAINERD_MODE ?= managed
CONTAINERD_EXECUTABLE ?= $(CURDIR)/build/containerd/bin/containerd
CONTAINERD_OCI_RUNTIME ?= $(CURDIR)/build/containerd/bin/runc
CONTAINERD_SOCKET ?= /run/containerd/containerd.sock
CONTAINERD_LOG_ROOT ?= /var/log/gr8s/pods/
KUBECONFIG ?= /tmp/gr8s.kubeconfig

LISP_SOURCES := $(wildcard src/*.lisp) $(wildcard tests/*.lisp) $(wildcard schema/*.json) gr8s.asd
NODE_PROTOCOL_PROTO := proto/gr8s/node/v1/node.proto
NODE_PROTOCOL_LISP := src/node-v1-generated.lisp
TEST_EVAL := --eval '(require :asdf)' --eval '(asdf:test-system :gr8s)'

.PHONY: all help containerd-bundle generate-protocol test test-containerd test-whistler-cni test-routed-network test-vxlan-network test-agent-network test-node-topology test-endpoint-policy test-endpoint-policy-kernel test-service-lb smoke-service-lb smoke-service-lb-agent test-core-api check smoke smoke-two-node run kubeconfig native clean

all: native

containerd-bundle:
	scripts/install-containerd.sh build/containerd

help:
	@echo "gr8s targets:"
	@echo "  containerd-bundle Build and verify pinned containerd, runc, and CNI binaries"
	@echo "  generate-protocol Generate Common Lisp node-protocol bindings"
	@echo "  test          Run the unit and HTTP test suite"
	@echo "  test-core-api Verify ConfigMap/Secret kubectl workflows and restart persistence"
	@echo "  test-containerd Include the live CRI/containerd integration tests"
	@echo "  test-routed-network Test native routed veths in isolated user/network namespaces"
	@echo "  test-vxlan-network Test two-node VXLAN and routed Pod connectivity"
	@echo "  test-agent-network Test agent CNI IPC, IPAM recovery, and Pod DNS"
	@echo "  test-node-topology Test live node snapshots, VXLAN, and route recovery"
	@echo "  test-whistler-cni Test the chained Whistler TC/eBPF CNI plugin"
	@echo "  test-service-lb Load/attach/pin the ClusterIP socket LB on a real kernel (sudo)"
	@echo "  smoke-service-lb End-to-end: redirect an unrouted ClusterIP connect to backends (sudo)"
	@echo "  smoke-service-lb-agent End-to-end agent path: Service+EndpointSlice -> redirect (sudo)"
	@echo "  check         Syntax-check scripts and run tests"
	@echo "  smoke         Run kubectl -> gr8s -> containerd end to end"
	@echo "  smoke-two-node Test real containerd Pods across two isolated agent nodes"
	@echo "  run           Start gr8s (override STATE_DIR, PORT, RUNTIME, KUBECONFIG)"
	@echo "  kubeconfig    Write KUBECONFIG for the configured PORT"
	@echo "  native        Build the dumped native executable at build/gr8s"
	@echo "  clean         Remove build outputs"

generate-protocol: $(NODE_PROTOCOL_LISP)

$(NODE_PROTOCOL_LISP): $(NODE_PROTOCOL_PROTO) scripts/generate-node-protocol.lisp
	$(SBCL) --noinform --non-interactive --load scripts/generate-node-protocol.lisp

test: generate-protocol
	$(SBCL) --noinform --non-interactive $(TEST_EVAL)

test-containerd:
	GR8S_RUN_CONTAINERD_TESTS=1 GR8S_RUN_CONTAINERD_SANDBOX_TESTS=1 \
	GR8S_RUN_CONTAINERD_LIFECYCLE_TESTS=1 \
	GR8S_CONTAINERD_SOCKET="$(CONTAINERD_SOCKET)" \
	$(SBCL) --noinform --non-interactive $(TEST_EVAL)

test-routed-network:
	unshare -Urn $(SBCL) --noinform --non-interactive --load scripts/test-routed-network.lisp

test-vxlan-network:
	unshare -Urn $(SBCL) --noinform --non-interactive --load scripts/test-vxlan-network.lisp

test-agent-network:
	unshare -Urn $(SBCL) --noinform --non-interactive --load scripts/test-agent-network.lisp

test-node-topology:
	unshare -Urn $(SBCL) --noinform --non-interactive --load scripts/test-node-topology.lisp

# The egress guard is JIT-compiled in-process; the fixture is its raw bytecode +
# map descriptors as JSON, not an ELF object.
build/gr8s-endpoint-test.json: src/egress-guard-program.lisp src/egress-guard.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform --script scripts/compile-endpoint-policy-fixture.lisp $@

test-endpoint-policy: build/gr8s-endpoint-test.json
	python3 scripts/test-endpoint-policy.py $<

# Real-root verification that the Service LB JIT-compiles, loads, attaches to a
# cgroup, pins its maps, and round-trips entries through the kernel. No ELF.
test-service-lb:
	sudo $(SBCL) --noinform --non-interactive --load scripts/test-service-lb.lisp

# Real-root end-to-end: a Pod connect(2) to an unrouted ClusterIP is redirected
# in-kernel to a backend, and repeated connects spread across backends.
smoke-service-lb:
	sudo $(SBCL) --noinform --non-interactive --load scripts/smoke-service-lb.lisp

# Real-root end-to-end of the AGENT path: converge a Service + EndpointSlice
# into the LB maps and redirect an unrouted ClusterIP connect to backends.
smoke-service-lb-agent:
	sudo $(SBCL) --noinform --non-interactive --load scripts/smoke-service-lb-agent.lisp

test-endpoint-policy-kernel: build/gr8s-endpoint-test.json
	python3 scripts/test-endpoint-policy.py $< --kernel

test-core-api:
	scripts/test-core-api.sh

test-whistler-cni: containerd-bundle test

check: containerd-bundle test-whistler-cni test-endpoint-policy
	sh -n scripts/gr8s scripts/gr8s-native scripts/install-containerd.sh \
	  scripts/verify-static-runtime.sh scripts/smoke.sh scripts/test-core-api.sh
	scripts/verify-static-runtime.sh build/containerd

smoke:
	@if [ "$$(id -u)" -eq 0 ]; then \
	  echo "Do not run make smoke with sudo; run it as your normal user." >&2; \
	  exit 1; \
	fi
	$(MAKE) native
	sudo env PATH="$(PATH)" GR8S_DISABLE_SERVICE_LB="$(GR8S_DISABLE_SERVICE_LB)" scripts/smoke.sh

# Run the smoke script assuming we are already root (invoked as `sudo make
# smoke-root SMOKE_PATH=...`), for environments where sudo is scoped to make.
# Build the native image first as your normal user: `make native`.
smoke-root:
	env PATH="$(SMOKE_PATH)" GR8S_DISABLE_SERVICE_LB="$(GR8S_DISABLE_SERVICE_LB)" scripts/smoke.sh

smoke-two-node:
	@if [ "$$(id -u)" -eq 0 ]; then \
	  echo "Run make smoke-two-node as your normal user." >&2; \
	  exit 1; \
	fi
	$(MAKE) native
	sudo env PATH="$(PATH)" python3 scripts/smoke-two-node.py

run: containerd-bundle
	scripts/gr8s serve --state-directory "$(STATE_DIR)" --port "$(PORT)" \
	  --runtime "$(RUNTIME)" --containerd-mode "$(CONTAINERD_MODE)" \
	  --containerd-executable "$(CONTAINERD_EXECUTABLE)" \
	  --containerd-oci-runtime "$(CONTAINERD_OCI_RUNTIME)" \
	  --containerd-socket "$(CONTAINERD_SOCKET)" \
	  --containerd-log-root "$(CONTAINERD_LOG_ROOT)" \
	  --kubeconfig "$(KUBECONFIG)"

kubeconfig:
	scripts/gr8s kubeconfig --output "$(KUBECONFIG)" \
	  --server "http://127.0.0.1:$(PORT)"

native: build/gr8s

build/gr8s: build/gr8s.bin scripts/gr8s-native
	cp -f scripts/gr8s-native build/gr8s
	chmod +x build/gr8s

build/gr8s.bin: containerd-bundle generate-protocol scripts/build-native.lisp $(LISP_SOURCES)
	$(SBCL) --noinform --non-interactive --load scripts/build-native.lisp

clean:
	rm -rf -- build
