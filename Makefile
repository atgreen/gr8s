# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
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

LISP_SOURCES := $(shell find src tests -type f -name '*.lisp') $(wildcard schema/*.json) gr8s.asd
NODE_PROTOCOL_PROTO := proto/gr8s/node/v1/node.proto
NODE_PROTOCOL_LISP := src/generated/node-v1-generated.lisp
TEST_EVAL := --eval '(require :asdf)' --eval '(asdf:test-system :gr8s)'

.PHONY: test-raft-snapshots test-raft-checkpoint-memory test-pod-transactions test-pod-transaction-memory test-core-recovery test-core-recovery-memory test-patches test-live-patching all help containerd-bundle generate-protocol test-protocol-generation test test-containerd test-whistler-cni test-routed-network test-vxlan-network test-agent-network test-node-topology test-endpoint-policy test-endpoint-policy-kernel test-service-lb smoke-service-lb smoke-service-lb-agent test-core-api test-install-lifecycle check smoke smoke-two-node run kubeconfig notices native clean

all: native

containerd-bundle:
	scripts/install-containerd.sh build/containerd

help:
	@echo "gr8s targets:"
	@echo "  containerd-bundle Build and verify pinned containerd, runc, and CNI binaries"
	@echo "  generate-protocol Generate Common Lisp node-protocol bindings"
	@echo "  test-protocol-generation Verify standalone protocol generation from a clean output"
	@echo "  test          Run the unit and HTTP test suite"
	@echo "  test-live-patching Test signed in-process upgrades across three fake-runtime control planes"
	@echo "  test-pod-transactions Test per-Pod consensus writes, conflicts, checkpoints and failover"
	@echo "  test-pod-transaction-memory Update a large Pod population within a 384 MiB heap"
	@echo "  test-raft-snapshots Test snapshot durability, chunk retry, mTLS catch-up and handoff"
	@echo "  test-raft-checkpoint-memory Reclaim Raft WAL history and recover its tail within a 384 MiB heap"
	@echo "  test-core-recovery Test journal recovery, corruption detection, and history budgets"
	@echo "  test-core-recovery-memory Recover a 512 MiB journal within a 384 MiB Lisp heap"
	@echo "  test-core-api Verify ConfigMap/Secret kubectl workflows and restart persistence"
	@echo "  test-install-lifecycle Verify rootless install, upgrade, cleanup, and uninstall contracts"
	@echo "  test-containerd Include the live CRI/containerd integration tests"
	@echo "  test-routed-network Test native routed veths in isolated user/network namespaces"
	@echo "  test-vxlan-network Test two-node VXLAN and routed Pod connectivity"
	@echo "  test-agent-network Test agent CNI IPC, IPAM recovery, and Pod DNS"
	@echo "  test-node-topology Test live node snapshots, VXLAN, and route recovery"
	@echo "  test-whistler-cni Test the chained Whistler TC/eBPF CNI plugin"
	@echo "  test-service-lb Load/attach/pin the ClusterIP socket LB on a real kernel (sudo)"
	@echo "  test-service-lb-program Execute Service socket bytecode across interrupted map updates"
	@echo "  test-service-packet-program Execute TC Service translation, checksum, and capacity tests"
	@echo "  test-service-packet-gc Execute bounded flow reclamation and capacity recovery tests"
	@echo "  test-service-packet-guard Execute Service/source-validation/policy/routing stage tests"
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

$(NODE_PROTOCOL_LISP): $(NODE_PROTOCOL_PROTO) scripts/generate-node-protocol.lisp src/generated/package.lisp
	$(SBCL) --noinform --non-interactive --load scripts/generate-node-protocol.lisp

test-protocol-generation:
	scripts/test-node-protocol-generation.sh

test-patches: generate-protocol
	$(SBCL) --noinform --non-interactive --eval '(require :asdf)' --eval '(asdf:test-system "gr8s/patch-tests")'

test-pod-transactions: generate-protocol
	$(SBCL) --noinform --non-interactive --eval '(require :asdf)' --eval '(asdf:load-system "gr8s/tests")' --eval '(dolist (suite (quote (gr8s/tests::pod-transactions gr8s/tests::ha-pod-failover))) (unless (fiveam:run! suite) (uiop:quit 1)))'

test-pod-transaction-memory:
	$(SBCL) --dynamic-space-size 384 --noinform --non-interactive --load scripts/test-pod-transaction-memory.lisp

test-raft-snapshots: generate-protocol
	$(SBCL) --noinform --non-interactive --eval '(require :asdf)' --eval '(asdf:load-system "gr8s/tests")' --eval '(unless (fiveam:run! (quote gr8s/tests::raft-snapshot)) (uiop:quit 1))'

test-raft-checkpoint-memory:
	$(SBCL) --dynamic-space-size 384 --noinform --non-interactive --load scripts/test-raft-checkpoint-memory.lisp

test-core-recovery: generate-protocol
	$(SBCL) --noinform --non-interactive --eval '(require :asdf)' --eval '(asdf:load-system "gr8s/tests")' --eval '(unless (fiveam:run! (quote gr8s/tests::core-recovery)) (uiop:quit 1))'

test-core-recovery-memory:
	$(SBCL) --dynamic-space-size 384 --noinform --non-interactive --load scripts/test-core-recovery-memory.lisp

test-live-patching:
	python3 scripts/test-live-patching.py

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
WHISTLER_FIXTURE_SOURCES := $(wildcard ocicl/whistler-*/src/*.lisp ocicl/whistler-*/src/loader/*.lisp)
build/gr8s-endpoint-test.json build/gr8s-service-test.json \
build/gr8s-service-packet-test.json build/gr8s-service-packet-gc-test.json \
build/gr8s-service-packet-guard-test.json build/gr8s-service-nat-test.json: $(WHISTLER_FIXTURE_SOURCES)

build/gr8s-endpoint-test.json: src/network/egress-guard-program.lisp src/network/egress-guard.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform --script scripts/compile-endpoint-policy-fixture.lisp $@

test-endpoint-policy: build/gr8s-endpoint-test.json
	python3 scripts/test-endpoint-policy.py $<

# Execute the socket LB bytecode across interrupted Service map updates.
build/gr8s-service-test.json: src/network/service-lb-program.lisp src/network/service-lb.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform --script scripts/compile-endpoint-policy-fixture.lisp $@ service-lb

.PHONY: test-service-lb-program
test-service-lb-program: build/gr8s-service-test.json
	python3 scripts/test-service-lb-program.py $<

build/gr8s-service-packet-test.json: src/network/service-packet-program.lisp src/network/service-lb-program.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform --script scripts/compile-endpoint-policy-fixture.lisp $@ service-packet-lb

.PHONY: test-service-packet-program
test-service-packet-program: build/gr8s-service-packet-test.json
	python3 scripts/test-service-packet-program.py $<

build/gr8s-service-nat-test.json: src/network/service-nat-program.lisp src/network/service-packet-program.lisp src/network/service-lb-program.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform --script scripts/compile-endpoint-policy-fixture.lisp $@ service-nat

.PHONY: test-service-nat
test-service-nat: build/gr8s-service-nat-test.json
	python3 scripts/test-service-nat.py $<

build/gr8s-legacy-service-packet-guard-test.json: scripts/compile-legacy-service-packet-guard-fixture.lisp scripts/compile-endpoint-policy-fixture.lisp tests/fixtures/service-packet-pre-reservation.lisp $(wildcard src/network/*.lisp) gr8s.asd $(WHISTLER_FIXTURE_SOURCES)
	sbcl --noinform --script scripts/compile-legacy-service-packet-guard-fixture.lisp $@ service-packet-guard

TCP_CLIENT_LDFLAGS ?= -static
build/service-tcp-client: scripts/service-tcp-client.c
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror $(TCP_CLIENT_LDFLAGS) $< -o $@

.PHONY: test-service-tcp-state
test-service-tcp-state: build/gr8s-service-packet-test.json build/gr8s-service-packet-gc-test.json
	python3 scripts/test-service-tcp-state.py $^

build/gr8s-service-packet-gc-test.json: src/network/service-packet-program.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform --script scripts/compile-endpoint-policy-fixture.lisp $@ service-packet-gc

.PHONY: test-service-packet-gc
test-service-packet-gc: build/gr8s-service-packet-test.json build/gr8s-service-packet-gc-test.json
	python3 scripts/test-service-packet-gc.py $^

build/gr8s-service-packet-guard-test.json: src/network/service-packet-program.lisp src/network/egress-guard-program.lisp src/network/egress-guard.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform --script scripts/compile-endpoint-policy-fixture.lisp $@ service-packet-guard

.PHONY: test-service-packet-guard
test-service-packet-guard: build/gr8s-service-packet-guard-test.json
	python3 scripts/test-service-packet-guard.py $<

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

test-install-lifecycle:
	python3 scripts/test_install_lifecycle.py
	python3 scripts/test_uninstall_lifecycle.py

test-whistler-cni: containerd-bundle test

check: containerd-bundle test-protocol-generation test-whistler-cni test-endpoint-policy test-service-lb-program test-service-packet-program test-service-nat test-service-packet-guard test-service-packet-gc test-service-tcp-state test-install-lifecycle
	sh -n install.sh gr8s-killall.sh gr8s-uninstall.sh \
	  scripts/gr8s scripts/install-containerd.sh scripts/collect-notices.sh \
	  scripts/verify-static-runtime.sh scripts/smoke.sh scripts/test-core-api.sh
	scripts/verify-static-runtime.sh build/containerd

smoke:
	@if [ "$$(id -u)" -eq 0 ]; then \
	  echo "Do not run make smoke with sudo; run it as your normal user." >&2; \
	  exit 1; \
	fi
	$(MAKE) native
	sudo env PATH="$(PATH)" GR8S_DISABLE_SERVICE_LB="$(GR8S_DISABLE_SERVICE_LB)" GR8S_SMOKE_POD_CIDR="$(GR8S_SMOKE_POD_CIDR)" scripts/smoke.sh

# Run the smoke script assuming we are already root (invoked as `sudo make
# smoke-root SMOKE_PATH=...`), for environments where sudo is scoped to make.
# Build the native image first as your normal user: `make native`.
smoke-root:
	env PATH="$(SMOKE_PATH)" GR8S_DISABLE_SERVICE_LB="$(GR8S_DISABLE_SERVICE_LB)" GR8S_SMOKE_POD_CIDR="$(GR8S_SMOKE_POD_CIDR)" scripts/smoke.sh

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

notices:
	scripts/collect-notices.sh NOTICES

native: build/gr8s

build/gr8s: containerd-bundle generate-protocol scripts/build-native.lisp $(LISP_SOURCES)
	$(SBCL) --noinform --non-interactive --load scripts/build-native.lisp

clean:
	rm -rf -- build
