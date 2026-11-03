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

LISP_SOURCES := $(wildcard src/*.lisp) $(wildcard tests/*.lisp) gr8s.asd
NODE_PROTOCOL_PROTO := proto/gr8s/node/v1/node.proto
NODE_PROTOCOL_LISP := src/node-v1-generated.lisp
TEST_EVAL := --eval '(require :asdf)' --eval '(asdf:test-system :gr8s)'

.PHONY: all help containerd-bundle generate-protocol test test-containerd test-podman test-whistler-cni check smoke run kubeconfig native clean

all: native

containerd-bundle:
	scripts/install-containerd.sh build/containerd

help:
	@echo "gr8s targets:"
	@echo "  containerd-bundle Build and verify pinned containerd, runc, and CNI binaries"
	@echo "  generate-protocol Generate Common Lisp node-protocol bindings"
	@echo "  test          Run the unit and HTTP test suite"
	@echo "  test-containerd Include the live CRI/containerd integration tests"
	@echo "  test-podman   Include the disposable rootless Podman integration test"
	@echo "  test-whistler-cni Test the chained Whistler TC/eBPF CNI plugin"
	@echo "  check         Syntax-check scripts and run tests"
	@echo "  smoke         Run kubectl -> gr8s -> containerd end to end"
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

test-podman:
	GR8S_RUN_PODMAN_TESTS=1 $(SBCL) --noinform --non-interactive $(TEST_EVAL)

test-whistler-cni: containerd-bundle test

check: containerd-bundle test-whistler-cni
	sh -n scripts/gr8s scripts/gr8s-native scripts/install-containerd.sh \
	  scripts/verify-static-runtime.sh scripts/smoke.sh
	scripts/verify-static-runtime.sh build/containerd

smoke:
	@if [ "$$(id -u)" -eq 0 ]; then \
	  echo "Do not run make smoke with sudo; run it as your normal user." >&2; \
	  exit 1; \
	fi
	$(MAKE) native
	sudo env PATH="$(PATH)" scripts/smoke.sh

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
