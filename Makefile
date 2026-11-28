# SPDX-FileCopyrightText: 2026 Anthony Green
# SPDX-License-Identifier: Apache-2.0
#
# Purpose:
# Define reproducible developer entry points for generating protocol bindings,
# running unit and privileged networking tests, assembling the embedded runtime,
# and producing the dumped gr8s executable.

SBCL ?= sbcl
LISP_BOOTSTRAP := --no-sysinit --no-userinit --load scripts/bootstrap.lisp
STATE_DIR ?= /tmp/gr8s-state
PORT ?= 6443
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

# Dependencies are pinned in ocicl.csv and restored on demand with `ocicl
# install`; the ocicl/ tree itself is not vendored. The stamp reinstalls
# whenever the lockfile changes and is an order-only prerequisite of every
# target that loads a Lisp system, so a fresh checkout builds without a manual
# install step.
OCICL ?= ocicl
OCICL_STAMP := ocicl/.ocicl-installed

.PHONY: xterm-assets graph-assets dashboard-assets-from-source dashboard-assets-compress test-raft-snapshots test-raft-checkpoint-memory test-pod-transactions test-pod-transaction-memory test-core-recovery test-core-recovery-memory all help containerd-bundle dashboard-assets generate-protocol lint check-undefined test-protocol-generation test test-containerd test-whistler-cni test-routed-network test-vxlan-network test-agent-network test-node-topology test-endpoint-policy test-endpoint-policy-kernel test-service-lb smoke-service-lb smoke-service-lb-agent test-core-api test-install-lifecycle check smoke smoke-two-node run kubeconfig notices native clean deps

all: native

deps: $(OCICL_STAMP)

$(OCICL_STAMP): ocicl.csv
	$(OCICL) install
	@mkdir -p ocicl && touch $@

# Order-only: restore pinned dependencies before any target that loads a Lisp
# system. Targets that reach a Lisp load through generate-protocol inherit the
# stamp via $(NODE_PROTOCOL_LISP) below.
$(NODE_PROTOCOL_LISP) build/gr8s: | $(OCICL_STAMP)

test-pod-transaction-memory test-raft-checkpoint-memory test-core-recovery-memory \
test-containerd test-routed-network test-vxlan-network test-agent-network \
test-node-topology test-service-lb smoke-service-lb smoke-service-lb-agent: | $(OCICL_STAMP)

build/gr8s-endpoint-test.json build/gr8s-service-test.json \
build/gr8s-service-packet-test.json build/gr8s-service-packet-gc-test.json \
build/gr8s-service-packet-guard-test.json build/gr8s-service-nat-test.json \
build/gr8s-service-nat-policy-test.json build/gr8s-service-nat-guard-test.json \
build/gr8s-service-wire-test.json build/gr8s-legacy-service-packet-guard-test.json: | $(OCICL_STAMP)

# Represent the containerd bundle by its primary output binary so a tree that
# already has it built neither re-runs the installer nor relinks anything
# downstream. install-containerd.sh is itself idempotent, but making it a real
# file target lets make skip it entirely when nothing changed. The pinned
# containerd/runc/CNI versions live in the script, so bumping one changes the
# script's mtime and rebuilds the bundle; containerd-bundle stays a convenience
# alias for the file.
CONTAINERD_BUNDLE_MARKER := build/containerd/bin/containerd

$(CONTAINERD_BUNDLE_MARKER): scripts/install-containerd.sh
	scripts/install-containerd.sh build/containerd

containerd-bundle: $(CONTAINERD_BUNDLE_MARKER)

# Embed the Headlamp frontend into the dashboard. The assets are a hard build
# dependency of build/gr8s -- a gr8s without its dashboard is not a valid build
# (podster-22l). The default source is the digest-pinned upstream container
# image (no npm needed, same pinning discipline as the containerd bundle);
# dashboard-assets-from-source builds from a local Headlamp checkout instead,
# for hacking on Headlamp itself (git clone https://github.com/kubernetes-sigs/headlamp).
HEADLAMP_IMAGE ?= ghcr.io/headlamp-k8s/headlamp@sha256:8a0ef97527544baa2b35825940ddf4db6e2d09c30cd5aa31fd269ff604cc8b75
# ^ v0.46.0
DASHBOARD_MARKER := assets/dashboard/index.html
HEADLAMP ?= $(HOME)/git/headlamp

$(DASHBOARD_MARKER):
	rm -rf assets/dashboard build/headlamp-rootfs
	mkdir -p assets/dashboard build/headlamp-rootfs
	tool=$$(command -v podman || command -v docker) && \
	  cid=$$("$$tool" create "$(HEADLAMP_IMAGE)") && \
	  { "$$tool" export "$$cid" | tar -x -C build/headlamp-rootfs headlamp/frontend; \
	    status=$$?; "$$tool" rm "$$cid" >/dev/null; exit $$status; }
	cd build/headlamp-rootfs/headlamp/frontend && \
	  find . -type f ! -name '*.br' ! -name '*.map' -print0 | \
	  cpio -pd0 --quiet "$(CURDIR)/assets/dashboard"
	rm -rf build/headlamp-rootfs
	$(MAKE) dashboard-assets-compress
	@# The embedder reads assets at compile time; make sure a cached FASL from an
	@# asset-less build cannot survive a fresh asset tree.
	touch src/apiserver/dashboard-assets.lisp

dashboard-assets:
	rm -rf assets/dashboard
	$(MAKE) $(DASHBOARD_MARKER)
	$(MAKE) xterm-assets
	$(MAKE) graph-assets

# xterm.js (MIT) for the dashboard's Agent tab: the published npm tarballs, pinned
# by version and SHA-256; only the browser bundles and the stylesheet are kept.
XTERM_VERSION ?= 6.0.0
XTERM_SHA256 ?= 908e66e04af6c8dc6b00dd3b54de088e2e81e5ed866284fd6c2fb3c2d1c7a3f6
XTERM_FIT_VERSION ?= 0.11.0
XTERM_FIT_SHA256 ?= 26003b4517a132b64e4ff228fd88a5fda3fff5e606c76093f6dcff772e9ecec0
XTERM_MARKER := assets/xterm/xterm.js

$(XTERM_MARKER):
	rm -rf assets/xterm build/xterm
	mkdir -p assets/xterm build/xterm
	curl -fsSL -o build/xterm/xterm.tgz \
	  https://registry.npmjs.org/@xterm/xterm/-/xterm-$(XTERM_VERSION).tgz
	curl -fsSL -o build/xterm/addon-fit.tgz \
	  https://registry.npmjs.org/@xterm/addon-fit/-/addon-fit-$(XTERM_FIT_VERSION).tgz
	echo "$(XTERM_SHA256)  build/xterm/xterm.tgz" | sha256sum -c --quiet
	echo "$(XTERM_FIT_SHA256)  build/xterm/addon-fit.tgz" | sha256sum -c --quiet
	tar -xzf build/xterm/xterm.tgz -O package/css/xterm.css > assets/xterm/xterm.css
	tar -xzf build/xterm/addon-fit.tgz -O package/lib/addon-fit.js > assets/xterm/addon-fit.js
	tar -xzf build/xterm/xterm.tgz -O package/LICENSE > assets/xterm/xterm.LICENSE.txt
	tar -xzf build/xterm/addon-fit.tgz -O package/LICENSE > assets/xterm/addon-fit.LICENSE.txt
	tar -xzf build/xterm/xterm.tgz -O package/lib/xterm.js > build/xterm/xterm.js
	mv build/xterm/xterm.js $(XTERM_MARKER)
	rm -rf build/xterm
	touch src/server/dashboard-agent.lisp

xterm-assets:
	rm -rf assets/xterm
	$(MAKE) $(XTERM_MARKER)

# Cytoscape.js and its fcose and dagre layouts (MIT) for the dashboard's Network tab:
# the published npm tarballs, pinned by version and SHA-256 (name version sha256 file).
GRAPH_PACKAGES := \
  cytoscape 3.30.2 8e9bfaaf9f5f461642355b0d17c6cf1d0d58c5cb9e00ac983e2d242fd1cfb928 dist/cytoscape.min.js \
  layout-base 2.0.1 34165e46d8c4b9d719a592e39a60fa5f7324c21a3edd02733e1116b17013defd layout-base.js \
  cose-base 2.2.0 612ec91a30b7f2dc158cca4846eeea1b7f89a97fc672951da3c1932107de6da8 cose-base.js \
  cytoscape-fcose 2.2.0 4e1f30e1821fdd4b66f21043c8ea40a8e2ad0ba75e4ccdd2c24d289cf5595432 cytoscape-fcose.js \
  dagre 0.8.5 ffaf576ea24546aed65aa2bed174d77fe4fbfe7985aa6c4a7cd0293c1994c4ed dist/dagre.min.js \
  cytoscape-dagre 2.5.0 cbb58d8e719b0c0ed891a140ab050af8aac35a11b0b51f0b4ec46238fce47577 cytoscape-dagre.js
# The Network tab's icons and font: software logos from Simple Icons (CC0), each in its
# brand colour; generic icons from Lucide (ISC); Inter (OFL) in three weights.
SIMPLE_ICONS_VERSION ?= 16.37.0
SIMPLE_ICONS_SHA256 ?= cd9faf0e6faa8a8fdd15e9632ab4c86fcae4b986fe552b87673149847f2f671d
SIMPLE_ICONS := postgresql mysql mariadb redis mongodb apachekafka rabbitmq elasticsearch opensearch \
  grafana prometheus nginx envoyproxy vault openbao etcd minio kubernetes
LUCIDE_VERSION ?= 1.71.0
LUCIDE_SHA256 ?= c53ba25989d0893250e1cb0a949e4ec04a4d9ed92bcc3f68246b2e1e31b78815
LUCIDE_ICONS := server globe network box layers database boxes timer split router archive hard-drive key-round door-open users
INTER_VERSION ?= 5.3.0
INTER_SHA256 ?= 02034af8d41dcc67ac8eab88f642e129bb8a2e8922abf30229c32725f54d8fd6
GRAPH_MARKER := assets/graph/cytoscape.js

$(GRAPH_MARKER):
	rm -rf assets/graph build/graph
	mkdir -p assets/graph build/graph
	set -e; set -- $(GRAPH_PACKAGES); while [ $$# -gt 0 ]; do \
	  curl -fsSL -o build/graph/$$1.tgz https://registry.npmjs.org/$$1/-/$$1-$$2.tgz; \
	  echo "$$3  build/graph/$$1.tgz" | sha256sum -c --quiet; \
	  tar -xzf build/graph/$$1.tgz -O package/$$4 > assets/graph/$$1.js; \
	  tar -xzf build/graph/$$1.tgz -O package/LICENSE > assets/graph/$$1.LICENSE.txt; \
	  shift 4; done
	mkdir -p assets/graph/icons assets/graph/fonts
	curl -fsSL -o build/graph/simple-icons.tgz https://registry.npmjs.org/simple-icons/-/simple-icons-$(SIMPLE_ICONS_VERSION).tgz
	echo "$(SIMPLE_ICONS_SHA256)  build/graph/simple-icons.tgz" | sha256sum -c --quiet
	tar -xzf build/graph/simple-icons.tgz -O package/data/simple-icons.json > build/graph/simple-icons.json
	set -e; for icon in $(SIMPLE_ICONS); do \
	  tar -xzf build/graph/simple-icons.tgz -O package/icons/$$icon.svg > assets/graph/icons/$$icon.svg; \
	  colour=$$(python3 -c "import json,sys; d=json.load(open('build/graph/simple-icons.json')); d=d['icons'] if isinstance(d,dict) else d; print(next(i['hex'] for i in d if i.get('slug', i['title'].lower().replace(' ', '')) == sys.argv[1]))" $$icon); \
	  sed -i "s|<svg |<svg fill=\"#$$colour\" |" assets/graph/icons/$$icon.svg; done
	tar -xzf build/graph/simple-icons.tgz -O package/LICENSE.md > assets/graph/simple-icons.LICENSE.txt
	curl -fsSL -o build/graph/lucide-static.tgz https://registry.npmjs.org/lucide-static/-/lucide-static-$(LUCIDE_VERSION).tgz
	echo "$(LUCIDE_SHA256)  build/graph/lucide-static.tgz" | sha256sum -c --quiet
	set -e; for icon in $(LUCIDE_ICONS); do \
	  tar -xzf build/graph/lucide-static.tgz -O package/icons/$$icon.svg > assets/graph/icons/lucide-$$icon.svg; done
	tar -xzf build/graph/lucide-static.tgz -O package/LICENSE > assets/graph/lucide-static.LICENSE.txt
	curl -fsSL -o build/graph/inter.tgz https://registry.npmjs.org/@fontsource/inter/-/inter-$(INTER_VERSION).tgz
	echo "$(INTER_SHA256)  build/graph/inter.tgz" | sha256sum -c --quiet
	set -e; for weight in 400 500 600; do \
	  tar -xzf build/graph/inter.tgz -O package/files/inter-latin-$$weight-normal.woff2 > assets/graph/fonts/inter-$$weight.woff2; done
	tar -xzf build/graph/inter.tgz -O package/LICENSE > assets/graph/inter.LICENSE.txt
	rm -rf build/graph
	touch src/server/dashboard-network.lisp

graph-assets:
	rm -rf assets/graph
	$(MAKE) $(GRAPH_MARKER)

dashboard-assets-from-source:
	npm --prefix "$(HEADLAMP)/frontend" ci
	npm --prefix "$(HEADLAMP)/frontend" run build
	rm -rf assets/dashboard
	mkdir -p assets/dashboard
	cd "$(HEADLAMP)/frontend/build" && \
	  find . -type f ! -name '*.br' ! -name '*.map' -print0 | \
	  cpio -pd0 --quiet "$(CURDIR)/assets/dashboard"
	$(MAKE) dashboard-assets-compress
	touch src/apiserver/dashboard-assets.lisp

dashboard-assets-compress:
	@# Pre-gzip the voluminous text assets (JS/CSS/JSON/SVG/WASM) so the image
	@# embeds and the browser receives them compressed; each original is replaced
	@# by its .gz, which dashboard-assets.lisp serves with Content-Encoding: gzip.
	@# -n keeps the build reproducible (no name/mtime in the gzip header). HTML is
	@# left raw because index.html is rewritten with the session base-url on serve.
	cd "$(CURDIR)/assets/dashboard" && \
	  find . -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.css' \
	    -o -name '*.json' -o -name '*.svg' -o -name '*.txt' -o -name '*.wasm' \) -print0 | \
	  xargs -0 -r gzip -9 -n
	@echo "embedded $$(find assets/dashboard -type f | wc -l) dashboard asset files ($$(du -sh assets/dashboard | cut -f1))"

.PHONY: gr8 test-gr8
gr8:
	cd gr8 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../build/gr8 ./cmd/gr8
	cd gr8 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o ../build/gr8s-kms ./cmd/gr8s-kms

test-gr8:
	cd gr8 && go vet ./... && go test ./...

help:
	@echo "gr8s targets:"
	@echo "  containerd-bundle Build and verify pinned containerd, runc, and CNI binaries"
	@echo "  dashboard-assets Refresh the embedded Headlamp frontend from the pinned image (always built in)"
	@echo "  generate-protocol Generate Common Lisp node-protocol bindings"
	@echo "  test-protocol-generation Verify standalone protocol generation from a clean output"
	@echo "  lint             ocicl lint over src, tests and scripts, with .ocicl-lint.conf's exceptions"
	@echo "  test          Run the unit and HTTP test suite"
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
	@echo "  gr8           Build build/gr8, which runs a command in a sandboxed local Pod"
	@echo "  test-gr8      Run the gr8 Go tests"
	@echo "  deps          Restore pinned dependencies from ocicl.csv into ocicl/"
	@echo "  clean         Remove build outputs"

generate-protocol: $(NODE_PROTOCOL_LISP)

$(NODE_PROTOCOL_LISP): $(NODE_PROTOCOL_PROTO) scripts/generate-node-protocol.lisp src/generated/package.lisp
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/generate-node-protocol.lisp

test-protocol-generation:
	scripts/test-node-protocol-generation.sh

test-pod-transactions: generate-protocol
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --eval '(require :asdf)' --eval '(asdf:load-system "gr8s/tests")' --eval '(dolist (suite (quote (gr8s/tests::pod-transactions gr8s/tests::ha-pod-failover))) (unless (fiveam:run! suite) (uiop:quit 1)))'

test-pod-transaction-memory:
	$(SBCL) --dynamic-space-size 384 --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/test-pod-transaction-memory.lisp

test-raft-snapshots: generate-protocol
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --eval '(require :asdf)' --eval '(asdf:load-system "gr8s/tests")' --eval '(unless (fiveam:run! (quote gr8s/tests::raft-snapshot)) (uiop:quit 1))'

test-raft-checkpoint-memory:
	$(SBCL) --dynamic-space-size 384 --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/test-raft-checkpoint-memory.lisp

test-core-recovery: generate-protocol
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --eval '(require :asdf)' --eval '(asdf:load-system "gr8s/tests")' --eval '(unless (fiveam:run! (quote gr8s/tests::core-recovery)) (uiop:quit 1))'

test-core-recovery-memory:
	$(SBCL) --dynamic-space-size 384 --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/test-core-recovery-memory.lisp

# ocicl lint, with the exceptions in .ocicl-lint.conf. Every file is named: a directory
# argument doesn't reach its subdirectories.
lint:
	ocicl lint $$(find src tests scripts -name '*.lisp' | sort)

# Recompile gr8s and its tests from source, failing on any undefined function or variable
# the compiler reports in gr8s's own files.
check-undefined: generate-protocol
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --eval '(require :asdf)' --load scripts/check-undefined.lisp

test: generate-protocol
	python3 scripts/test-bootstrap.py
	python3 scripts/test_native_readiness.py
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive $(TEST_EVAL)
	$(MAKE) test-doctor

test-containerd:
	GR8S_RUN_CONTAINERD_TESTS=1 GR8S_RUN_CONTAINERD_SANDBOX_TESTS=1 \
	GR8S_RUN_CONTAINERD_LIFECYCLE_TESTS=1 \
	GR8S_CONTAINERD_SOCKET="$(CONTAINERD_SOCKET)" \
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive $(TEST_EVAL)

test-routed-network:
	unshare -Urn $(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/test-routed-network.lisp

test-vxlan-network:
	unshare -Urn $(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/test-vxlan-network.lisp

test-agent-network:
	unshare -Urn $(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/test-agent-network.lisp

test-node-topology:
	unshare -Urn $(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/test-node-topology.lisp

# The egress guard is JIT-compiled in-process; the fixture is its raw bytecode +
# map descriptors as JSON, not an ELF object.
WHISTLER_FIXTURE_SOURCES := $(wildcard ocicl/whistler-*/src/*.lisp ocicl/whistler-*/src/loader/*.lisp)
build/gr8s-endpoint-test.json build/gr8s-service-test.json \
build/gr8s-service-packet-test.json build/gr8s-service-packet-gc-test.json \
build/gr8s-service-packet-guard-test.json build/gr8s-service-nat-test.json build/gr8s-service-nat-policy-test.json build/gr8s-service-nat-guard-test.json build/gr8s-service-wire-test.json: $(WHISTLER_FIXTURE_SOURCES)

build/gr8s-endpoint-test.json: src/network/egress-guard-program.lisp src/network/egress-guard.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --script scripts/compile-endpoint-policy-fixture.lisp $@

test-endpoint-policy: build/gr8s-endpoint-test.json
	python3 scripts/test-endpoint-policy.py $<

# Execute the socket LB bytecode across interrupted Service map updates.
build/gr8s-service-test.json: src/network/service-lb-program.lisp src/network/service-lb.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --script scripts/compile-endpoint-policy-fixture.lisp $@ service-lb

.PHONY: test-service-lb-program
build/gr8s-egress-steering.json build/gr8s-gateway-steering.json: src/controllers/egress-proxy.lisp src/controllers/gateway-sklookup.lisp scripts/compile-endpoint-policy-fixture.lisp | $(OCICL_STAMP)
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --script scripts/compile-endpoint-policy-fixture.lisp $@ $(patsubst build/gr8s-%.json,%,$@)

.PHONY: test-egress-steering-kernel
# Root in a disposable VM: sk_lookup steering of the egress proxy address (podster-wv1w.2).
test-egress-steering-kernel: build/gr8s-egress-steering.json build/gr8s-gateway-steering.json
	python3 scripts/test-egress-steering.py $^

test-service-lb-program: build/gr8s-service-test.json
	python3 scripts/test-service-lb-program.py $<

build/gr8s-service-packet-test.json: src/network/service-packet-program.lisp src/network/service-lb-program.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --script scripts/compile-endpoint-policy-fixture.lisp $@ service-packet-lb

.PHONY: test-service-packet-program
test-service-packet-program: build/gr8s-service-packet-test.json
	python3 scripts/test-service-packet-program.py $<

build/gr8s-service-nat-test.json: src/network/service-nat-program.lisp src/network/service-packet-program.lisp src/network/service-lb-program.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --script scripts/compile-endpoint-policy-fixture.lisp $@ service-nat

.PHONY: test-service-nat
test-service-nat: build/gr8s-service-nat-test.json
	python3 scripts/test-service-nat.py $<
	python3 scripts/test-service-nat-tcp.py $<
	python3 scripts/test-service-nat-gc.py $<

build/gr8s-service-nat-policy-test.json: src/network/service-nat-policy.lisp src/network/service-nat-program.lisp src/network/egress-guard-program.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --script scripts/compile-endpoint-policy-fixture.lisp $@ service-nat-policy

.PHONY: test-service-nat-policy
test-service-nat-policy: build/gr8s-service-nat-policy-test.json
	python3 scripts/test-service-nat-policy.py $<

build/gr8s-service-nat-guard-test.json: src/network/service-nat-guard.lisp src/network/service-nat-policy.lisp src/network/service-nat-program.lisp src/network/service-packet-program.lisp src/network/egress-guard-program.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --script scripts/compile-endpoint-policy-fixture.lisp $@ service-nat-guard

.PHONY: test-service-nat-guard
test-service-nat-guard: build/gr8s-service-nat-guard-test.json
	python3 scripts/test-service-nat-guard.py $<
	python3 scripts/probe-service-passive-ownership.py $< --risk

build/gr8s-service-wire-test.json: src/network/service-wire.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --script scripts/compile-endpoint-policy-fixture.lisp $@ service-wire

.PHONY: test-service-wire
test-service-wire: build/gr8s-service-wire-test.json
	python3 scripts/test-service-wire.py $<

build/gr8s-legacy-service-packet-guard-test.json: scripts/compile-legacy-service-packet-guard-fixture.lisp scripts/compile-endpoint-policy-fixture.lisp tests/fixtures/service-packet-pre-reservation.lisp $(wildcard src/network/*.lisp) gr8s.asd $(WHISTLER_FIXTURE_SOURCES)
	sbcl --noinform --script scripts/compile-legacy-service-packet-guard-fixture.lisp $@ service-packet-guard

TCP_CLIENT_LDFLAGS ?= -static
build/service-tcp-client: scripts/service-tcp-client.c
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror $(TCP_CLIENT_LDFLAGS) $< -o $@

.PHONY: test-service-tcp-state
test-service-tcp-state: build/gr8s-service-packet-test.json build/gr8s-service-packet-gc-test.json
	python3 scripts/test-service-tcp-state.py $^

build/gr8s-service-packet-gc-test.json: src/network/service-packet-program.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --script scripts/compile-endpoint-policy-fixture.lisp $@ service-packet-gc

.PHONY: test-service-packet-gc
test-service-packet-gc: build/gr8s-service-packet-test.json build/gr8s-service-packet-gc-test.json
	python3 scripts/test-service-packet-gc.py $^

build/gr8s-service-packet-guard-test.json: src/network/service-packet-program.lisp src/network/egress-guard-program.lisp src/network/egress-guard.lisp scripts/compile-endpoint-policy-fixture.lisp
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --script scripts/compile-endpoint-policy-fixture.lisp $@ service-packet-guard

.PHONY: test-service-packet-guard
test-service-packet-guard: build/gr8s-service-packet-guard-test.json
	python3 scripts/test-service-packet-guard.py $<

# Real-root verification that the Service LB JIT-compiles, loads, attaches to a
# cgroup, pins its maps, and round-trips entries through the kernel. No ELF.
test-service-lb:
	sudo $(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/test-service-lb.lisp

# Real-root end-to-end: a Pod connect(2) to an unrouted ClusterIP is redirected
# in-kernel to a backend, and repeated connects spread across backends.
smoke-service-lb:
	sudo $(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/smoke-service-lb.lisp

# Real-root end-to-end of the AGENT path: converge a Service + EndpointSlice
# into the LB maps and redirect an unrouted ClusterIP connect to backends.
smoke-service-lb-agent:
	sudo $(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/smoke-service-lb-agent.lisp

test-endpoint-policy-kernel: build/gr8s-endpoint-test.json
	python3 scripts/test-endpoint-policy.py $< --kernel

test-core-api:
	scripts/test-core-api.sh

test-install-lifecycle:
	python3 scripts/test_runtime_download_errors.py
	python3 scripts/test_install_lifecycle.py
	python3 scripts/test_uninstall_lifecycle.py

test-whistler-cni: containerd-bundle test

.PHONY: test-gateway-conformance-runner
test-gateway-conformance-runner:
	python3 scripts/test_gateway_conformance_runner.py
	sh -n deploy/conformance/run-conformance.sh

check: containerd-bundle test-protocol-generation test-whistler-cni test-endpoint-policy test-service-lb-program test-service-packet-program test-service-nat test-service-nat-policy test-service-nat-guard test-service-wire test-service-packet-guard test-service-packet-gc test-service-tcp-state test-install-lifecycle test-gateway-conformance-runner
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
	  --server "https://127.0.0.1:$(PORT)"

notices:
	scripts/collect-notices.sh NOTICES

native: build/gr8s

build/gr8s: $(CONTAINERD_BUNDLE_MARKER) $(DASHBOARD_MARKER) $(XTERM_MARKER) $(GRAPH_MARKER) $(NODE_PROTOCOL_LISP) scripts/build-native.lisp scripts/bootstrap.lisp ocicl.csv $(LISP_SOURCES)
	$(SBCL) --noinform $(LISP_BOOTSTRAP) --non-interactive --load scripts/build-native.lisp

clean:
	rm -rf -- build

# Isolated doctor suite: no cluster, native runtime, or root privileges required.
.PHONY: test-doctor
test-doctor:
	$(SBCL) --noinform --no-sysinit --no-userinit --script tests/doctor/references-test.lisp
	$(SBCL) --noinform --no-sysinit --no-userinit --script tests/doctor/catalog-test.lisp
	$(SBCL) --noinform --no-sysinit --no-userinit --script tests/doctor/doctor-test.lisp
	$(SBCL) --noinform --no-sysinit --no-userinit --script tests/doctor/flows-test.lisp
	$(SBCL) --noinform --no-sysinit --no-userinit --script tests/doctor/causal-test.lisp
	$(SBCL) --noinform --no-sysinit --no-userinit --script tests/doctor/survey-test.lisp
	python3 tests/doctor/diagnose-cli-test.py
	python3 tests/doctor/cli-test.py
