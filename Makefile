#!/usr/bin/make -f

# Copyright 2019 The gVisor Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Helpful pretty-printer.
INFO := \033[0;32mINFO:\033[0m
submake = echo -e "$(INFO) make $1"; sh -c "$(MAKE) $1"

# Described below.
OPTIONS :=
STARTUP_OPTIONS :=
TARGETS := //runsc
ARGS    :=

default: runsc
.PHONY: default

## usage: make <target>
##         or
##        make <build|test|copy|run|sudo> STARTUP_OPTIONS="..." OPTIONS="..." TARGETS="..." ARGS="..."
##
## Basic targets.
##
##   This Makefile wraps basic build and test targets for ease-of-use. Bazel
##   is run inside a canonical Docker container in order to simplify up-front
##   requirements.
##
##   There are common arguments that may be passed to targets. These are:
##     STARTUP_OPTIONS - Bazel startup options.
##     OPTIONS - Build or test options.
##     TARGETS - The bazel targets.
##     ARGS    - Arguments for run or sudo.
##
##   Additionally, the copy target expects a DESTINATION to be provided.
##
##   For example, to build runsc using this Makefile, you can run:
##     make build OPTIONS="" TARGETS="//runsc"'
##
help: ## Shows all targets and help from the Makefile (this message).
	@grep --no-filename -E '^([a-z.A-Z_-]+:.*?|)##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = "(:.*?|)## ?"}; { \
			if (length($$1) > 0) { \
				printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2; \
			} else { \
				printf "%s\n", $$2; \
			} \
		}'
build: ## Builds the given $(TARGETS) with the given $(OPTIONS). E.g. make build TARGETS=runsc
test:  ## Tests the given $(TARGETS) with the given $(OPTIONS). E.g. make test TARGETS=pkg/buffer:buffer_test
copy:  ## Copies the given $(TARGETS) to the given $(DESTINATION). E.g. make copy TARGETS=runsc DESTINATION=/tmp
run:   ## Runs the given $(TARGETS), built with $(OPTIONS), using $(ARGS). E.g. make run TARGETS=runsc ARGS=-version
sudo:  ## Runs the given $(TARGETS) as per run, but using "sudo -E". E.g. make sudo TARGETS=test/root:root_test ARGS=-test.v
.PHONY: help build test copy run sudo

# Load all bazel wrappers.
#
# This file should define the basic "build", "test", "run" and "sudo" rules, in
# addition to the $(BRANCH_NAME) variable.
ifneq (,$(wildcard tools/google.mk))
include tools/google.mk
else
include tools/bazel.mk
endif

##
## Docker image targets.
##
##   Images used by the tests must also be built and available locally.
##   The canonical test targets defined below will automatically load
##   relevant images. These can be loaded or built manually via these
##   targets.
##
##   (*) Note that you may provide an ARCH parameter in order to build
##   and load images from an alternate archiecture (using qemu). When
##   bazel is run as a server, this has the effect of running an full
##   cross-architecture chain, and can produce cross-compiled binaries.
##
define images
$(1)-%: ## Image tool: $(1) a given image (also may use 'all-images').
	@$(call submake,-C images $$@)
endef
rebuild-...: ## Rebuild the given image. Also may use 'rebuild-all-images'.
$(eval $(call images,rebuild))
push-...: ## Push the given image. Also may use 'push-all-images'.
$(eval $(call images,pull))
pull-...: ## Pull the given image. Also may use 'pull-all-images'.
$(eval $(call images,push))
load-...: ## Load (pull or rebuild) the given image. Also may use 'load-all-images'.
$(eval $(call images,load))
list-images: ## List all available images.
	@$(call submake, -C images $$@)

##
## Canonical build and test targets.
##
##   These targets are used by continuous integration and provide
##   convenient entrypoints for testing changes. If you're adding a
##   new subsystem or workflow, consider adding a new target here.
##
runsc: ## Builds the runsc binary.
	@$(call submake,build OPTIONS="-c opt" TARGETS="//runsc")
.PHONY: runsc

debian: ## Builds the debian packages.
	@$(call submake,build OPTIONS="-c opt" TARGETS="//runsc:runsc-debian")
.PHONY: debian

smoke-test: ## Runs a simple smoke test after build runsc.
	@$(call submake,run DOCKER_PRIVILEGED="" ARGS="--alsologtostderr --network none --debug --TESTONLY-unsafe-nonroot=true --rootless do true")
.PHONY: smoke-tests

unit-tests: ## Local package unit tests in pkg/..., runsc/, tools/.., etc.
	@$(call submake,test TARGETS="pkg/... runsc/... tools/... benchmarks/... benchmarks/runner:runner_test")

tests: ## Runs all unit tests and syscall tests.
tests: unit-tests
	@$(call submake,test TARGETS="test/syscalls/...")
.PHONY: tests

integration-tests: ## Run all standard integration tests.
integration-tests: docker-tests overlay-tests hostnet-tests swgso-tests
integration-tests: do-tests kvm-tests root-tests
.PHONY: integration-tests

network-tests: ## Run all networking integration tests.
network-tests: iptables-tests packetdrill-tests packetimpact-tests
.PHONY: network-tests

# Standard integration targets.
INTEGRATION_TARGETS := //test/image:image_test //test/e2e:integration_test

syscall-%-tests:
	@$(call submake,test OPTIONS="--test_tag_filters runsc_$* test/syscalls/...")

syscall-native-tests:
	@$(call submake,test OPTIONS="--test_tag_filters native test/syscalls/...")
.PHONY: syscall-native-tests

syscall-tests: ## Run all system call tests.
syscall-tests: syscall-ptrace-tests syscall-kvm-tests syscall-native-tests
.PHONY: syscall-tests

%-runtime-tests: load-runtimes-%
	@$(call submake,test-install)
	@$(call submake,test-runtime TARGETS="//test/runtimes:$*_test")

do-tests: runsc
	@$(call submake,run TARGETS="//runsc" ARGS="--rootless do true")
	@$(call submake,run TARGETS="//runsc" ARGS="--rootless -network=none do true")
	@$(call submake,sudo TARGETS="//runsc" ARGS="do true")
.PHONY: do-tests

simple-tests: unit-tests # Compatibility target.
.PHONY: simple-tests

docker-tests: load-basic-images
	@$(call submake,test-install RUNTIME="vfs1")
	@$(call submake,test-runtime RUNTIME="vfs1" TARGETS="$(INTEGRATION_TARGETS)")
	@$(call submake,test-install RUNTIME="vfs2" ARGS="--vfs2")
	@$(call submake,test-runtime RUNTIME="vfs2" OPTIONS="--test_filter=.*TestHelloWorld" TARGETS="$(INTEGRATION_TARGETS)")
.PHONY: docker-tests

overlay-tests: load-basic-images
	@$(call submake,test-install RUNTIME="overlay" ARGS="--overlay")
	@$(call submake,test-runtime RUNTIME="overlay" TARGETS="$(INTEGRATION_TARGETS)")
.PHONY: overlay-tests

swgso-tests: load-basic-images
	@$(call submake,test-install RUNTIME="swgso" ARGS="--software-gso=true --gso=false")
	@$(call submake,test-runtime RUNTIME="swgso" TARGETS="$(INTEGRATION_TARGETS)")
.PHONY: swgso-tests

hostnet-tests: load-basic-images
	@$(call submake,test-install RUNTIME="hostnet" ARGS="--network=host")
	@$(call submake,test-runtime RUNTIME="hostnet" OPTIONS="--test_arg=-checkpoint=false" TARGETS="$(INTEGRATION_TARGETS)")
.PHONY: hostnet-tests

kvm-tests: load-basic-images
	@(lsmod | grep -E '^(kvm_intel|kvm_amd)') || sudo modprobe kvm
	@if ! [[ -w /dev/kvm ]]; then sudo chmod a+rw /dev/kvm; fi
	@$(call submake,test TARGETS="//pkg/sentry/platform/kvm:kvm_test")
	@$(call submake,test-install RUNTIME="kvm" ARGS="--platform=kvm")
	@$(call submake,test-runtime RUNTIME="kvm" TARGETS="$(INTEGRATION_TARGETS)")
.PHONY: kvm-tests

iptables-tests: load-iptables
	@$(call submake,test-runtime RUNTIME="runc" TARGETS="//test/iptables:iptables_test")
	@$(call submake,test-install RUNTIME="iptables" ARGS="--net-raw")
	@$(call submake,test-runtime RUNTIME="iptables" TARGETS="//test/iptables:iptables_test")
.PHONY: iptables-tests

packetdrill-tests: load-packetdrill
	@$(call submake,test-install RUNTIME="packetdrill")
	@$(call submake,test-runtime RUNTIME="packetdrill" $$($(MAKE) query TARGETS="attr(tags, packetdrill, tests(//...))"))
.PHONY: packetdrill-tests

packetimpact-tests: load-packetimpact
	@$(call submake,test-install RUNTIME="packetimpact")
	@$(call submake,test-runtime RUNTIME="packetimpact" $$($(MAKE) query TARGETS="attr(tags, packetimpact, tests(//...))"))
.PHONY: packetimpact-tests

root-tests: load-basic-images
	@$(call submake,test-install)
	@$(call submake,test-runtime TARGETS="//test/root:root_test")
.PHONY: test-root

##
## Benchmark targets.
##
##   To run benchmarks, set the BENCHMARK_REGEX and BENCHMARK_RUNTIMES
##   variables and make gcp-benchmarks or local-benchmarks. These will
##   execute the given set of benchmarks.
##     BENCHMARK_REGEX      - The regular expression for suites to run.
##     BENCHMARK_RUNTIMES   - The runtimes to use for benchmarks.
##     BENCHMARK_INSTALLERS - The benchmark installers.
##
BENCHMARK_REGEX      := (startup|absl)
BENCHMARK_RUNTIMES   := runc runsc
BENCHMARK_INSTALLERS := head
BENCHMARK_FULL_RUNTIMES   := $(foreach runtime, $(BENCHMARK_RUNTIMES), --runtime=$(runtime))
BENCHMARK_FULL_INSTALLERS := $(foreach install, $(BENCHMARK_INSTALLERS), --installers=$(installer))

%-benchmarks: ## Use gcp-benchmarks or local-benchmarks.
	@$(call submake,run TARGETS="//benchmarks" ARGS="--verbose run-$* $(BENCHMARK_REGEX) --internal $(BENCHMARK_FULL_RUNTIMES) $(BENCHMARK_FULL_INSTALLERS)")

##
## Website & documentation helpers.
##
##   The website is built from repository documentation and wrappers, using
##   using a locally-defined Docker image (see images/jekyll). The following
##   variables may be set when using website-push:
##     WEBSITE_IMAGE   - The name of the container image.
##     WEBSITE_SERVICE - The backend service.
##     WEBSITE_PROJECT - The project id to use.
##     WEBSITE_REGION  - The region to deploy to.
##
WEBSITE_IMAGE   := gcr.io/gvisordev/gvisordev
WEBSITE_SERVICE := gvisordev
WEBSITE_PROJECT := gvisordev
WEBSITE_REGION  := us-central1

website-build: load-jekyll ## Build the site image locally.
	@$(call submake,run TARGETS="//website:website")
.PHONY: website-build

website-server: website-build ## Run a local server for development.
	@docker run -i -p 8080:8080 gvisor.dev/images/website
.PHONY: website-server

website-push: website-build ## Push a new image and update the service.
	@docker tag gvisor.dev/images/website $(WEBSITE_IMAGE) && docker push $(WEBSITE_IMAGE)
.PHONY: website-push

website-deploy: website-push ## Deploy a new version of the website.
	@gcloud run deploy $(WEBSITE_SERVICE) --platform=managed --region=$(WEBSITE_REGION) --project=$(WEBSITE_PROJECT) --image=$(WEBSITE_IMAGE)
.PHONY: website-push

##
## Repository builders.
##
##   This builds a local apt repository. The following variables may be set:
##     RELEASE_ROOT    - The repository root (default: "repo" directory).
##     RELEASE_KEY     - The repository GPG private key file (default: dummy key is created).
##     RELEASE_NIGHTLY - Set to true if a nightly release (default: false).
##     RELEASE_COMMIT  - The commit or Change-Id for the release (needed for tag).
##     RELEASE_NAME    - The name of the release in the proper format (needed for tag).
##     RELEASE_NOTES   - The file containing release notes (needed for tag).
##
RELEASE_ROOT    := $(CURDIR)/repo
RELEASE_KEY     := repo.key
RELEASE_NIGHTLY := false
RELEASE_COMMIT  :=
RELEASE_NAME    :=
RELEASE_NOTES   :=

GPG_TEST_OPTIONS := $(shell if gpg --pinentry-mode loopback --version >/dev/null 2>&1; then echo --pinentry-mode loopback; fi)
$(RELEASE_KEY):
	@echo "WARNING: Generating a key for testing ($@); don't use this."
	T=$$(mktemp /tmp/keyring.XXXXXX); \
	C=$$(mktemp /tmp/config.XXXXXX); \
	echo Key-Type: DSA >> $$C && \
	echo Key-Length: 1024 >> $$C && \
	echo Name-Real: Test >> $$C && \
	echo Name-Email: test@example.com >> $$C && \
	echo Expire-Date: 0 >> $$C && \
	echo %commit >> $$C && \
	gpg --batch $(GPG_TEST_OPTIONS) --passphrase '' --no-default-keyring --keyring $$T --no-tty --gen-key $$C && \
	gpg --batch $(GPG_TEST_OPTIONS) --export-secret-keys --no-default-keyring --keyring $$T --secret-keyring $$T > $@; \
	rc=$$?; rm -f $$T $$C; exit $$rc

release: $(RELEASE_KEY) ## Builds a release.
	@mkdir -p $(RELEASE_ROOT)
	@T=$$(mktemp -d /tmp/release.XXXXXX); \
	  $(call submake,copy TARGETS="runsc" DESTINATION=$$T && \)
	  $(call submake,copy TARGETS="runsc:runsc-debian" DESTINATION=$$T && \)
	  NIGHTLY=$(RELEASE_NIGHTLY) tools/make_release.sh $(RELEASE_KEY) $(RELEASE_ROOT) $$T/*; \
	rc=$$?; rm -rf $$T; exit $$rc
.PHONY: release

tag: ## Creates and pushes a release tag.
	@tools/tag_release.sh "$(RELEASE_COMMIT)" "$(RELEASE_NAME)" "$(RELEASE_NOTES)"
.PHONY: tag

##
## Development helpers and tooling.
##
##   These targets faciliate local development by automatically
##   installing and configuring a runtime. Several variables may
##   be used here to tweak the installation:
##     RUNTIME         - The name of the installed runtime (default: branch).
##     RUNTIME_DIR     - Where the runtime will be installed (default: temporary directory with the $RUNTIME).
##     RUNTIME_BIN     - The runtime binary (default: $RUNTIME_DIR/runsc).
##     RUNTIME_LOG_DIR - The logs directory (default: $RUNTIME_DIR/logs).
##     RUNTIME_LOGS    - The log pattern (default: $RUNTIME_LOG_DIR/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%).
##
ifeq (,$(BRANCH_NAME))
RUNTIME     := runsc
RUNTIME_DIR := $(shell dirname $(shell mktemp -u))/$(RUNTIME)
else
RUNTIME     := $(BRANCH_NAME)
RUNTIME_DIR := $(shell dirname $(shell mktemp -u))/$(RUNTIME)
endif
RUNTIME_BIN     := $(RUNTIME_DIR)/runsc
RUNTIME_LOG_DIR := $(RUNTIME_DIR)/logs
RUNTIME_LOGS    := $(RUNTIME_LOG_DIR)/runsc.log.%TEST%.%TIMESTAMP%.%COMMAND%

dev: ## Installs a set of local runtimes. Requires sudo.
	@$(call submake,refresh ARGS="--net-raw")
	@$(call submake,configure RUNTIME="$(RUNTIME)" ARGS="--net-raw")
	@$(call submake,configure RUNTIME="$(RUNTIME)-d" ARGS="--net-raw --debug --strace --log-packets")
	@$(call submake,configure RUNTIME="$(RUNTIME)-p" ARGS="--net-raw --profile")
	@$(call submake,configure RUNTIME="$(RUNTIME)-vfs2-d" ARGS="--net-raw --debug --strace --log-packets --vfs2")
	@sudo systemctl restart docker
.PHONY: dev

refresh: ## Refreshes the runtime binary (for development only). Must have called 'dev' or 'test-install' first.
	@mkdir -p "$(RUNTIME_DIR)"
	@$(call submake,copy TARGETS=runsc DESTINATION="$(RUNTIME_BIN)" && chmod 0755 "$(RUNTIME_BIN)")
.PHONY: install

test-install: ## Installs the runtime for testing. Requires sudo.
	@$(call submake,refresh ARGS="--TESTONLY-test-name-env=RUNSC_TEST_NAME --debug --strace --log-packets $(ARGS)")
	@$(call submake,configure)
	@if sudo systemctl status docker 2>/dev/null; then sudo systemctl restart docker; fi
.PHONY: test-install

configure: ## Configures a single runtime. Requires sudo. Typically called from dev or test-install.
	@sudo sudo "$(RUNTIME_BIN)" install --experimental=true --runtime="$(RUNTIME)" -- --debug-log "$(RUNTIME_LOGS)" $(ARGS)
	@echo -e "$(INFO) Installed runtime \"$(RUNTIME)\" @ $(RUNTIME_BIN)"
	@echo -e "$(INFO) Logs are in: $(RUNTIME_LOG_DIR)"
	@sudo rm -rf "$(RUNTIME_LOG_DIR)" && mkdir -p "$(RUNTIME_LOG_DIR)"
.PHONY: configure

test-runtime: ## A convenient wrapper around test that provides the runtime argument. Target must still be provided.
	@$(call submake,test OPTIONS="$(OPTIONS) --test_arg=--runtime=$(RUNTIME)")
.PHONY: test-runtime
