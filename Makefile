# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

.PHONY: all build tools manifests-dir manifests cluster-up cluster-down image push install-trustee install clean fmt-check clippy lint test test-release

KUBECTL=kubectl

REGISTRY ?= quay.io
OPERATOR_IMAGE=$(REGISTRY)/confidential-clusters/cocl-operator:latest
COMPUTE_PCRS_IMAGE=$(REGISTRY)/confidential-clusters/compute-pcrs:latest

BUILD_TYPE ?= release

all: build tools

build:
	cargo build -p compute-pcrs
	cargo build -p operator

tools:
	cargo build -p manifest-gen

manifests-dir:
	mkdir -p manifests

manifests: tools
	target/debug/manifest-gen --output-dir manifests \
		--image $(OPERATOR_IMAGE) \
		--trustee-namespace operators \
		--pcrs-compute-image $(COMPUTE_PCRS_IMAGE)

cluster-up:
	scripts/create-cluster-kind.sh

cluster-down:
	scripts/delete-cluster-kind.sh

image:
	podman build --build-arg build_type=$(BUILD_TYPE) -t $(OPERATOR_IMAGE) -f Containerfile .
	podman build --build-arg build_type=$(BUILD_TYPE) -t $(COMPUTE_PCRS_IMAGE) -f compute-pcrs/Containerfile .

# TODO: remove the tls-verify, right now we are pushing only on the local registry
push: image
	podman push $(OPERATOR_IMAGE) --tls-verify=false
	podman push $(COMPUTE_PCRS_IMAGE) --tls-verify=false

install-trustee:
	scripts/install-trustee.sh

install:
	scripts/clean-cluster-kind.sh $(OPERATOR_IMAGE) $(COMPUTE_PCRS_IMAGE)
	$(KUBECTL) apply -f manifests/operator.yaml
	$(KUBECTL) apply -f manifests/confidential_cluster_crd.yaml
	$(KUBECTL) apply -f manifests/confidential_cluster_cr.yaml

clean:
	cargo clean
	rm -rf manifests

fmt-check:
	cargo fmt -- --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

lint: fmt-check clippy

test:
	cargo test --workspace --all-targets

test-release:
	cargo test --workspace --all-targets --release
