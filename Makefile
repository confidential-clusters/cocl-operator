# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

.PHONY: all build tools manifests-dir manifests cluster-up cluster-down image push install-trustee install clean fmt-check clippy lint test test-release

NAMESPACE ?= confidential-clusters

KUBECTL=kubectl

REGISTRY ?= quay.io/confidential-clusters
OPERATOR_IMAGE=$(REGISTRY)/cocl-operator:latest
COMPUTE_PCRS_IMAGE=$(REGISTRY)/compute-pcrs:latest
REG_SERVER_IMAGE=$(REGISTRY)/registration-server:latest
# TODO add support for TPM AK verification, then move to a KBS with implemented verifier
TRUSTEE_IMAGE ?= quay.io/confidential-clusters/key-broker-service:tpm-verifier-built-in-as-20250711

BUILD_TYPE ?= release

all: build tools reg-server

build:
	cargo build -p compute-pcrs
	cargo build -p operator

reg-server:
	cargo build -p register-server

tools:
	cargo build -p manifest-gen

manifests-dir:
	mkdir -p manifests

manifests: tools
	target/debug/manifest-gen --output-dir manifests \
		--namespace $(NAMESPACE) \
		--image $(OPERATOR_IMAGE) \
		--trustee-image $(TRUSTEE_IMAGE) \
		--pcrs-compute-image $(COMPUTE_PCRS_IMAGE) \
		--register-server-image $(REG_SERVER_IMAGE)

cluster-up:
	scripts/create-cluster-kind.sh

cluster-down:
	scripts/delete-cluster-kind.sh

image:
	podman build --build-arg build_type=$(BUILD_TYPE) -t $(OPERATOR_IMAGE) -f Containerfile .
	podman build --build-arg build_type=$(BUILD_TYPE) -t $(COMPUTE_PCRS_IMAGE) -f compute-pcrs/Containerfile .
	podman build --build-arg build_type=$(BUILD_TYPE) -t $(REG_SERVER_IMAGE) -f register-server/Containerfile .

# TODO: remove the tls-verify, right now we are pushing only on the local registry
push: image
	podman push $(OPERATOR_IMAGE) --tls-verify=false
	podman push $(COMPUTE_PCRS_IMAGE) --tls-verify=false
	podman push $(REG_SERVER_IMAGE) --tls-verify=false

install:
ifndef TRUSTEE_ADDR
	$(error TRUSTEE_ADDR is undefined)
endif
	scripts/clean-cluster-kind.sh $(OPERATOR_IMAGE) $(COMPUTE_PCRS_IMAGE) $(REG_SERVER_IMAGE)
	yq '.spec.trusteeAddr = "$(TRUSTEE_ADDR):8080" | .spec.registerServerPort = 8000' \
		-i manifests/confidential_cluster_cr.yaml
	$(KUBECTL) apply -f manifests/operator.yaml
	$(KUBECTL) apply -f manifests/confidential_cluster_crd.yaml
	$(KUBECTL) apply -f manifests/confidential_cluster_cr.yaml
	$(KUBECTL) apply -f kind/register-forward.yaml
	$(KUBECTL) apply -f kind/kbs-forward.yaml

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
