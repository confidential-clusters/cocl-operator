# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

.PHONY: all build crds-rs generate manifests cluster-up cluster-down image push install-trustee install clean fmt-check clippy lint test test-release

NAMESPACE ?= confidential-clusters

KUBECTL=kubectl

LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_TOOLS_VERSION ?= v0.19.0
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen-$(CONTROLLER_TOOLS_VERSION)
YQ_VERSION ?= v4.48.1
YQ ?= $(LOCALBIN)/yq-$(YQ_VERSION)
# tracking k8s v1.33, sync with Cargo.toml
KOPIUM_VERSION ?= 0.21.3
KOPIUM ?= $(LOCALBIN)/kopium-$(KOPIUM_VERSION)

REGISTRY ?= quay.io/confidential-clusters
OPERATOR_IMAGE=$(REGISTRY)/cocl-operator:latest
COMPUTE_PCRS_IMAGE=$(REGISTRY)/compute-pcrs:latest
REG_SERVER_IMAGE=$(REGISTRY)/registration-server:latest
# TODO add support for TPM AK verification, then move to a KBS with implemented verifier
TRUSTEE_IMAGE ?= quay.io/confidential-clusters/key-broker-service:tpm-verifier-built-in-as-20250711

BUILD_TYPE ?= release

all: build cocl-gen reg-server

build: crds-rs
	cargo build -p compute-pcrs
	cargo build -p operator

reg-server: crds-rs
	cargo build -p register-server

CRD_YAML_PATH = config/crd
API_PATH = api/v1alpha1
generate: $(CONTROLLER_GEN)
	$(CONTROLLER_GEN) rbac:roleName=cocl-operator-role crd webhook paths="./..." \
		output:crd:artifacts:config=$(CRD_YAML_PATH)

RS_LIB_PATH = lib/src
CRD_RS_PATH = $(RS_LIB_PATH)/kopium
$(CRD_RS_PATH):
	mkdir $(CRD_RS_PATH)

YAML_PREFIX = confidential-clusters.io_
$(CRD_RS_PATH)/%.rs: $(CRD_YAML_PATH)/$(YAML_PREFIX)%.yaml $(KOPIUM) $(CRD_RS_PATH)
	$(KOPIUM) -f $< > $@
	rustfmt $@

crds-rs: generate
	$(MAKE) $(shell find $(CRD_YAML_PATH) -type f \
		| sed -E 's|$(CRD_YAML_PATH)/$(YAML_PREFIX)(.*)\.yaml|$(CRD_RS_PATH)/\1.rs|')

cocl-gen:
	go build -o $@ api/$@.go

DEPLOY_PATH = config/deploy
manifests: cocl-gen
	./cocl-gen -output-dir $(DEPLOY_PATH) \
		-namespace $(NAMESPACE) \
		-image $(OPERATOR_IMAGE) \
		-trustee-image $(TRUSTEE_IMAGE) \
		-pcrs-compute-image $(COMPUTE_PCRS_IMAGE) \
		-register-server-image $(REG_SERVER_IMAGE)

cluster-up:
	scripts/create-cluster-kind.sh

cluster-down:
	scripts/delete-cluster-kind.sh

image: crds-rs
	podman build --build-arg build_type=$(BUILD_TYPE) -t $(OPERATOR_IMAGE) -f Containerfile .
	podman build --build-arg build_type=$(BUILD_TYPE) -t $(COMPUTE_PCRS_IMAGE) -f compute-pcrs/Containerfile .
	podman build --build-arg build_type=$(BUILD_TYPE) -t $(REG_SERVER_IMAGE) -f register-server/Containerfile .

# TODO: remove the tls-verify, right now we are pushing only on the local registry
push: image
	podman push $(OPERATOR_IMAGE) --tls-verify=false
	podman push $(COMPUTE_PCRS_IMAGE) --tls-verify=false
	podman push $(REG_SERVER_IMAGE) --tls-verify=false

install: $(YQ)
ifndef TRUSTEE_ADDR
	$(error TRUSTEE_ADDR is undefined)
endif
	scripts/clean-cluster-kind.sh $(OPERATOR_IMAGE) $(COMPUTE_PCRS_IMAGE) $(REG_SERVER_IMAGE)
	$(YQ) '.spec.publicTrusteeAddr = "$(TRUSTEE_ADDR):8080"' \
		-i $(DEPLOY_PATH)/confidential_cluster_cr.yaml
	$(YQ) '.namespace = "$(NAMESPACE)"' -i config/rbac/kustomization.yaml
	$(KUBECTL) apply -f $(DEPLOY_PATH)/operator.yaml
	$(KUBECTL) apply -f config/crd
	$(KUBECTL) apply -k config/rbac
	$(KUBECTL) apply -f $(DEPLOY_PATH)/confidential_cluster_cr.yaml
	$(KUBECTL) apply -f kind/register-forward.yaml
	$(KUBECTL) apply -f kind/kbs-forward.yaml

clean:
	cargo clean
	rm -rf bin manifests $(CRD_YAML_PATH) $(CRD_RS_PATH)
	rm -f cocl-gen config/rbac/role.yaml .crates.toml .crates2.json

fmt-check:
	cargo fmt -- --check
	gofmt -l .

clippy: crds-rs
	cargo clippy --all-targets --all-features -- -D warnings

vet:
	go vet ./...

equal-conditions:
	cargo test --test equal_conditions

lint: fmt-check clippy vet equal-conditions

test:
	cargo test --workspace --all-targets

test-release:
	cargo test --workspace --all-targets --release

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),controller-gen,sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

$(YQ): $(LOCALBIN)
	$(call go-install-tool,$(YQ),yq,github.com/mikefarah/yq/v4,$(YQ_VERSION))

$(KOPIUM): $(LOCALBIN)
	$(call cargo-install-tool,$(KOPIUM),kopium,$(KOPIUM_VERSION))

define go-install-tool
[ -f "$(1)" ] || { \
	set -e; \
	package=$(3)@$(4) ;\
	GOBIN="$(LOCALBIN)" go install $(3)@$(4) ;\
	mv "$$(dirname $(1))/$(2)" $(1) ;\
}
endef

define cargo-install-tool
[ -f "$(1)" ] || { \
	set -e; \
	cargo install --locked --version $(3) --root "$(LOCALBIN)/.." $(2) ;\
	mv "$$(dirname $(1))/$(2)" $(1) ;\
}
endef
