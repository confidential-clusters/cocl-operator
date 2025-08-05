K8S_VERSION ?= 1.33
KUBECTL=kubectl

REGISTRY ?= quay.io
IMAGE=$(REGISTRY)/confidential-clusters/cocl-operator:latest

all: build tools

build:
	K8S_OPENAPI_ENABLED_VERSION=$(K8S_VERSION) cargo build -p operator

tools:
	K8S_OPENAPI_ENABLED_VERSION=$(K8S_VERSION) cargo build -p manifest-gen

manifests-dir:
	mkdir -p manifests

manifests: tools
	target/debug/manifest-gen --output-dir manifests \
		--image $(IMAGE) \
		--trustee-namespace operators

cluster-up:
	scripts/create-cluster-kind.sh

cluster-down:
	scripts/delete-cluster-kind.sh

image: build
	podman build -t $(IMAGE) -f Containerfile .

# TODO: remove the tls-verify, right now we are pushing only on the local registry
push: image
	podman push $(IMAGE) --tls-verify=false

install-trustee:
	scripts/install-trustee.sh

install:
	scripts/clean-cluster-kind.sh $(IMAGE)
	$(KUBECTL) apply -f manifests/operator.yaml
	$(KUBECTL) apply -f manifests/confidential_cluster_crd.yaml
	$(KUBECTL) apply -f manifests/confidential_cluster_cr.yaml

clean:
	cargo clean
	rm -rf manifests
