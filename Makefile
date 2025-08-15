K8S_VERSION ?= 1.33
KUBECTL=kubectl

REGISTRY ?= quay.io
OPERATOR_IMAGE=$(REGISTRY)/confidential-clusters/cocl-operator:latest
REG_SERVER_IMAGE=$(REGISTRY)/confidential-clusters/registration-server:latest


all: build tools reg-server

build:
	K8S_OPENAPI_ENABLED_VERSION=$(K8S_VERSION) cargo build -p operator

reg-server:
	K8S_OPENAPI_ENABLED_VERSION=$(K8S_VERSION) cargo build -p register-server

tools:
	K8S_OPENAPI_ENABLED_VERSION=$(K8S_VERSION) cargo build -p manifest-gen

manifests-dir:
	mkdir -p manifests

manifests: tools
	target/debug/manifest-gen --output-dir manifests \
		--image $(OPERATOR_IMAGE) \
		--register-server-image $(REG_SERVER_IMAGE) \
		--trustee-namespace operators

cluster-up:
	scripts/create-cluster-kind.sh

cluster-down:
	scripts/delete-cluster-kind.sh

image: build reg-server
	podman build -t $(OPERATOR_IMAGE) -f Containerfile .
	podman build -t $(REG_SERVER_IMAGE) -f register-server/Containerfile .

# TODO: remove the tls-verify, right now we are pushing only on the local registry
push: image
	podman push $(OPERATOR_IMAGE) --tls-verify=false
	podman push $(REG_SERVER_IMAGE) --tls-verify=false

install-trustee:
	scripts/install-trustee.sh

install:
	scripts/clean-cluster-kind.sh $(OPERATOR_IMAGE) $(REG_SERVER_IMAGE)
	$(KUBECTL) apply -f manifests/operator.yaml
	$(KUBECTL) apply -f manifests/confidential_cluster_crd.yaml
	$(KUBECTL) apply -f manifests/confidential_cluster_cr.yaml

clean:
	cargo clean
	rm -rf manifests
