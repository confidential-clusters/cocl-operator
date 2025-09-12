#!/bin/bash

set -xe

OP_FRMWK_VERSION=0.31.0

source scripts/common.sh

scripts/kubeconfig.sh
export KUBECONFIG=$(pwd)/.kubeconfig

curl -sL \
	https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v${OP_FRMWK_VERSION}/install.sh | \
	bash -s v${OP_FRMWK_VERSION} || true

namespace=trustee-operator-system
kubectl create ns $namespace

kubectl apply -f - << EOF
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: trustee-operator-group
  namespace: $namespace
EOF


kubectl apply -f - << EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: my-trustee-operator
  namespace: ${namespace}
spec:
  channel: alpha
  name: trustee-operator
  source: operatorhubio-catalog
  sourceNamespace: olm
EOF

operator=trustee-operator.v0.4.0
kubectl_do_csv() {
	verb=$1
	shift
	kubectl "$verb" -n "$namespace" csv "$operator" "$@"
}

kubectl_get_csv_env_name() {
	kubectl_do_csv get \
		-o jsonpath="{.spec.install.spec.deployments[0].spec.template.spec.containers[0].env[$1].name}"
}

kubectl_patch_csv_env_value() {
	kubectl_do_csv patch --type="json" \
		-p="[{'op': 'replace', 'path': '/spec/install/spec/deployments/0/spec/template/spec/containers/0/env/$1/value', 'value':$2}]"
}

kubectl_do_csv wait --for=create --timeout=90s
kubectl_do_csv wait --for=jsonpath="{.status.phase}"=Succeeded

if [ "$(kubectl_get_csv_env_name 2)" != "KBS_IMAGE_NAME_MICROSERVICES" ] || \
	[ "$(kubectl_get_csv_env_name 3)" != "AS_IMAGE_NAME" ]; then
	echo "Unexpected change in Trustee CSV environment order"
	exit 1
fi

kubectl_patch_csv_env_value 2 "quay.io/afrosi_rh/kbs-grpc-as:latest"
kubectl_patch_csv_env_value 3 "quay.io/afrosi_rh/coco-as-grpc:latest"

kubectl apply -f - << EOF
apiVersion: v1
kind: Service
metadata:
  name: kbs-forward
  namespace: ${namespace}
spec:
  type: NodePort
  ports:
  - name: http
    nodePort: 31000
    port: 8080
  selector:
    app: kbs
EOF
