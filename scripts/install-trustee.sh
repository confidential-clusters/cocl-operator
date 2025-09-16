#!/bin/bash

OP_FRMWK_VERSION=0.31.0

source scripts/common.sh

scripts/kubeconfig.sh
export KUBECONFIG=$(pwd)/.kubeconfig

curl -sL \
	https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v${OP_FRMWK_VERSION}/install.sh | \
	bash -s v${OP_FRMWK_VERSION}

namespace=operators

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

kubectl_do_csv wait --for=create --timeout=90s
kubectl_do_csv wait --for=jsonpath="{.status.phase}"=Succeeded

if [ "$(kubectl_do_csv get -o \
		jsonpath="{.spec.install.spec.deployments[0].spec.template.spec.containers[0].env[1].name}")" \
			!= "KBS_IMAGE_NAME" ]; then
	echo "Unexpected change in Trustee CSV environment order"
fi

# TODO add support for TPM AK verification, then move to a KBS with implemented verifier
kubectl_do_csv patch --type="json" -p="[{'op': 'replace', \
  'path': '/spec/install/spec/deployments/0/spec/template/spec/containers/0/env/1/value', \
  'value': 'quay.io/confidential-clusters/key-broker-service:tpm-verifier-built-in-as-20250711'}]"

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
