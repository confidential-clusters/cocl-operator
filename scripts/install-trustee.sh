#!/bin/bash

OP_FRMWK_VERSION=0.31.0

source scripts/common.sh

scripts/kubeconfig.sh
export KUBECONFIG=$(pwd)/.kubeconfig

curl -sL \
	https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v${OP_FRMWK_VERSION}/install.sh | \
	bash -s v${OP_FRMWK_VERSION}

kubectl apply -f - << EOF
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: my-trustee-operator
  namespace: operators
spec:
  channel: alpha
  name: trustee-operator
  source: operatorhubio-catalog
  sourceNamespace: olm
EOF
