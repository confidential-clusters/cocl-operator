#!/bin/bash

OP_FRMWK_VERSION=0.31.0

source ./common.sh

scripts/kubeconfig.sh
export KUBECONFIG=$(pwd)/.kubeconfig

curl -sL \
	https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v${OP_FRMWK_VERSION}/install.sh | \
	bash -s v${OP_FRMWK_VERSION}

kubectl apply -f - << EOF
apiVersion: v1
kind: Namespace
metadata:
  name: trustee
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata: 
  name: trustee-operator
  namespace: trustee
spec: 
  channel: alpha
  name: trustee-operator
  source: operatorhubio-catalog
  sourceNamespace: olm
EOF

kubectl create -f https://operatorhub.io/install/trustee-operator.yaml
