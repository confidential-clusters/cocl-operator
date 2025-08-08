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
