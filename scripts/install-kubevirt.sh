#!/bin/bash

. scripts/common.sh

# Fix kvm permission on kind
$RUNTIME exec -ti kind-control-plane chmod 666 /dev/kvm
export VERSION=$(curl -s https://storage.googleapis.com/kubevirt-prow/release/kubevirt/kubevirt/stable.txt)
kubectl create -f "https://github.com/kubevirt/kubevirt/releases/download/${VERSION}/kubevirt-operator.yaml"
kubectl create -f "https://github.com/kubevirt/kubevirt/releases/download/${VERSION}/kubevirt-cr.yaml"

kubectl patch kubevirt kubevirt -n kubevirt --type='merge' -p \
'{"spec":{"configuration":{"developerConfiguration":{"featureGates":["ExperimentalIgnitionSupport"]}}}}'

kubectl wait --for=jsonpath='{.status.phase}'=Deployed kubevirt/kubevirt -n kubevirt --timeout=10m
