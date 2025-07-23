#!/bin/bash

set -x

source scripts/common.sh

IMAGE=$1
if ${RUNTIME} exec -ti kind-control-plane crictl inspecti ${IMAGE} &> /dev/null ; then
	${RUNTIME} exec -ti kind-control-plane crictl rmi ${IMAGE}
fi

kubectl delete deploy cocl-operator -n confidential-clusters || true

