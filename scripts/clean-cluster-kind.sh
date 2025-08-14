#!/bin/bash

set -x

source scripts/common.sh

for image in "$@"; do
	if ${RUNTIME} exec -ti kind-control-plane crictl inspecti ${image} &> /dev/null ; then
		echo "Delete image ${image}"
		${RUNTIME} exec -ti kind-control-plane crictl rmi ${image}
	fi
done
kubectl delete deploy cocl-operator -n confidential-clusters || true
kubectl delete deploy register-server -n confidential-clusters || true

