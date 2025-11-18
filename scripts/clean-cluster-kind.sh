#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

set -x

. scripts/common.sh

for image in "$@"; do
	if ${RUNTIME} exec -ti kind-control-plane crictl inspecti ${image} &> /dev/null ; then
		echo "Delete image ${image}"
		${RUNTIME} exec -ti kind-control-plane crictl rmi ${image}
	fi
done
kubectl delete deploy trusted-cluster-operator -n trusted-execution-clusters || true
