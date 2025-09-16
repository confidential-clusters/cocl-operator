#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

set -x

source scripts/common.sh

IMAGE=$1
if ${RUNTIME} exec -ti kind-control-plane crictl inspecti ${IMAGE} &> /dev/null ; then
	${RUNTIME} exec -ti kind-control-plane crictl rmi ${IMAGE}
fi

kubectl delete deploy cocl-operator -n confidential-clusters || true
