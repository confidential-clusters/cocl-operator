#!/bin/bash

set -x

source ./common.sh

wait_for_service() {
    local svc_name=$1
    local namespace=${2:-$NAMESPACE}
    local retries=60  # ~5 minutes max
    local count=0

    echo "Waiting for service '$svc_name' in namespace '$namespace'..."
    until oc get svc "$svc_name" -n "$namespace" >/dev/null 2>&1; do
        count=$((count + 1))
        if [ $count -ge $retries ]; then
            echo "ERROR: Service '$svc_name' did not appear after $retries attempts."
            exit 1
        fi
        sleep 5
    done
    echo "Service '$svc_name' is now available."
}

export REGISTRY=image-registry.openshift-image-registry.svc:5000/$NAMESPACE

(cd .. && make manifests)
cp -r ../manifests .

yq '.spec.publicTrusteeAddr = "kbs-service-demo-cocl.apps.dev-normal-shared.cc.azure.dog8.cloud" | .spec.registerServerPort = 8000 | .spec.trusteeKbsPort = 8080' \
		-i manifests/confidential_cluster_cr.yaml

./uninstall.sh

oc apply -f manifests/operator.yaml
oc apply -f manifests/confidential_cluster_crd.yaml
oc apply -f manifests/confidential_cluster_cr.yaml

wait_for_service kbs-service
oc expose svc kbs-service
wait_for_service register-server
oc expose register-server

oc create secret generic demo-ignition -n openshift-machine-api --from-file=userData=demo-ignition.json
oc apply -f demo-machineset.yaml

oc scale machineset machineset-cocl-demo --replicas=1 -n openshift-machine-api
