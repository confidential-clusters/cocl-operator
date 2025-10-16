#!/bin/bash

source ./common.sh

# Follow the README to expose the internal cluster registry: https://docs.redhat.com/en/documentation/openshift_container_platform/4.15/html/registry/securing-exposing-registry
export REGISTRY=default-route-openshift-image-registry.apps.dev-normal-shared.cc.azure.dog8.cloud

podman login $REGISTRY -u $(oc whoami) -p $(oc whoami -t)  --tls-verify=false
export REGISTRY=$REGISTRY/$NAMESPACE
oc get istag -n $NAMESPACE
(cd .. && make push)
