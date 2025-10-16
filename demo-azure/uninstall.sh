#!/bin/bash

source ./common.sh

oc delete -n $NAMESPACE deploy cocl-operator && true
oc delete confidentialclusters -n $NAMESPACE confidential-cluster && true
oc delete  configmaps  image-pcrs
