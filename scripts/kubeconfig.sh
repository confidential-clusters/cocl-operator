#!/bin/bash

source scripts/common.sh

config=$(pwd)/.kubeconfig
kind get kubeconfig > $config
echo "set export KUBECONFIG=$config"
