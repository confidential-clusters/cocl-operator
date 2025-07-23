#!/bin/bash

source scripts/common.sh
kind delete cluster
podman rm -f kind-registry
