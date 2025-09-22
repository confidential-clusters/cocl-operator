#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

source scripts/common.sh

config=$(pwd)/.kubeconfig
kind get kubeconfig > $config
echo "set export KUBECONFIG=$config"
