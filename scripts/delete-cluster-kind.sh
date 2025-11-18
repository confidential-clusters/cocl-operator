#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

source scripts/common.sh

$RUNTIME stop kind-registry >/dev/null 2>&1 || true
$RUNTIME rm -f kind-registry >/dev/null 2>&1 || true

kind delete cluster
