#!/bin/bash

# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

RUNTIME=${RUNTIME:=podman}
if [ "$RUNTIME" == "podman" ]; then
	export KIND_EXPERIMENTAL_PROVIDER=podman
	export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
fi
