#!/bin/bash

RUNTIME=${RUNTIME:=podman}
if [ "$RUNTIME" == "podman" ]; then
	export KIND_EXPERIMENTAL_PROVIDER=podman
	export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/podman/podman.sock
fi
