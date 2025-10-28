# Confidential Cluster Operator (cocl-operator)

This repository contains a Kubernetes operator for managing Confidential Clusters. The operator introduces a 
`ConfidentialCluster` Custom Resource Definition (CRD) which allows users to declaratively manage the configuration 
of a confidential cluster and trustee server, a core component which handles the attestation process.

The operator watches for `ConfidentialCluster` resources and ensures that the necessary configurations for the trustee 
(such as KBS configuration, attestation policies, and resource policies) are correctly set up and maintained 
within the cluster.

## Repository Structure

-   `/api`: Defines the `ConfidentialCluster` Custom Resource Definition (CRD) and associated CRDs and RBAC definitions in Go. Also contains a program to generate a `ConfidentialCluster` CR and associated deployment.
-   `/operator`: Contains the source code for the Kubernetes operator itself.
-   `/register-server`: A server that provides Clevis PINs for key retrieval with random UUIDs.
-   `/compute-pcrs`: A program to compute PCR reference values using the [compute-pcrs library](https://github.com/confidential-clusters/compute-pcrs) and insert them into a ConfigMap, run as a Job.
-   `/lib`: Shared Rust definitions, including translated CRDs
-   `/scripts`: Helper scripts for managing a local `kind` development cluster.
-   `/config`: The default output directory for generated manifests. This directory is not checked into source control.

## Getting Started

### Prerequisites

-   Rust toolchain
-   `podman` or `docker`
-   `kubectl`
-   `kind`

### Quick Start

Create the cluster and deploy the operator.

Provide an address where the VM you will attest from can access the cluster.
When using a local kind & libvirt VM, this may be your gateway address (`default via …` in `ip route`) for user libvirt or bridge (`virbr0` in `ip route`) for system libvirt.

```bash
$ ip route
...
192.168.122.0/24 dev virbr0 proto kernel scope link src 192.168.122.1
...
$ ip=192.168.122.1
``

```bash
make cluster-up
make REGISTRY=localhost:5000 push # optional: use BUILD_TYPE=debug
make REGISTRY=localhost:5000 manifests
make TRUSTEE_ADDR=$ip install
```

The KBS port will be forwarded to `8080` on your machine; the node register server to `8000`, where new Ignition configs are served at `/register`.

### Test

Run a VM as described in the
[investigations](https://github.com/confidential-clusters/investigations?tab=readme-ov-file#example-with-the-confidential-clusters-operator-and-a-local-vm)
repository.

## Licenses

See [LICENSES](LICENSES).
