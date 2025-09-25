# Confidential Cluster Operator (cocl-operator)

This repository contains a Kubernetes operator for managing Confidential Clusters. The operator introduces a 
`ConfidentialCluster` Custom Resource Definition (CRD) which allows users to declaratively manage the configuration 
of a confidential cluster and trustee server, a core component which handles the attestation process.

The operator watches for `ConfidentialCluster` resources and ensures that the necessary configurations for the trustee 
(such as KBS configuration, attestation policies, and resource policies) are correctly set up and maintained 
within the cluster.

## Repository Structure

-   `/operator`: Contains the source code for the Kubernetes operator itself.
-   `/crds`: Defines the `ConfidentialCluster` Custom Resource Definition (CRD) in Rust.
-   `/register-server`: A server that provides Clevis PINs for key retrieval with random UUIDs.
-   `/compute-pcrs`: A program to compute PCR reference values using the [compute-pcrs library](https://github.com/confidential-clusters/compute-pcrs) and insert them into a ConfigMap, run as a Job.
-   `/rv-store`: Shared reference value definitions.
-   `/manifest-gen`: A tool for generating all the necessary Kubernetes manifests (Operator Deployment, CRD, RBAC rules, etc.).
-   `/scripts`: Helper scripts for managing a local `kind` development cluster.
-   `/manifests`: The default output directory for generated manifests. This directory is not checked into source control.

## Getting Started

### Prerequisites

-   Rust toolchain
-   `podman` or `docker`
-   `kubectl`
-   `kind`

### Quick Start

Create the cluster, install [trustee operator](https://github.com/confidential-containers/trustee-operator) and deploy 
the operator.

Provide an address where the VM you will attest from can access the cluster.
In many cases, this will be your gateway address (`arp -a`).
For an existing VM on system libvirt, you can also find this address via `virsh net-dhcp-leases`.

```bash
$ arp -a
_gateway (192.168.178.1) at 34:2c:c4:de:fc:52 [ether] on wlp0s20f3
$ ip=192.168.178.1
``

```bash
make cluster-up
make REGISTRY=localhost:5000 image push # optional: use BUILD_TYPE=debug
make REGISTRY=localhost:5000 TRUSTEE_ADDR=$ip manifests
make install-trustee
make install
```

The KBS port will be forwarded to `8080` on your machine; the node register server to `3030`, where new Ignition configs are served at `/register`.

### Test

Run a VM as described in the
[investigations](https://github.com/confidential-clusters/investigations?tab=readme-ov-file#example-with-the-confidential-clusters-operator-and-a-local-vm)
repository.

## Licenses

See [LICENSES](LICENSES).
