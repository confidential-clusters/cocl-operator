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

```bash
make cluster-up
make REGISTRY=localhost:5000 image
make REGISTRY=localhost:5000 push
make REGISTRY=localhost:5000 manifests
make install-trustee
make install
```

The KBS port will be forwarded to `8080` on your machine.

### Test

Run a VM as described in the
[investigations](https://github.com/confidential-clusters/investigations?tab=readme-ov-file#example-with-the-confidential-clusters-operator-and-a-local-vm)
repository.

## Licenses

See [LICENSES](LICENSES).
