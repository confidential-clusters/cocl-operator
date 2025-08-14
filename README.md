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

Fill the file `operator/src/reference-values-in.json` with the desired PCR values, e.g. by

```bash
$ for i in {4,7,14}; do
    sudo tpm2_pcrread sha256:${i} | awk -F: '/0x/ {sub(/.*0x/, "", $2); gsub(/[^0-9A-Fa-f]/, "", $2); print tolower($2)}'
done
6401162a80170f039aabff2606d2c7b4843c592edcdc082abd66f644131d83c8
b3a56a06c03a65277d0a787fcabc1e293eaa5d6dd79398f2dda741f7b874c65d
17cdefd9548f4383b67a37a901673bf3c8ded6f619d36c8007562de1d93c81cc
```

i.e.

```json
{
    "pcr4":  "6401162a80170f039aabff2606d2c7b4843c592edcdc082abd66f644131d83c8",
    "pcr7":  "b3a56a06c03a65277d0a787fcabc1e293eaa5d6dd79398f2dda741f7b874c65d",
    "pcr14": "17cdefd9548f4383b67a37a901673bf3c8ded6f619d36c8007562de1d93c81cc"
}
```

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
