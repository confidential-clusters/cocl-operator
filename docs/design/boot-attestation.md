# Boot and attestation process

## Overview

This document describes the booting flow for confidential clusters in case of first and second boots.

## Architecture Diagram

![Boot KBS Flow](../pics/boot-kbs.png)

## RATS Models

In this design the [Passport](https://github.com/confidential-containers/trustee/tree/main/kbs#passport-mode) model
will be used for first boot, while the
[Background Check](https://github.com/confidential-containers/trustee/tree/main/kbs#background-check-mode) for second
boot.

### Passport Model (First Boot)

The passport model decouples the provisioning of resources from the validation of evidence by utilizing two separate
Key Broker Services:

- **KBS1**: Handles evidence verification and attestation validation
- **KBS2**: Handles resource provisioning and key management

This separation is recommended when resource provisioning and attestation are handled by separate entities, which is
precisely our case during the first boot phase.

### Background Check Model (Second Boot)

For subsequent boots, the system transitions to the background check model where a single KBS handles both attestation
and resource provisioning directly since the LUKS key was registered at firstboot with the node identifier.

## Machine Resource

The Machine resource is a core component from [Cluster API](https://cluster-api.sigs.k8s.io/user/concepts#machine)
that represents a declarative specification for an infrastructure component hosting a Kubernetes Node (such as a VM)
and controls its lifecycle. When a Machine is created, a provider-specific controller provisions a new host and
registers it as a Kubernetes Node. If the Machine spec is updated, the controller replaces the host. When deleted, both
the underlying infrastructure and Node are removed.

Machines follow an immutable model where they are never updated, only replaced. This ensures consistent and predictable
infrastructure management.

The Machine object can be used for matching the existence of a node in the cluster. However, critical information like
node identifiers, addresses, and provider IDs is not populated at object creation time but rather during the machine's
lifecycle. As detailed in the
[Machine Controller documentation](https://cluster-api.sigs.k8s.io/developer/core/controllers/machine), the provider ID
is populated by the infrastructure provider when the infrastructure object is ready, the machine controller will attempt
to read its Spec.ProviderID and copy it into Machine.Spec.ProviderID.

**Delayed Verification Requirement**: Due to this asynchronous population of node identifiers, we cannot immediately
match the node ID from the attestation request with the real node existence in the cloud infrastructure. Therefore, we
delay the verification of whether the node ID truly matches with a Machine object until the end of the first boot phase.
This allows the first boot process to continue with key generation while we prepare `KBS1` for subsequent verification.

## Node identifier
TBD

## Flow Description

### First Boot Phase

The first boot phase implements the passport model to establish trust and generate the initial LUKS encryption key:

1. **Node Attestation**
   - The `AttestationAgent` on `node01` initiates the attestation process
   - Evidence is sent to the `Trustee Server` for validation

2. **Evidence Verification**
   - The `Trustee Server` validates the hardware evidence
   - An attestation token is returned to the `AttestationAgent`

3. **LUKS Key Generation Request**
   - The `AttestationAgent` requests a resource from `KBS2` using the path: `/cluster/firstboot/root-key`. This path is
     constant for all the nodes since it signals that the node requests a new LUKS key for the root disk.
     *Note*
     At this point time the LUKS key is meaningless since it doesn't decrypt any disks, therefore we don't need to ensure
     that the identifier matches with a real node in the cluster, this will be necessary only for the second boot and to
     store the key in the first KBSs.

4. **Key Generation**
   - The `Key Generator` component creates a new LUKS key and replies to the Attestation Agent request with it,

5. **Key Registration**
   - Before registering the LUKS key in `KBS1`, the operator needs to check if there is a Machine object which correspond
     to the identifier present in the resource request. If there is an actual machine matching with the request, then
     the LUKS key is stored in `KBS1`.
   - The generated is stored it at the path: `/cluster/root/<node-id>`. The *node id* is extrapolated
     by the HTTP request for the resource and the attestation token.
   - The generated LUKS key is registered in `KBS1` for future use
   - This establishes the trust relationship for subsequent boots

6. **Resource policy nodes list update**
   - The resource policy controls the release of the secret resource. Since the operator has already verified the
     existence of a real node in the cluster, it requires also to update the resource policy for second boots in `KBS1`.
     During second boot, the secret resource will be release only if the attestation was successful and the node
     identifier in the request matches with one of the node in the resource list.

### Second Boot Phase

The second boot phase transitions to the background check model for streamlined access:

1. **Simplified Attestation**
   - The `AttestationAgent` performs attestation with the `Trustee Server`
   - An attestation token is returned upon successful verification

2. **Direct Key Retrieval**
   - The `AttestationAgent` directly requests the LUKS key from `KBS1` using the path: `/cluster/root/<node-id>`
   - The node identifier in the request needs to match one of the node in the node lists in the resource policy.
   - `KBS1` returns the previously stored LUKS key without requiring key generation

## Security Considerations

### Access Control

- Resource paths are structured hierarchically: `/cluster/root/<node_id>` based on the node id.
- The resources are registered in `KBS1` if and only if there is a matching Machine in the cluster by the operator.
- The LUKS key is released during second boot only if node id in the resource request matches with one of the node in the
  cluster thanks to the resource policy.

## References

- [RATS Passport Mode Documentation](https://datatracker.ietf.org/doc/draft-ietf-rats-reference-interaction-models/)
- [Confidential Containers Trustee](https://github.com/confidential-containers/trustee)
- [Cluster API Machine Concepts](https://cluster-api.sigs.k8s.io/user/concepts#machine)
