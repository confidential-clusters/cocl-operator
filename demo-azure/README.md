# Demo
The demo attests a machines created using the Machine API. The demo relies on the internal cluster registry which can be exposed by following [this documentation](https://docs.redhat.com/en/documentation/openshift_container_platform/4.15/html/registry/securing-exposing-registry)
Run:
```bash
./push-images.sh
```
Install the operator and the machineset, and scale and create a machine to attest:
```bash
./install-demo.sh 
```

*Note: you need to have already an image prepared in Azure declared in image.resourceID*
The image can be built using the script and just as described in the [investigations README](https://github.com/confidential-clusters/investigations?tab=readme-ov-file#example-with-local-vms-attestation-and-disk-encryption), but changing the platform from qemu to azure. 
Then, it can be uploaded in Azure like explained in the [coreos guide](https://docs.fedoraproject.org/en-US/fedora-coreos/provisioning-azure/)
