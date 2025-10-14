// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
//
// SPDX-License-Identifier: MIT

mod common;

virt_test! {
async fn test_attestation() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    let (_private_key, public_key, key_path) = common::generate_ssh_key_pair()?;
    test_ctx.info(format!("Generated SSH key pair and added to ssh-agent: {:?}", key_path));

    let vm_name = "test-coreos-vm";
    let register_server_url = format!(
        "http://register-server.{}.svc.cluster.local:8000/ignition-clevis-pin-trustee",
        namespace
    );
    let image = "quay.io/confidential-clusters/fedora-coreos-kubevirt:latest";

    test_ctx.info(format!("Creating VM: {}", vm_name));
    common::create_kubevirt_vm(
        client,
        namespace,
        vm_name,
        &public_key,
        &register_server_url,
        image,
    )
    .await?;

    test_ctx.info(format!("Waiting for VM {} to reach Running state", vm_name));
    common::wait_for_vm_running(client, namespace, vm_name, 120).await?;
    test_ctx.info(format!("VM {} is Running", vm_name));

    test_ctx.info(format!("Waiting for SSH access to VM {}", vm_name));
    common::wait_for_vm_ssh_ready(namespace, vm_name, &key_path, 300).await?;
    test_ctx.info("SSH access is ready");

    test_ctx.info("Verifying encrypted root device");
    let has_encrypted_root = common::verify_encrypted_root(namespace, vm_name, &key_path).await?;

    let _ = std::fs::remove_file(&key_path);

    assert!(
        has_encrypted_root,
        "VM should have an encrypted root device (attestation failed)"
    );
    test_ctx.info("Attestation successful: encrypted root device verified");

    test_ctx.cleanup().await?;

    Ok(())
}
}

virt_test! {
async fn test_parallel_vm_attestation() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    test_ctx.info("Testing parallel VM attestation - launching 2 VMs simultaneously");

    // Generate SSH keys for both VMs
    let (_private_key1, public_key1, key_path1) = common::generate_ssh_key_pair()?;
    let (_private_key2, public_key2, key_path2) = common::generate_ssh_key_pair()?;
    test_ctx.info("Generated SSH key pairs for both VMs");

    let register_server_url = format!(
        "http://register-server.{}.svc.cluster.local:8000/ignition-clevis-pin-trustee",
        namespace
    );
    let image = "quay.io/confidential-clusters/fedora-coreos-kubevirt:latest";

    // Launch both VMs in parallel
    let vm1_name = "test-coreos-vm1";
    let vm2_name = "test-coreos-vm2";

    test_ctx.info("Creating VM1 and VM2 in parallel");
    let (vm1_result, vm2_result) = tokio::join!(
        common::create_kubevirt_vm(
            client,
            namespace,
            vm1_name,
            &public_key1,
            &register_server_url,
            image,
        ),
        common::create_kubevirt_vm(
            client,
            namespace,
            vm2_name,
            &public_key2,
            &register_server_url,
            image,
        )
    );

    vm1_result?;
    vm2_result?;
    test_ctx.info("Both VMs created successfully");

    // Wait for both VMs to reach Running state in parallel
    test_ctx.info("Waiting for both VMs to reach Running state");
    let (vm1_running, vm2_running) = tokio::join!(
        common::wait_for_vm_running(client, namespace, vm1_name, 300),
        common::wait_for_vm_running(client, namespace, vm2_name, 300)
    );

    vm1_running?;
    vm2_running?;
    test_ctx.info("Both VMs are Running");

    // Wait for SSH access on both VMs in parallel
    test_ctx.info("Waiting for SSH access on both VMs");
    let (ssh1_ready, ssh2_ready) = tokio::join!(
        common::wait_for_vm_ssh_ready(namespace, vm1_name, &key_path1, 300),
        common::wait_for_vm_ssh_ready(namespace, vm2_name, &key_path2, 300)
    );

    ssh1_ready?;
    ssh2_ready?;
    test_ctx.info("SSH access ready on both VMs");

    // Verify attestation on both VMs in parallel
    test_ctx.info("Verifying encrypted root on both VMs");
    let (vm1_encrypted, vm2_encrypted) = tokio::join!(
        common::verify_encrypted_root(namespace, vm1_name, &key_path1),
        common::verify_encrypted_root(namespace, vm2_name, &key_path2)
    );

    let vm1_has_encrypted_root = vm1_encrypted?;
    let vm2_has_encrypted_root = vm2_encrypted?;

    // Clean up SSH keys
    let _ = std::fs::remove_file(&key_path1);
    let _ = std::fs::remove_file(&key_path2);

    assert!(
        vm1_has_encrypted_root,
        "VM1 should have an encrypted root device (attestation failed)"
    );
    assert!(
        vm2_has_encrypted_root,
        "VM2 should have an encrypted root device (attestation failed)"
    );

    test_ctx.info("Both VMs successfully attested with encrypted root devices");

    test_ctx.cleanup().await?;

    Ok(())
}
}

virt_test! {
async fn test_vm_reboot_attestation() -> anyhow::Result<()> {
    let test_ctx = setup!().await?;
    let client = test_ctx.client();
    let namespace = test_ctx.namespace();

    test_ctx.info("Testing VM reboot - VM should successfully boot after multiple reboots");

    let (_private_key, public_key, key_path) = common::generate_ssh_key_pair()?;
    test_ctx.info(format!("Generated SSH key pair: {:?}", key_path));

    let vm_name = "test-coreos-reboot";
    let register_server_url = format!(
        "http://register-server.{}.svc.cluster.local:8000/ignition-clevis-pin-trustee",
        namespace
    );
    let image = "quay.io/confidential-clusters/fedora-coreos-kubevirt:latest";

    test_ctx.info(format!("Creating VM: {}", vm_name));
    common::create_kubevirt_vm(
        client,
        namespace,
        vm_name,
        &public_key,
        &register_server_url,
        image,
    )
    .await?;

    test_ctx.info("Waiting for VM to reach Running state");
    common::wait_for_vm_running(client, namespace, vm_name, 300).await?;

    test_ctx.info("Waiting for SSH access");
    common::wait_for_vm_ssh_ready(namespace, vm_name, &key_path, 300).await?;

    test_ctx.info("Verifying initial encrypted root device");
    let has_encrypted_root = common::verify_encrypted_root(namespace, vm_name, &key_path).await?;
    assert!(
        has_encrypted_root,
        "VM should have encrypted root device on initial boot"
    );
    test_ctx.info("Initial boot: attestation successful");

    // Perform multiple reboots
    let num_reboots = 3;
    for i in 1..=num_reboots {
        test_ctx.info(format!("Performing reboot {} of {}", i, num_reboots));

        // Reboot the VM via SSH
        let _reboot_result = common::virtctl_ssh_exec(
            namespace,
            vm_name,
            &key_path,
            "sudo systemctl reboot"
        ).await;

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        test_ctx.info(format!("Waiting for SSH access after reboot {}", i));
        common::wait_for_vm_ssh_ready(namespace, vm_name, &key_path, 300).await?;

        // Verify encrypted root is still present after reboot
        test_ctx.info(format!("Verifying encrypted root after reboot {}", i));
        let has_encrypted_root = common::verify_encrypted_root(namespace, vm_name, &key_path).await?;
        assert!(
            has_encrypted_root,
            "VM should have encrypted root device after reboot {}", i
        );
        test_ctx.info(format!("Reboot {}: attestation successful", i));
    }

    // Clean up SSH key
    let _ = std::fs::remove_file(&key_path);

    test_ctx.info(format!(
        "VM successfully rebooted {} times with encrypted root device maintained",
        num_reboots
    ));

    test_ctx.cleanup().await?;

    Ok(())
}
}
