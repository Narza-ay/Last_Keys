//! End-to-end security flows of the key hierarchy, using the public API only.

// Test helpers outside `#[test]` functions: panicking is the intended outcome.
#![allow(clippy::unwrap_used)]

use lk_core::{
    AccountKeyBundle, CoreError, DeviceIdentity, EncryptedItem, Platform, create_account,
    trusted_devices,
};
use lk_crypto::{KdfParams, MasterPassword, SymmetricKey};

const NOW: u64 = 1_764_000_000;

fn password(s: &str) -> MasterPassword {
    MasterPassword::new(s).unwrap()
}

/// Full lifecycle: account creation, vault, items, two devices, enrollment by
/// transfer, revocation, password change, recovery-key rotation.
#[test]
fn complete_account_lifecycle() {
    // --- Account creation on device A -------------------------------------
    let pw = password("Tr0ub4dor & 3 horses");
    let new = create_account(&pw, KdfParams::recommended()).unwrap();
    let account = new.keys;
    let mut bundle = new.bundle;
    let account_id = account.account_id();

    let device_a = DeviceIdentity::generate().unwrap();
    let info_a = device_a
        .public_info("Windows desktop", Platform::Windows, NOW)
        .unwrap();
    let cert_a = account.certify_device(info_a.clone(), NOW).unwrap();

    // --- Vault and items ---------------------------------------------------
    let (vault, wrapped_vault) = account.create_vault().unwrap();
    let item = vault
        .create_item(br#"{"title":"Bank","password":"s3cret"}"#)
        .unwrap();
    assert_eq!(
        vault.open_item(&item).unwrap().as_slice(),
        br#"{"title":"Bank","password":"s3cret"}"#
    );

    // The server stores only ciphertext: the plaintext never appears in the
    // serialized forms.
    let server_view = format!(
        "{}{}{}",
        serde_json::to_string(&bundle).unwrap(),
        serde_json::to_string(&wrapped_vault).unwrap(),
        serde_json::to_string(&item).unwrap()
    );
    assert!(!server_view.contains("s3cret") && !server_view.contains("Bank"));

    // --- Enroll device B from device A (trusted-device authorization) ------
    let device_b = DeviceIdentity::generate().unwrap();
    let info_b = device_b
        .public_info("Android phone", Platform::Android, NOW + 10)
        .unwrap();
    let cert_b = account.certify_device(info_b.clone(), NOW + 10).unwrap();
    let transfer = account
        .transfer_account_key(&device_a, &cert_b, &[])
        .unwrap();

    // Device B receives the account key, then completes the unlock from the
    // bundle downloaded from the server.
    let received = device_b.receive_account_key(&transfer, &info_a).unwrap();
    let account_on_b = bundle.unlock_with_account_key(received).unwrap();
    // Device B now verifies that the sender is a certified, non-revoked device.
    let certs = vec![cert_a.clone(), cert_b.clone()];
    let trusted =
        trusted_devices(&account_id, &account_on_b.signing_public_key(), &certs, &[]).unwrap();
    assert!(trusted.iter().any(|d| d.device_id == info_a.device_id));

    // Device B can read the vault.
    let vault_on_b = account_on_b.open_vault_key(&wrapped_vault).unwrap();
    assert_eq!(
        vault_on_b.open_item(&item).unwrap().as_slice(),
        br#"{"title":"Bank","password":"s3cret"}"#
    );

    // --- Revoke device B ---------------------------------------------------
    let revocation = account.revoke_device(info_b.device_id, NOW + 100).unwrap();
    let trusted = trusted_devices(
        &account_id,
        &account.signing_public_key(),
        &certs,
        std::slice::from_ref(&revocation),
    )
    .unwrap();
    assert_eq!(trusted.len(), 1);
    assert_eq!(trusted[0].device_id, info_a.device_id);
    // A revoked device can no longer receive the account key.
    assert_eq!(
        account
            .transfer_account_key(&device_a, &cert_b, std::slice::from_ref(&revocation))
            .unwrap_err(),
        CoreError::UntrustedDevice
    );

    // --- Change the master password ---------------------------------------
    let new_pw = password("a completely new passphrase");
    let (changed, new_auth) = account
        .change_password(&bundle, &new_pw, KdfParams::recommended())
        .unwrap();
    assert_ne!(new_auth.expose_secret(), new.auth_key.expose_secret());
    assert_eq!(
        changed.unlock_with_password(&pw).unwrap_err(),
        CoreError::InvalidCredentials
    );
    let reunlocked = changed.unlock_with_password(&new_pw).unwrap();
    // Same account key: existing vaults still open, nothing re-encrypted.
    reunlocked.open_vault_key(&wrapped_vault).unwrap();
    // The recovery key still works after a password change.
    changed.unlock_with_recovery_key(&new.recovery_key).unwrap();
    bundle = changed;

    // --- Rotate the recovery key ------------------------------------------
    let (rotated, new_rk, _new_rk_auth) = account.rotate_recovery_key(&bundle).unwrap();
    assert_eq!(
        rotated
            .unlock_with_recovery_key(&new.recovery_key)
            .unwrap_err(),
        CoreError::InvalidCredentials
    );
    let via_new_rk = rotated.unlock_with_recovery_key(&new_rk).unwrap();
    via_new_rk.open_vault_key(&wrapped_vault).unwrap();
    rotated.unlock_with_password(&new_pw).unwrap();
}

#[test]
fn items_cannot_be_swapped_moved_or_altered() {
    let new = create_account(&password("pw"), KdfParams::recommended()).unwrap();
    let (vault, _) = new.keys.create_vault().unwrap();
    let (other_vault, _) = new.keys.create_vault().unwrap();
    let a = vault.create_item(b"item A").unwrap();
    let b = vault.create_item(b"item B").unwrap();

    // Swap contents between two items of the same vault.
    let swapped = EncryptedItem {
        content: b.content.clone(),
        ..a.clone()
    };
    assert!(vault.open_item(&swapped).is_err());

    // Swap wrapped item keys.
    let swapped_keys = EncryptedItem {
        wrapped_item_key: b.wrapped_item_key.clone(),
        ..a.clone()
    };
    assert!(vault.open_item(&swapped_keys).is_err());

    // Relabel an item as belonging to another vault.
    let moved = EncryptedItem {
        vault_id: other_vault.vault_id(),
        ..a.clone()
    };
    assert!(other_vault.open_item(&moved).is_err());
    assert_eq!(
        vault.open_item(&moved).unwrap_err(),
        CoreError::Mismatch("vault")
    );

    // Change the item id.
    let renamed = EncryptedItem {
        item_id: b.item_id,
        ..a.clone()
    };
    assert!(vault.open_item(&renamed).is_err());

    // Flip a byte of the content ciphertext.
    let mut content = a.content.as_slice().to_vec();
    let last = content.len() - 1;
    content[last] ^= 1;
    let altered = EncryptedItem {
        content: content.into(),
        ..a.clone()
    };
    assert!(vault.open_item(&altered).is_err());
}

#[test]
fn item_update_keeps_identity_and_key() {
    let new = create_account(&password("pw"), KdfParams::recommended()).unwrap();
    let (vault, _) = new.keys.create_vault().unwrap();
    let v1 = vault.create_item(b"v1").unwrap();
    let v2 = vault.update_item(&v1, b"v2").unwrap();
    assert_eq!(v2.item_id, v1.item_id);
    assert_eq!(v2.wrapped_item_key, v1.wrapped_item_key);
    assert_ne!(v2.content, v1.content);
    assert_eq!(vault.open_item(&v2).unwrap().as_slice(), b"v2");
}

#[test]
fn vault_keys_are_bound_to_their_account() {
    let alice = create_account(&password("alice"), KdfParams::recommended()).unwrap();
    let bob = create_account(&password("bob"), KdfParams::recommended()).unwrap();
    let (_, wrapped) = alice.keys.create_vault().unwrap();
    assert_eq!(
        bob.keys.open_vault_key(&wrapped).unwrap_err(),
        CoreError::Mismatch("account")
    );
    // Relabeling the wrapped key with Bob's id does not help either.
    let mut relabeled = wrapped;
    relabeled.account_id = bob.keys.account_id();
    assert!(bob.keys.open_vault_key(&relabeled).is_err());
}

#[test]
fn device_certificates_resist_forgery_and_tampering() {
    let alice = create_account(&password("alice"), KdfParams::recommended()).unwrap();
    let mallory = create_account(&password("mallory"), KdfParams::recommended()).unwrap();
    let alice_id = alice.keys.account_id();
    let alice_pk = alice.keys.signing_public_key();

    let device = DeviceIdentity::generate().unwrap();
    let info = device.public_info("Laptop", Platform::Linux, NOW).unwrap();
    let genuine = alice.keys.certify_device(info.clone(), NOW).unwrap();
    genuine.verify(&alice_id, &alice_pk).unwrap();

    // Certificate signed by another account, relabeled with Alice's id.
    let mut forged = mallory.keys.certify_device(info.clone(), NOW).unwrap();
    forged.account_id = alice_id;
    assert_eq!(
        forged.verify(&alice_id, &alice_pk).unwrap_err(),
        CoreError::UntrustedDevice
    );

    // Tampered fields.
    let mut renamed = genuine.clone();
    renamed.device.name = "Evil".into();
    assert_eq!(
        renamed.verify(&alice_id, &alice_pk).unwrap_err(),
        CoreError::UntrustedDevice
    );
    let attacker_device = DeviceIdentity::generate().unwrap();
    let attacker_info = attacker_device
        .public_info("Laptop", Platform::Linux, NOW)
        .unwrap();
    let mut rekeyed = genuine.clone();
    rekeyed.device.encryption_public_key = attacker_info.encryption_public_key.clone();
    assert_eq!(
        rekeyed.verify(&alice_id, &alice_pk).unwrap_err(),
        CoreError::UntrustedDevice
    );
    let mut replatformed = genuine.clone();
    replatformed.device.platform = Platform::Ios;
    assert!(replatformed.verify(&alice_id, &alice_pk).is_err());

    // A server injecting a forged certificate makes the whole list fail.
    let list = vec![genuine.clone(), forged];
    assert!(trusted_devices(&alice_id, &alice_pk, &list, &[]).is_err());

    // Conflicting certificates for the same device id are rejected.
    let mut conflicting_info = attacker_info;
    conflicting_info.device_id = info.device_id;
    let conflicting = alice.keys.certify_device(conflicting_info, NOW).unwrap();
    let list = vec![genuine.clone(), conflicting];
    assert_eq!(
        trusted_devices(&alice_id, &alice_pk, &list, &[]).unwrap_err(),
        CoreError::InconsistentKeyMaterial
    );

    // A revocation forged by another account makes the list fail.
    let mut forged_rev = mallory.keys.revoke_device(info.device_id, NOW).unwrap();
    forged_rev.account_id = alice_id;
    assert!(trusted_devices(&alice_id, &alice_pk, &[genuine], &[forged_rev]).is_err());
}

#[test]
fn account_key_transfer_is_bound_to_sender_and_recipient() {
    let new = create_account(&password("pw"), KdfParams::recommended()).unwrap();
    let account = new.keys;
    let a = DeviceIdentity::generate().unwrap();
    let b = DeviceIdentity::generate().unwrap();
    let c = DeviceIdentity::generate().unwrap();
    let info_a = a.public_info("A", Platform::MacOs, NOW).unwrap();
    let info_b = b.public_info("B", Platform::Ios, NOW).unwrap();
    let info_c = c.public_info("C", Platform::Web, NOW).unwrap();
    let cert_b = account.certify_device(info_b, NOW).unwrap();

    // Refuses to transfer to a device certified by another account.
    let other = create_account(&password("other"), KdfParams::recommended()).unwrap();
    let foreign_cert = other.keys.certify_device(info_c.clone(), NOW).unwrap();
    assert_eq!(
        account
            .transfer_account_key(&a, &foreign_cert, &[])
            .unwrap_err(),
        CoreError::UntrustedDevice
    );

    // Refuses when the revocation list has been tampered with.
    let mut forged_rev = other.keys.revoke_device(info_a.device_id, NOW).unwrap();
    forged_rev.account_id = account.account_id();
    assert_eq!(
        account
            .transfer_account_key(&a, &cert_b, &[forged_rev])
            .unwrap_err(),
        CoreError::UntrustedDevice
    );

    let transfer = account.transfer_account_key(&a, &cert_b, &[]).unwrap();

    // Another device cannot use it, even by relabeling the recipient.
    assert_eq!(
        c.receive_account_key(&transfer, &info_a).unwrap_err(),
        CoreError::Mismatch("recipient device")
    );
    let mut redirected = transfer.clone();
    redirected.to_device = c.device_id();
    assert!(c.receive_account_key(&redirected, &info_a).is_err());

    // The claimed sender must match and its signature must verify.
    assert_eq!(
        b.receive_account_key(&transfer, &info_c).unwrap_err(),
        CoreError::Mismatch("sender device")
    );
    let mut spoofed_sender = info_c.clone();
    spoofed_sender.device_id = info_a.device_id;
    assert!(b.receive_account_key(&transfer, &spoofed_sender).is_err());

    // Tampering with the sealed key breaks the signature.
    let mut tampered = transfer.clone();
    let mut sealed = tampered.sealed_account_key.as_slice().to_vec();
    sealed[40] ^= 1;
    tampered.sealed_account_key = sealed.into();
    assert!(b.receive_account_key(&tampered, &info_a).is_err());

    // The genuine transfer works.
    let key = b.receive_account_key(&transfer, &info_a).unwrap();
    new.bundle.unlock_with_account_key(key).unwrap();
}

#[test]
fn received_key_from_another_account_does_not_unlock_bundle() {
    let alice = create_account(&password("alice"), KdfParams::recommended()).unwrap();
    let mallory = create_account(&password("mallory"), KdfParams::recommended()).unwrap();
    let sender = DeviceIdentity::generate().unwrap();
    let sender_info = sender.public_info("M", Platform::Linux, NOW).unwrap();
    let victim = DeviceIdentity::generate().unwrap();
    let victim_info = victim.public_info("V", Platform::Linux, NOW).unwrap();
    // Mallory certifies the victim's device and pushes her own account key.
    let cert = mallory.keys.certify_device(victim_info, NOW).unwrap();
    let transfer = mallory
        .keys
        .transfer_account_key(&sender, &cert, &[])
        .unwrap();
    let key = victim.receive_account_key(&transfer, &sender_info).unwrap();
    // It does not unlock Alice's bundle.
    assert_eq!(
        alice.bundle.unlock_with_account_key(key).unwrap_err(),
        CoreError::InconsistentKeyMaterial
    );
}

#[test]
fn device_identity_storage_roundtrip() {
    let device = DeviceIdentity::generate().unwrap();
    let storage_key = SymmetricKey::generate().unwrap();
    let sealed = device.seal(&storage_key).unwrap();
    let json = serde_json::to_string(&sealed).unwrap();
    let restored =
        DeviceIdentity::open(&serde_json::from_str(&json).unwrap(), &storage_key).unwrap();
    assert_eq!(restored.device_id(), device.device_id());
    assert_eq!(
        restored.public_info("x", Platform::Cli, NOW).unwrap(),
        device.public_info("x", Platform::Cli, NOW).unwrap()
    );
    assert!(DeviceIdentity::open(&sealed, &SymmetricKey::generate().unwrap()).is_err());
}

#[test]
fn device_identity_sealed_under_account_key() {
    let alice = create_account(&password("alice"), KdfParams::recommended()).unwrap();
    let bob = create_account(&password("bob"), KdfParams::recommended()).unwrap();
    let device = DeviceIdentity::generate().unwrap();
    let sealed = alice.keys.seal_device_identity(&device).unwrap();
    let restored = alice.keys.open_device_identity(&sealed).unwrap();
    assert_eq!(restored.device_id(), device.device_id());
    assert!(bob.keys.open_device_identity(&sealed).is_err());
}

#[test]
fn device_names_are_bounded() {
    let device = DeviceIdentity::generate().unwrap();
    let long = "x".repeat(lk_core::device::MAX_DEVICE_NAME_BYTES + 1);
    assert_eq!(
        device.public_info(&long, Platform::Linux, NOW).unwrap_err(),
        CoreError::FieldTooLong("device name")
    );
}

#[test]
fn serialized_structures_roundtrip_through_json() {
    let new = create_account(&password("pw"), KdfParams::recommended()).unwrap();
    let (vault, wrapped) = new.keys.create_vault().unwrap();
    let item = vault.create_item(b"payload").unwrap();
    let item2: EncryptedItem =
        serde_json::from_str(&serde_json::to_string(&item).unwrap()).unwrap();
    assert_eq!(item2, item);
    let bundle2: AccountKeyBundle =
        serde_json::from_str(&serde_json::to_string(&new.bundle).unwrap()).unwrap();
    let keys = bundle2.unlock_with_password(&password("pw")).unwrap();
    let vault2 = keys
        .open_vault_key(&serde_json::from_str(&serde_json::to_string(&wrapped).unwrap()).unwrap())
        .unwrap();
    assert_eq!(vault2.open_item(&item2).unwrap().as_slice(), b"payload");
}
