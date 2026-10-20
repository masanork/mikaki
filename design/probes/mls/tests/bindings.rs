mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_mls_probe::{BoundMlsClient, Invitation, MlsProbeClient, trust::*};
use openmls_traits::OpenMlsProvider;
use serde_json::{Value, json};
use support::*;
use zeroize::Zeroizing;

#[test]
fn unconfirmed_revocation_is_not_a_pin_but_cannot_be_bypassed_after_restore() {
    let pair = Pair::new();
    let mut client =
        BoundMlsClient::new(&pair.alice_id.credential().unwrap(), &pair.authorities).unwrap();
    client
        .bind_self(&pair.a.enroll(&client, &pair.alice_id, NOW), NOW)
        .unwrap();
    let revoked = pair.b.binding(
        &pair.bob_id,
        &pair.bob.public_key(),
        2,
        Status::Revoked,
        NOW,
    );
    assert_eq!(client.review_peer(&revoked, NOW).unwrap(), "revoked");
    let mut restored = pair.reload(&client);
    assert!(
        serde_json::from_str::<Value>(&restored.peer_trust(NOW).unwrap()).unwrap()["peer"]
            .is_null()
    );
    let active = pair
        .b
        .binding(&pair.bob_id, &pair.bob.public_key(), 3, Status::Active, NOW);
    assert!(restored.review_peer(&active, NOW).is_err());
    assert!(
        restored
            .confirm_peer(&active, &pair.bob.fingerprint().unwrap(), NOW)
            .is_err()
    );
    let id = device(BOB, 2, 2);
    let replacement = BoundMlsClient::new(&id.credential().unwrap(), &pair.authorities).unwrap();
    let token = pair
        .b
        .binding(&id, &replacement.public_key(), 4, Status::Active, NOW);
    assert_eq!(restored.review_peer(&token, NOW).unwrap(), "unconfirmed");
    restored
        .confirm_peer(&token, &replacement.fingerprint().unwrap(), NOW)
        .unwrap();
}

#[test]
fn verified_display_does_not_establish_first_trust_or_accept_another_slot() {
    let pair = Pair::new();
    let mut client =
        BoundMlsClient::new(&pair.alice_id.credential().unwrap(), &pair.authorities).unwrap();
    client
        .bind_self(&pair.a.enroll(&client, &pair.alice_id, NOW), NOW)
        .unwrap();
    let display: Value =
        serde_json::from_str(&client.inspect_peer(&pair.bob_token, NOW).unwrap()).unwrap();
    assert_eq!(display["fingerprint"], pair.bob.fingerprint().unwrap());
    assert_eq!(
        display["device"],
        serde_json::to_value(&pair.bob_id).unwrap()
    );
    let state: Value = serde_json::from_str(&client.peer_trust(NOW).unwrap()).unwrap();
    assert!(state["peer"].is_null());
    assert_eq!(state["group_usable"], false);
    assert!(client.outgoing_context(NOW, true).is_err());
    assert!(client.inspect_peer(&pair.alice_token, NOW).is_err());
    let forged = pair
        .a
        .binding(&pair.bob_id, &pair.bob.public_key(), 1, Status::Active, NOW);
    assert!(client.inspect_peer(&forged, NOW).is_err());
    client
        .confirm_peer(&pair.bob_token, &pair.bob.fingerprint().unwrap(), NOW)
        .unwrap();
    let other = pair.b.binding(
        &device(BOB, 3, 1),
        &pair.bob.public_key(),
        1,
        Status::Active,
        NOW,
    );
    assert!(client.inspect_peer(&other, NOW).is_err());
}

#[test]
fn public_review_tracks_changed_and_accepted_keys_without_reauthorizing_old_leaves() {
    let mut pair = Pair::new();
    pair.join();
    let old = pair.bob.fingerprint().unwrap();
    let id = device(BOB, 2, 2);
    let replacement = BoundMlsClient::new(&id.credential().unwrap(), &pair.authorities).unwrap();
    let token = pair
        .b
        .binding(&id, &replacement.public_key(), 2, Status::Active, NOW + 1);
    assert_eq!(
        pair.alice.observe_binding(&token, NOW + 1).unwrap(),
        "key_changed"
    );
    let state: Value = serde_json::from_str(&pair.alice.peer_trust(NOW + 1).unwrap()).unwrap();
    assert_eq!(state["peer"]["accepted"]["fingerprint"], old);
    assert_eq!(
        state["peer"]["latest"]["fingerprint"],
        replacement.fingerprint().unwrap()
    );
    assert_eq!(state["peer"]["state"], "key_changed");
    let mut restored = pair.reload(&pair.alice);
    restored
        .accept_key_change(&token, &old, &replacement.fingerprint().unwrap(), NOW + 1)
        .unwrap();
    let state: Value = serde_json::from_str(&restored.peer_trust(NOW + 1).unwrap()).unwrap();
    assert_eq!(state["peer"]["state"], "current");
    assert_eq!(state["group_usable"], false);
    assert!(
        restored
            .send("old group is still blocked", NOW + 1)
            .is_err()
    );
}

#[test]
fn public_review_keeps_registry_conflicts_revocation_and_expiry_distinct() {
    let mut pair = Pair::new();
    let bogus_key = MlsProbeClient::new("conflicting key").unwrap();
    let conflicting = pair.b.binding(
        &pair.bob_id,
        &bogus_key.public_key(),
        1,
        Status::Active,
        NOW,
    );
    assert_eq!(
        pair.alice.observe_binding(&conflicting, NOW).unwrap(),
        "registry_conflict"
    );
    let state: Value = serde_json::from_str(&pair.alice.peer_trust(NOW).unwrap()).unwrap();
    assert_eq!(state["peer"]["state"], "registry_conflict");
    let revoked = pair.b.binding(
        &pair.bob_id,
        &pair.bob.public_key(),
        2,
        Status::Revoked,
        NOW + 1,
    );
    pair.alice.observe_binding(&revoked, NOW + 1).unwrap();
    let state: Value =
        serde_json::from_str(&pair.reload(&pair.alice).peer_trust(NOW + 1).unwrap()).unwrap();
    assert_eq!(state["peer"]["state"], "revoked");
    let fresh = Pair::new();
    let state: Value = serde_json::from_str(&fresh.alice.peer_trust(NOW + 301).unwrap()).unwrap();
    assert_eq!(state["peer"]["state"], "expired");
}

#[test]
fn issuer_authenticated_devices_exchange_structured_sender_identities_after_restore() {
    let mut pair = Pair::new();
    pair.join();
    let mut alice = pair.reload(&pair.alice);
    let mut bob = pair.reload(&pair.bob);
    let message = alice.send("署名された端末の会話", NOW + 1).unwrap();
    let received: Value = serde_json::from_str(&bob.receive(&message, NOW + 1).unwrap()).unwrap();
    assert_eq!(
        received,
        json!({"kind":"application", "sender":pair.alice_id, "text":"署名された端末の会話"})
    );
    let update = alice.update(NOW + 1).unwrap();
    alice.merge_pending(NOW + 1).unwrap();
    bob.receive(&update, NOW + 1).unwrap();
    alice
        .receive(&bob.send("更新後", NOW + 1).unwrap(), NOW + 1)
        .unwrap();
}

#[test]
fn account_issuer_device_generation_and_nonce_are_bound_to_registration_proof() {
    let issuer = Issuer::new(ALICE);
    let expected = device(ALICE, 1, 1);
    let authorities = serde_json::to_string(&[issuer.authority()]).unwrap();
    let mut client = BoundMlsClient::new(&expected.credential().unwrap(), &authorities).unwrap();
    assert!(client.key_package(NOW).is_err());
    assert!(client.create_group(&GROUP, NOW).is_err());
    let nonce = B64.encode([5; 32]);
    let proof = client.registration_proof(&nonce, NOW).unwrap();
    assert_eq!(
        verify_registration(&proof, &expected, &nonce, NOW, issuer.provider.crypto()).unwrap(),
        client.public_key()
    );
    for changed in [device(ALICE, 2, 1), device(BOB, 1, 1), device(ALICE, 1, 2)] {
        assert!(
            verify_registration(&proof, &changed, &nonce, NOW, issuer.provider.crypto()).is_err()
        );
    }
    let mut changed = expected.clone();
    changed.device_id = device(ALICE, 2, 1).device_id;
    assert!(verify_registration(&proof, &changed, &nonce, NOW, issuer.provider.crypto()).is_err());
    assert!(
        verify_registration(
            &proof,
            &expected,
            &B64.encode([6; 32]),
            NOW,
            issuer.provider.crypto()
        )
        .is_err()
    );
    assert!(
        verify_registration(
            &proof,
            &expected,
            &nonce,
            NOW + 60,
            issuer.provider.crypto()
        )
        .is_err()
    );
    let mut modified = proof.into_bytes();
    modified[10] ^= 1;
    assert!(
        verify_registration(
            std::str::from_utf8(&modified).unwrap(),
            &expected,
            &nonce,
            NOW,
            issuer.provider.crypto()
        )
        .is_err()
    );
}

#[test]
fn initial_fingerprint_confirmation_cannot_be_omitted_or_replaced_by_directory_data() {
    let pair = Pair::new();
    let mut client =
        BoundMlsClient::new(&pair.alice_id.credential().unwrap(), &pair.authorities).unwrap();
    let token = pair.a.enroll(&client, &pair.alice_id, NOW);
    client.bind_self(&token, NOW).unwrap();
    assert!(
        client
            .confirm_peer(&pair.bob_token, "directory-supplied-unconfirmed", NOW)
            .is_err()
    );
    client
        .confirm_peer(&pair.bob_token, &pair.bob.fingerprint().unwrap(), NOW)
        .unwrap();
    assert!(
        client
            .confirm_peer(&pair.bob_token, &pair.bob.fingerprint().unwrap(), NOW)
            .is_err()
    );
}

#[test]
fn same_identity_impostor_key_package_is_rejected_before_group_mutation() {
    let mut pair = Pair::new();
    pair.alice.create_group(&GROUP, NOW).unwrap();
    let impostor = MlsProbeClient::new(&pair.bob_id.credential().unwrap()).unwrap();
    let before = pair.alice.epoch().unwrap();
    assert_eq!(
        pair.alice
            .invite(&impostor.key_package().unwrap(), NOW)
            .unwrap_err(),
        "device_key_mismatch"
    );
    assert_eq!(pair.alice.epoch().unwrap(), before);
    let good_package = pair.bob.key_package(NOW).unwrap();
    pair.alice.invite(&good_package, NOW).unwrap();
    pair.alice.merge_pending(NOW).unwrap();
}

#[test]
fn substituted_welcome_is_rejected_without_consuming_real_join_secrets() {
    let mut pair = Pair::new();
    let package = pair.bob.key_package(NOW).unwrap();
    let mut impostor = MlsProbeClient::new(&pair.alice_id.credential().unwrap()).unwrap();
    impostor.create_group(&GROUP).unwrap();
    let evil: Invitation = serde_json::from_str(&impostor.invite(&package).unwrap()).unwrap();
    impostor.merge_pending().unwrap();
    assert_eq!(
        pair.bob.join(&evil.welcome, &GROUP, NOW).unwrap_err(),
        "device_key_mismatch"
    );
    pair.alice.create_group(&GROUP, NOW).unwrap();
    let good: Invitation =
        serde_json::from_str(&pair.alice.invite(&package, NOW).unwrap()).unwrap();
    pair.alice.merge_pending(NOW).unwrap();
    pair.bob.join(&good.welcome, &GROUP, NOW).unwrap();
    pair.bob
        .receive(&pair.alice.send("real sender", NOW).unwrap(), NOW)
        .unwrap();
}

#[test]
fn signed_revocation_blocks_messages_and_reenrollment_and_survives_restore() {
    let mut pair = Pair::new();
    pair.join();
    let revoked = pair.a.binding(
        &pair.alice_id,
        &pair.alice.public_key(),
        2,
        Status::Revoked,
        NOW + 1,
    );
    assert_eq!(
        pair.bob.observe_binding(&revoked, NOW + 1).unwrap(),
        "revoked"
    );
    let mut bob = pair.reload(&pair.bob);
    let message = pair.alice.send("unaware revoked device", NOW + 1).unwrap();
    assert_eq!(
        bob.receive(&message, NOW + 1).unwrap_err(),
        "device_revoked"
    );
    assert!(
        bob.send("do not encrypt for revoked member", NOW + 1)
            .is_err()
    );
    assert!(bob.observe_binding(&pair.alice_token, NOW + 1).is_err());
    assert!(
        bob.confirm_peer(
            &pair.alice_token,
            &pair.alice.fingerprint().unwrap(),
            NOW + 1
        )
        .is_err()
    );
    let reactivation = pair.a.binding(
        &pair.alice_id,
        &pair.alice.public_key(),
        3,
        Status::Active,
        NOW + 1,
    );
    assert_eq!(
        bob.observe_binding(&reactivation, NOW + 1).unwrap_err(),
        "device_revoked"
    );
    // Revocation must not prevent an active owner removing that member.
    bob.remove_peer(NOW + 1).unwrap();
    bob.merge_pending(NOW + 1).unwrap();
    bob.send("only remaining active device", NOW + 1).unwrap();
}

#[test]
fn own_revocation_blocks_key_packages_sends_and_updates() {
    let mut pair = Pair::new();
    pair.join();
    let revoked = pair.a.binding(
        &pair.alice_id,
        &pair.alice.public_key(),
        2,
        Status::Revoked,
        NOW + 1,
    );
    assert_eq!(
        pair.alice.observe_binding(&revoked, NOW + 1).unwrap(),
        "revoked"
    );
    assert!(pair.alice.key_package(NOW + 1).is_err());
    assert!(pair.alice.send("revoked", NOW + 1).is_err());
    assert!(pair.alice.update(NOW + 1).is_err());
}

#[test]
fn key_replacement_freezes_old_pin_and_requires_exact_review_and_new_group_state() {
    let mut pair = Pair::new();
    pair.join();
    let new_id = device(BOB, 2, 2);
    let mut replacement =
        BoundMlsClient::new(&new_id.credential().unwrap(), &pair.authorities).unwrap();
    let token = pair.b.binding(
        &new_id,
        &replacement.public_key(),
        2,
        Status::Active,
        NOW + 1,
    );
    let old = pair.bob.fingerprint().unwrap();
    let new = replacement.fingerprint().unwrap();
    assert_eq!(
        pair.alice.observe_binding(&token, NOW + 1).unwrap(),
        "key_changed"
    );
    let mut alice = pair.reload(&pair.alice);
    assert!(alice.send("key change pending", NOW + 1).is_err());
    assert!(alice.observe_binding(&pair.bob_token, NOW + 1).is_err());
    assert!(
        alice
            .accept_key_change(&token, "wrong old fingerprint", &new, NOW + 1)
            .is_err()
    );
    assert!(
        alice
            .accept_key_change(&token, &old, "wrong new fingerprint", NOW + 1)
            .is_err()
    );
    alice
        .accept_key_change(&token, &old, &new, NOW + 1)
        .unwrap();
    // Reviewing an account's new key must not authenticate the old MLS member.
    assert!(alice.send("old group is still obsolete", NOW + 1).is_err());
    assert!(
        alice
            .receive(&pair.bob.send("retired key", NOW + 1).unwrap(), NOW + 1)
            .is_err()
    );
    assert!(
        alice
            .accept_key_change(&pair.bob_token, &new, &old, NOW + 1)
            .is_err()
    );
    // Explicit removal/re-invitation transitions the MLS membership. Review
    // alone never opens the old membership to the new key or the old key again.
    replacement.bind_self(&token, NOW + 1).unwrap();
    replacement
        .confirm_peer(
            &pair.alice_token,
            &pair.alice.fingerprint().unwrap(),
            NOW + 1,
        )
        .unwrap();
    alice.remove_peer(NOW + 1).unwrap();
    alice.merge_pending(NOW + 1).unwrap();
    let invitation: Invitation = serde_json::from_str(
        &alice
            .invite(&replacement.key_package(NOW + 1).unwrap(), NOW + 1)
            .unwrap(),
    )
    .unwrap();
    alice.merge_pending(NOW + 1).unwrap();
    replacement
        .join(&invitation.welcome, &GROUP, NOW + 1)
        .unwrap();
    let future = alice
        .send("replacement joined explicitly", NOW + 1)
        .unwrap();
    assert!(pair.bob.receive(&future, NOW + 1).is_err());
    replacement.receive(&future, NOW + 1).unwrap();
    let reply: Value = serde_json::from_str(
        &alice
            .receive(
                &replacement.send("generation two", NOW + 1).unwrap(),
                NOW + 1,
            )
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["sender"], serde_json::to_value(new_id).unwrap());
}

#[test]
fn expiry_and_clock_rollback_fail_closed_and_current_same_key_bindings_can_refresh() {
    let mut pair = Pair::new();
    pair.join();
    assert_eq!(
        pair.alice.send("expired", NOW + 300).unwrap_err(),
        "binding_not_current"
    );
    assert_eq!(
        pair.alice.send("rewind", NOW).unwrap_err(),
        "clock_rollback"
    );
    let alice_token = pair.a.binding(
        &pair.alice_id,
        &pair.alice.public_key(),
        1,
        Status::Active,
        NOW + 300,
    );
    let bob_token = pair.b.binding(
        &pair.bob_id,
        &pair.bob.public_key(),
        1,
        Status::Active,
        NOW + 300,
    );
    pair.alice.observe_binding(&alice_token, NOW + 300).unwrap();
    pair.alice.observe_binding(&bob_token, NOW + 300).unwrap();
    pair.bob.observe_binding(&alice_token, NOW + 300).unwrap();
    pair.bob.observe_binding(&bob_token, NOW + 300).unwrap();
    pair.bob
        .receive(&pair.alice.send("fresh", NOW + 300).unwrap(), NOW + 300)
        .unwrap();
    let mut alice = pair.reload(&pair.alice);
    assert!(alice.send("restored clock rewind", NOW).is_err());
}

#[test]
fn issuer_keys_and_namespaces_cannot_be_taken_from_the_binding_or_checkpoint() {
    let mut pair = Pair::new();
    let rogue = Issuer::new(ALICE);
    let token = rogue.binding(
        &pair.alice_id,
        &pair.alice.public_key(),
        2,
        Status::Revoked,
        NOW,
    );
    assert!(pair.alice.observe_binding(&token, NOW).is_err());
    let state = Zeroizing::new(pair.alice.checkpoint().unwrap());
    let authorities = serde_json::to_string(&[rogue.authority(), pair.b.authority()]).unwrap();
    assert!(BoundMlsClient::restore(&state, &authorities).is_err());
    let different_account = pair.a.binding(
        &device(ALICE, 9, 1),
        &pair.alice.public_key(),
        1,
        Status::Active,
        NOW,
    );
    assert!(pair.alice.observe_binding(&different_account, NOW).is_err());
}

#[test]
fn jwt_header_claims_sizes_and_canonical_encodings_are_strict() {
    let mut pair = Pair::new();
    let payload = serde_json::from_slice::<Value>(
        &decode(pair.alice_token.split('.').nth(1).unwrap()).unwrap(),
    )
    .unwrap();
    for field in ["alg", "typ", "kid"] {
        let mut header = pair.a.header();
        header[field] = "unexpected".into();
        assert!(
            pair.alice
                .observe_binding(&pair.a.sign(header, payload.clone()), NOW)
                .is_err()
        );
    }
    for extra in ["jwk", "jku", "x5u", "crit", "b64"] {
        let mut header = pair.a.header();
        header[extra] = json!(true);
        assert!(
            pair.alice
                .observe_binding(&pair.a.sign(header, payload.clone()), NOW)
                .is_err()
        );
    }
    for (field, value) in [
        ("aud", json!("another-product")),
        ("revision", json!(0)),
        ("revision", json!(9_007_199_254_740_992u64)),
        ("iat", json!(NOW + 1)),
        ("exp", json!(NOW)),
        ("exp", json!(NOW + 301)),
        ("unknown", json!(true)),
    ] {
        let mut changed = payload.clone();
        changed[field] = value;
        assert!(
            pair.alice
                .observe_binding(&pair.a.sign(pair.a.header(), changed), NOW)
                .is_err()
        );
    }
    assert!(pair.alice.observe_binding(&"a".repeat(8193), NOW).is_err());
    let parts: Vec<_> = pair.alice_token.split('.').collect();
    let padded = format!("{}=.{}.{}", parts[0], parts[1], parts[2]);
    assert!(pair.alice.observe_binding(&padded, NOW).is_err());
}

#[test]
fn same_generation_substitution_and_registry_equivocation_never_silently_restore_trust() {
    let mut pair = Pair::new();
    pair.join();
    let impostor = MlsProbeClient::new(&pair.bob_id.credential().unwrap()).unwrap();
    // Even signed directory mistakes/conflicts must freeze the previously
    // accepted key; refreshing the old key cannot dismiss the review task.
    let conflict = pair.b.binding(
        &pair.bob_id,
        &impostor.public_key(),
        1,
        Status::Active,
        NOW + 1,
    );
    assert_eq!(
        pair.alice.observe_binding(&conflict, NOW + 1).unwrap(),
        "registry_conflict"
    );
    let restored = pair.b.binding(
        &pair.bob_id,
        &pair.bob.public_key(),
        2,
        Status::Active,
        NOW + 1,
    );
    assert_eq!(
        pair.alice.observe_binding(&restored, NOW + 1).unwrap(),
        "key_changed"
    );
    let mut alice = pair.reload(&pair.alice);
    assert!(alice.send("review still required", NOW + 1).is_err());
    let changed = pair.b.binding(
        &pair.bob_id,
        &impostor.public_key(),
        3,
        Status::Active,
        NOW + 1,
    );
    assert_eq!(
        alice.observe_binding(&changed, NOW + 1).unwrap(),
        "key_changed"
    );
    let old_again = pair.b.binding(
        &pair.bob_id,
        &pair.bob.public_key(),
        4,
        Status::Active,
        NOW + 1,
    );
    assert_eq!(
        alice.observe_binding(&old_again, NOW + 1).unwrap(),
        "key_changed"
    );
    assert!(alice.send("must not clear automatically", NOW + 1).is_err());
}

#[test]
fn reviewing_a_replacement_cannot_reactivate_its_revoked_generation() {
    let mut pair = Pair::new();
    pair.join();
    let next_id = device(BOB, 2, 2);
    let replacement =
        BoundMlsClient::new(&next_id.credential().unwrap(), &pair.authorities).unwrap();
    let revoked = pair.b.binding(
        &next_id,
        &replacement.public_key(),
        2,
        Status::Revoked,
        NOW + 1,
    );
    assert_eq!(
        pair.alice.observe_binding(&revoked, NOW + 1).unwrap(),
        "revoked"
    );
    let active = pair.b.binding(
        &next_id,
        &replacement.public_key(),
        3,
        Status::Active,
        NOW + 1,
    );
    assert!(
        pair.alice
            .accept_key_change(
                &active,
                &pair.bob.fingerprint().unwrap(),
                &replacement.fingerprint().unwrap(),
                NOW + 1
            )
            .is_err()
    );
}

#[test]
fn authenticated_peer_cannot_add_an_unapproved_third_device_in_a_commit() {
    use openmls::prelude::{tls_codec::*, *};
    // Extract only synthetic fixture state to build an otherwise correctly
    // signed MLS Commit which bypasses the sender's application policy.
    let mut pair = Pair::new();
    pair.join();
    let (provider, signer, mut group) = fixture_group(&pair.bob);
    let outsider = MlsProbeClient::new(&device(BOB, 3, 1).credential().unwrap()).unwrap();
    let package = KeyPackageIn::tls_deserialize_exact(outsider.key_package().unwrap())
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let (commit, _, _) = group.add_members(&provider, &signer, &[package]).unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    let epoch = pair.alice.epoch().unwrap();
    assert!(pair.alice.receive(&commit, NOW).is_err());
    assert_eq!(pair.alice.epoch().unwrap(), epoch);
    pair.alice
        .receive(&pair.bob.send("valid original peer", NOW).unwrap(), NOW)
        .unwrap();
}

#[test]
fn authenticated_peer_cannot_replace_its_signature_key_in_an_unapproved_update() {
    use openmls::{
        credentials::NewSignerBundle,
        prelude::{tls_codec::*, *},
    };
    use openmls_basic_credential::SignatureKeyPair;
    let mut pair = Pair::new();
    pair.join();
    let (provider, old_signer, mut group) = fixture_group(&pair.bob);
    let new_signer = SignatureKeyPair::new(
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.signature_algorithm(),
    )
    .unwrap();
    new_signer.store(provider.storage()).unwrap();
    let bundle = group
        .self_update_with_new_signer(
            &provider,
            &old_signer,
            NewSignerBundle {
                signer: &new_signer,
                credential_with_key: CredentialWithKey {
                    credential: BasicCredential::new(
                        pair.bob_id.credential().unwrap().into_bytes(),
                    )
                    .into(),
                    signature_key: new_signer.public().into(),
                },
            },
            LeafNodeParameters::default(),
        )
        .unwrap();
    let message = bundle.commit().tls_serialize_detached().unwrap();
    let epoch = pair.alice.epoch().unwrap();
    assert_eq!(
        pair.alice.receive(&message, NOW).unwrap_err(),
        "device_key_mismatch"
    );
    assert_eq!(pair.alice.epoch().unwrap(), epoch);
    pair.alice
        .receive(
            &pair.bob.send("original key still works", NOW).unwrap(),
            NOW,
        )
        .unwrap();
}

#[test]
fn own_lease_refresh_cannot_use_a_peer_or_replace_a_pin_and_revocation_survives_restore() {
    let mut pair = Pair::new();
    let key = pair.alice.public_key();
    assert_eq!(
        pair.alice.refresh_self(&pair.bob_token, NOW).unwrap_err(),
        "own_binding_mismatch"
    );
    let fresh = pair
        .a
        .binding(&pair.alice_id, &key, 1, Status::Active, NOW + 250);
    assert_eq!(
        pair.alice.refresh_self(&fresh, NOW + 250).unwrap(),
        "current"
    );
    assert!(pair.alice.key_package(NOW + 301).is_ok());
    let changed = pair.a.binding(
        &device(ALICE, 1, 2),
        &pair.bob.public_key(),
        2,
        Status::Active,
        NOW + 301,
    );
    assert_eq!(
        pair.alice.refresh_self(&changed, NOW + 301).unwrap_err(),
        "own_binding_mismatch"
    );
    let revoked = pair
        .a
        .binding(&pair.alice_id, &key, 2, Status::Revoked, NOW + 301);
    assert_eq!(
        pair.alice.refresh_self(&revoked, NOW + 301).unwrap(),
        "revoked"
    );
    let mut restored = pair.reload(&pair.alice);
    assert!(restored.key_package(NOW + 302).is_err());
    assert!(restored.bind_self(&fresh, NOW + 302).is_err());
}

#[test]
fn delivery_grant_requires_the_actual_joined_group_and_both_reviewed_live_keys() {
    let mut unjoined = Pair::new();
    let own = unjoined.alice.fingerprint().unwrap();
    let peer = unjoined.bob.fingerprint().unwrap();
    assert!(
        unjoined
            .alice
            .check_delivery(&GROUP, &own, &peer, NOW)
            .is_err()
    );
    unjoined.alice.create_group(&GROUP, NOW).unwrap();
    assert!(
        unjoined
            .alice
            .check_delivery(&GROUP, &own, &peer, NOW)
            .is_err()
    );
    let mut pair = Pair::new();
    pair.join();
    let own = pair.alice.fingerprint().unwrap();
    let peer = pair.bob.fingerprint().unwrap();
    let alice = pair.reload(&pair.alice);
    alice.check_delivery(&GROUP, &own, &peer, NOW).unwrap();
    assert!(alice.check_delivery(&[2; 16], &own, &peer, NOW).is_err());
    assert!(alice.check_delivery(&GROUP, &peer, &own, NOW).is_err());
    assert!(
        alice
            .check_delivery(&GROUP, &own, &peer, NOW + 301)
            .is_err()
    );
    let revoked = pair.b.binding(
        &pair.bob_id,
        &pair.bob.public_key(),
        2,
        Status::Revoked,
        NOW,
    );
    pair.alice.observe_binding(&revoked, NOW).unwrap();
    assert!(pair.alice.check_delivery(&GROUP, &own, &peer, NOW).is_err());
}

#[test]
fn bootstrap_checks_reviewed_keys_and_never_retargets_an_existing_group() {
    let mut pair = Pair::new();
    let own = pair.alice.fingerprint().unwrap();
    let peer = pair.bob.fingerprint().unwrap();
    assert_eq!(
        pair.alice
            .check_bootstrap(&GROUP, &own, &peer, NOW)
            .unwrap(),
        "unjoined"
    );
    assert!(
        pair.alice
            .check_bootstrap(&GROUP, &peer, &own, NOW)
            .is_err()
    );
    pair.alice.create_group(&GROUP, NOW).unwrap();
    assert_eq!(
        pair.alice
            .check_bootstrap(&GROUP, &own, &peer, NOW)
            .unwrap(),
        "forming"
    );
    assert!(
        pair.alice
            .check_bootstrap(&[2; 16], &own, &peer, NOW)
            .is_err()
    );
    let kp = pair.bob.key_package(NOW).unwrap();
    let invitation: Invitation =
        serde_json::from_str(&pair.alice.invite(&kp, NOW).unwrap()).unwrap();
    assert_eq!(
        pair.alice
            .check_bootstrap(&GROUP, &own, &peer, NOW)
            .unwrap(),
        "forming"
    );
    pair.alice.merge_pending(NOW).unwrap();
    pair.bob.join(&invitation.welcome, &GROUP, NOW).unwrap();
    assert_eq!(
        pair.reload(&pair.alice)
            .check_bootstrap(&GROUP, &own, &peer, NOW)
            .unwrap(),
        "joined"
    );
    assert!(
        pair.alice
            .check_bootstrap(&GROUP, &own, &peer, NOW + 301)
            .is_err()
    );
}

#[test]
fn explicit_restart_preserves_identity_but_retires_group_and_old_key_package_secrets() {
    let mut pair = Pair::new();
    pair.join();
    let a = pair.alice.fingerprint().unwrap();
    let b = pair.bob.fingerprint().unwrap();
    let old_message = pair.alice.send("old", NOW).unwrap();
    let stale_kp = pair.bob.key_package(NOW).unwrap();
    let next = [9; 16];
    assert!(
        pair.alice
            .restart_group(&GROUP, &GROUP, &a, &b, NOW)
            .is_err()
    );
    pair.alice
        .restart_group(&GROUP, &next, &a, &b, NOW)
        .unwrap();
    pair.bob.restart_group(&GROUP, &next, &b, &a, NOW).unwrap();
    assert_eq!(pair.alice.fingerprint().unwrap(), a);
    assert_eq!(pair.bob.fingerprint().unwrap(), b);
    assert!(
        pair.alice
            .restart_group(&GROUP, &next, &a, &b, NOW)
            .is_err()
    );
    assert!(pair.alice.create_group(&GROUP, NOW).is_err());
    assert!(pair.alice.create_group(&[8; 16], NOW).is_err());
    pair.alice.create_group(&next, NOW).unwrap();
    let mut stale_inviter = pair.reload(&pair.alice);
    let stale: Invitation =
        serde_json::from_str(&stale_inviter.invite(&stale_kp, NOW).unwrap()).unwrap();
    assert!(pair.bob.join(&stale.welcome, &next, NOW).is_err());
    let kp = pair.bob.key_package(NOW).unwrap();
    let welcome: Invitation = serde_json::from_str(&pair.alice.invite(&kp, NOW).unwrap()).unwrap();
    pair.alice.merge_pending(NOW).unwrap();
    pair.bob.join(&welcome.welcome, &next, NOW).unwrap();
    let mut bob = pair.reload(&pair.bob);
    assert!(bob.receive(&old_message, NOW).is_err());
    let message = pair.alice.send("fresh", NOW).unwrap();
    assert!(bob.receive(&message, NOW).unwrap().contains("fresh"));
}
#[test]
fn group_restart_does_not_override_revocation_or_erase_retirement_on_restore() {
    let mut pair = Pair::new();
    pair.join();
    let a = pair.alice.fingerprint().unwrap();
    let b = pair.bob.fingerprint().unwrap();
    let revoked = pair.b.binding(
        &pair.bob_id,
        &pair.bob.public_key(),
        2,
        Status::Revoked,
        NOW,
    );
    pair.alice.observe_binding(&revoked, NOW).unwrap();
    assert!(
        pair.alice
            .restart_group(&GROUP, &[9; 16], &a, &b, NOW)
            .is_err()
    );
    let mut client = pair.reload(&pair.bob);
    client.restart_group(&GROUP, &[9; 16], &b, &a, NOW).unwrap();
    let mut restored = pair.reload(&client);
    assert!(
        restored
            .restart_group(&GROUP, &[9; 16], &b, &a, NOW)
            .is_err()
    );
    assert!(restored.create_group(&GROUP, NOW).is_err());
    restored.create_group(&[9; 16], NOW).unwrap();
}

#[test]
fn retirement_capacity_never_forgets_old_groups_or_resets_the_last_reservation() {
    let mut pair = Pair::new();
    let own = pair.alice.fingerprint().unwrap();
    let peer = pair.bob.fingerprint().unwrap();
    let mut previous = GROUP;
    for n in 2..=9 {
        let next = [n; 16];
        pair.alice
            .restart_group(&previous, &next, &own, &peer, NOW)
            .unwrap();
        previous = next;
    }
    let mut restored = pair.reload(&pair.alice);
    assert!(
        restored
            .restart_group(&previous, &[10; 16], &own, &peer, NOW)
            .is_err()
    );
    assert!(restored.check_bootstrap(&GROUP, &own, &peer, NOW).is_err());
    assert!(restored.create_group(&GROUP, NOW).is_err());
    restored.create_group(&previous, NOW).unwrap();
}

#[test]
fn replacement_enrollment_retains_exact_signed_predecessor_across_restore() {
    let pair = Pair::new();
    let id = device(BOB, 2, 2);
    let mut next = BoundMlsClient::new(&id.credential().unwrap(), &pair.authorities).unwrap();
    let old = pair.bob.fingerprint().unwrap();
    assert!(
        next.check_enrollment_predecessor(&pair.alice_token, &old, 1, NOW)
            .is_err()
    );
    assert!(
        next.check_enrollment_predecessor(
            &pair.bob_token,
            &pair.alice.fingerprint().unwrap(),
            1,
            NOW
        )
        .is_err()
    );
    assert!(
        next.check_enrollment_predecessor(&pair.bob_token, &old, 2, NOW)
            .is_err()
    );
    assert!(next.enrollment_binding_state(&pair.bob_token, NOW).is_err());
    next.check_enrollment_predecessor(&pair.bob_token, &old, 1, NOW)
        .unwrap();
    let mut restored = pair.reload(&next);
    assert_eq!(
        restored
            .enrollment_binding_state(&pair.bob_token, NOW)
            .unwrap(),
        "previous"
    );
    let token = pair
        .b
        .binding(&id, &restored.public_key(), 2, Status::Active, NOW);
    assert_eq!(
        restored.enrollment_binding_state(&token, NOW).unwrap(),
        "current"
    );
    restored.bind_self(&token, NOW).unwrap();
    assert!(restored.refresh_self(&pair.bob_token, NOW).is_err());
    let mut bad: Value = serde_json::from_slice(&restored.checkpoint().unwrap()).unwrap();
    bad["own_previous"]["revision"] = json!(0);
    assert!(
        BoundMlsClient::restore(&serde_json::to_vec(&bad).unwrap(), &pair.authorities).is_err()
    );
}

fn third_generation(pair: &Pair) -> (BoundMlsClient, String, String) {
    let middle_id = device(BOB, 2, 2);
    let middle = BoundMlsClient::new(&middle_id.credential().unwrap(), &pair.authorities).unwrap();
    let middle_token = pair
        .b
        .binding(&middle_id, &middle.public_key(), 2, Status::Active, NOW);
    let id = device(BOB, 2, 3);
    let mut next = BoundMlsClient::new(&id.credential().unwrap(), &pair.authorities).unwrap();
    next.check_enrollment_predecessor(&middle_token, &middle.fingerprint().unwrap(), 2, NOW)
        .unwrap();
    let token = pair
        .b
        .binding(&id, &next.public_key(), 3, Status::Active, NOW);
    next.bind_self(&token, NOW).unwrap();
    next.confirm_peer(&pair.alice_token, &pair.alice.fingerprint().unwrap(), NOW)
        .unwrap();
    let historical = pair.b.binding(
        &pair.bob_id,
        &pair.bob.public_key(),
        1,
        Status::Revoked,
        NOW,
    );
    (next, token, historical)
}

#[test]
fn historical_membership_survives_restore_without_changing_enrollment_ancestry_and_only_admits_the_selected_group()
 {
    let mut pair = Pair::new();
    pair.join();
    let old_wire = pair.alice.send("old retained history", NOW).unwrap();
    let (mut next, token, historical) = third_generation(&pair);
    let a = pair.alice.fingerprint().unwrap();
    let old = pair.bob.fingerprint().unwrap();
    let new = next.fingerprint().unwrap();
    let before: Value = serde_json::from_slice(&next.checkpoint().unwrap()).unwrap();
    let keys = json!({"old_own":old,"old_peer":a,"own":new,"peer":a}).to_string();
    assert!(next.replace_group(&GROUP, &[9; 16], &keys, NOW).is_err());
    next.check_group_predecessor(&historical, &old, &GROUP, &[9; 16], NOW)
        .unwrap();
    let after: Value = serde_json::from_slice(&next.checkpoint().unwrap()).unwrap();
    assert_eq!(before["own_previous"], after["own_previous"]);
    assert!(next.create_group(&[9; 16], NOW).is_err());
    let mut restored = pair.reload(&next);
    assert!(
        restored
            .replace_group(&GROUP, &[8; 16], &keys, NOW)
            .is_err()
    );
    assert!(
        restored
            .replace_group(&[7; 16], &[9; 16], &keys, NOW)
            .is_err()
    );
    assert_eq!(
        restored.outgoing_context(NOW, true).unwrap(),
        serde_json::to_string(&(&new, Some(&a))).unwrap()
    );
    restored
        .replace_group(&GROUP, &[9; 16], &keys, NOW)
        .unwrap();
    pair.alice.observe_binding(&token, NOW).unwrap();
    pair.alice
        .accept_key_change(&token, &old, &new, NOW)
        .unwrap();
    pair.alice
        .replace_group(
            &GROUP,
            &[9; 16],
            &json!({"old_own":a,"old_peer":old,"own":a,"peer":new}).to_string(),
            NOW,
        )
        .unwrap();
    pair.alice.create_group(&[9; 16], NOW).unwrap();
    let kp = restored.key_package(NOW).unwrap();
    let welcome: Invitation = serde_json::from_str(&pair.alice.invite(&kp, NOW).unwrap()).unwrap();
    pair.alice.merge_pending(NOW).unwrap();
    restored.join(&welcome.welcome, &[9; 16], NOW).unwrap();
    assert!(restored.receive(&old_wire, NOW).is_err());
    let wire = pair.alice.send("latest reviewed generation", NOW).unwrap();
    assert!(pair.bob.receive(&wire, NOW).is_err());
    assert!(
        restored
            .receive(&wire, NOW)
            .unwrap()
            .contains("latest reviewed generation")
    );
    assert!(pair.reload(&restored).create_group(&GROUP, NOW).is_err());
    let (mut blocked, _, token) = third_generation(&pair);
    blocked
        .check_group_predecessor(&token, &old, &GROUP, &[9; 16], NOW)
        .unwrap();
    let revoked = pair.a.binding(
        &pair.alice_id,
        &pair.alice.public_key(),
        2,
        Status::Revoked,
        NOW,
    );
    blocked.observe_binding(&revoked, NOW).unwrap();
    blocked
        .cancel_group_predecessor(&GROUP, &[9; 16], NOW)
        .unwrap();
    assert!(blocked.outgoing_context(NOW, true).is_err());
}

#[test]
fn stopped_changed_generation_retires_original_and_failed_groups_with_latest_keys_and_no_intermediate_wire()
 {
    let mut pair = Pair::new();
    pair.join();
    let old_wire = pair.bob.send("old group", NOW).unwrap();
    let (mut latest, token, historical) = third_generation(&pair);
    let a = pair.alice.fingerprint().unwrap();
    let old = pair.bob.fingerprint().unwrap();
    let new = latest.fingerprint().unwrap();
    let failed = [9; 16];
    let another_failed = [10; 16];
    let final_group = [11; 16];
    for client in [&pair.alice, &latest] {
        let before = client.checkpoint().unwrap();
        client.check_replacement_origin(&GROUP, NOW).unwrap();
        assert_eq!(&*client.checkpoint().unwrap(), &*before);
    }
    latest
        .check_group_predecessor(&historical, &old, &GROUP, &failed, NOW)
        .unwrap();
    pair.alice.observe_binding(&token, NOW).unwrap();
    pair.alice
        .accept_key_change(&token, &old, &new, NOW)
        .unwrap();
    pair.alice
        .replace_group(
            &GROUP,
            &failed,
            &json!({"old_own":a,"old_peer":old,"own":a,"peer":new}).to_string(),
            NOW,
        )
        .unwrap();
    latest
        .replace_group(
            &GROUP,
            &failed,
            &json!({"old_own":old,"old_peer":a,"own":new,"peer":a}).to_string(),
            NOW,
        )
        .unwrap();
    for (client, own, peer) in [(&mut pair.alice, &a, &new), (&mut latest, &new, &a)] {
        client
            .restart_group(&failed, &another_failed, own, peer, NOW)
            .unwrap();
        client
            .restart_group(&another_failed, &final_group, own, peer, NOW)
            .unwrap();
        assert!(client.check_replacement_origin(&GROUP, NOW).is_err());
        assert!(client.check_replacement_origin(&final_group, NOW).is_err());
        for group in [&GROUP, &failed, &another_failed] {
            assert!(client.create_group(group, NOW).is_err());
        }
    }
    let mut alice = pair.reload(&pair.alice);
    let mut bob = pair.reload(&latest);
    alice.create_group(&final_group, NOW).unwrap();
    let kp = bob.key_package(NOW).unwrap();
    let welcome: Invitation = serde_json::from_str(&alice.invite(&kp, NOW).unwrap()).unwrap();
    alice.merge_pending(NOW).unwrap();
    bob.join(&welcome.welcome, &final_group, NOW).unwrap();
    alice.check_replacement_origin(&final_group, NOW).unwrap();
    bob.check_replacement_origin(&final_group, NOW).unwrap();
    assert!(bob.receive(&old_wire, NOW).is_err());
    let wire = bob.send("only final latest-key conversation", NOW).unwrap();
    assert!(
        alice
            .receive(&wire, NOW)
            .unwrap()
            .contains("only final latest-key conversation")
    );
    assert!(pair.bob.receive(&wire, NOW).is_err());
}

#[test]
fn stop_origin_check_rejects_advanced_forming_reserved_other_groups_and_revoked_self_without_changing_state()
 {
    let mut pair = Pair::new();
    pair.join();
    assert!(pair.alice.check_replacement_origin(&[9; 16], NOW).is_err());
    let fresh_pair = Pair::new();
    let mut forming = fresh_pair.alice;
    forming.create_group(&GROUP, NOW).unwrap();
    assert!(forming.check_replacement_origin(&GROUP, NOW).is_err());
    let a = pair.alice.fingerprint().unwrap();
    let b = pair.bob.fingerprint().unwrap();
    pair.alice
        .restart_group(&GROUP, &[9; 16], &a, &b, NOW)
        .unwrap();
    let before = pair.alice.checkpoint().unwrap();
    assert!(pair.alice.check_replacement_origin(&[9; 16], NOW).is_err());
    assert_eq!(&*before, &*pair.alice.checkpoint().unwrap());
    let revoked = pair.b.binding(
        &pair.bob_id,
        &pair.bob.public_key(),
        2,
        Status::Revoked,
        NOW,
    );
    pair.bob.refresh_self(&revoked, NOW).unwrap();
    assert!(pair.bob.check_replacement_origin(&GROUP, NOW).is_err());
}

#[test]
fn historical_membership_rejects_untrusted_active_expired_other_slot_and_wrong_fingerprint_bindings_without_pin_changes()
 {
    let pair = Pair::new();
    let (mut next, _, historical) = third_generation(&pair);
    let old = pair.bob.fingerprint().unwrap();
    let bad_slot = device(BOB, 3, 1);
    let foreign = Issuer::new(BOB);
    let invalid = [
        pair.bob_token.clone(),
        pair.alice_token.clone(),
        pair.b
            .binding(&bad_slot, &pair.bob.public_key(), 1, Status::Revoked, NOW),
        foreign.binding(
            &pair.bob_id,
            &pair.bob.public_key(),
            1,
            Status::Revoked,
            NOW,
        ),
        pair.b.binding(
            &pair.bob_id,
            &pair.bob.public_key(),
            1,
            Status::Revoked,
            NOW - 301,
        ),
        pair.b.binding(
            &device(BOB, 2, 3),
            &pair.bob.public_key(),
            1,
            Status::Revoked,
            NOW,
        ),
    ];
    let before = next.checkpoint().unwrap();
    for token in invalid {
        assert!(
            next.check_group_predecessor(&token, &old, &GROUP, &[9; 16], NOW)
                .is_err()
        );
    }
    assert!(
        next.check_group_predecessor(
            &historical,
            &pair.alice.fingerprint().unwrap(),
            &GROUP,
            &[9; 16],
            NOW
        )
        .is_err()
    );
    assert!(
        next.check_group_predecessor(&historical, &old, &GROUP, &GROUP, NOW)
            .is_err()
    );
    assert_eq!(before, next.checkpoint().unwrap());
}

#[test]
fn historical_marker_cannot_survive_inconsistent_restore_or_override_current_revocation() {
    let pair = Pair::new();
    let (mut next, _, historical) = third_generation(&pair);
    let mut legacy: Value = serde_json::from_slice(&next.checkpoint().unwrap()).unwrap();
    legacy.as_object_mut().unwrap().remove("group_previous");
    next =
        BoundMlsClient::restore(&serde_json::to_vec(&legacy).unwrap(), &pair.authorities).unwrap();
    let old = pair.bob.fingerprint().unwrap();
    next.check_group_predecessor(&historical, &old, &GROUP, &[9; 16], NOW)
        .unwrap();
    let value: Value = serde_json::from_slice(&next.checkpoint().unwrap()).unwrap();
    for (field, bad) in [
        ("previous", json!([1])),
        ("next", json!(GROUP)),
        (
            "old",
            json!({"device": device(BOB,2,3),"fingerprint":old,"revision":1}),
        ),
    ] {
        let mut changed = value.clone();
        changed["group_previous"][field] = bad;
        assert!(
            BoundMlsClient::restore(&serde_json::to_vec(&changed).unwrap(), &pair.authorities)
                .is_err()
        );
    }
    let revoked = pair.b.binding(
        &device(BOB, 2, 3),
        &next.public_key(),
        4,
        Status::Revoked,
        NOW,
    );
    next.refresh_self(&revoked, NOW).unwrap();
    assert!(
        next.check_group_predecessor(&historical, &old, &GROUP, &[9; 16], NOW)
            .is_err()
    );
    assert!(next.replace_group(&GROUP, &[9;16], &json!({"old_own":old,"old_peer":pair.alice.fingerprint().unwrap(),"own":next.fingerprint().unwrap(),"peer":pair.alice.fingerprint().unwrap()}).to_string(), NOW).is_err());
}

#[test]
fn cancelling_historical_membership_releases_only_the_exact_unused_intent_and_preserves_identity_pins_and_fences()
 {
    let pair = Pair::new();
    let (mut next, _, historical) = third_generation(&pair);
    let old = pair.bob.fingerprint().unwrap();
    let fingerprint = next.fingerprint().unwrap();
    next.check_group_predecessor(&historical, &old, &GROUP, &[9; 16], NOW)
        .unwrap();
    let before = next.checkpoint().unwrap();
    assert!(
        next.cancel_group_predecessor(&GROUP, &[8; 16], NOW)
            .is_err()
    );
    assert_eq!(before, next.checkpoint().unwrap());
    next.cancel_group_predecessor(&GROUP, &[9; 16], NOW)
        .unwrap();
    let mut restored = pair.reload(&next);
    assert_eq!(restored.fingerprint().unwrap(), fingerprint);
    let a: Value = serde_json::from_slice(&before).unwrap();
    let b: Value = serde_json::from_slice(&restored.checkpoint().unwrap()).unwrap();
    for key in ["own_previous", "trust", "retired_groups", "next_group"] {
        assert_eq!(a[key], b[key]);
    }
    restored
        .check_bootstrap(
            &[8; 16],
            &fingerprint,
            &pair.alice.fingerprint().unwrap(),
            NOW,
        )
        .unwrap();
    restored
        .check_group_predecessor(&historical, &old, &GROUP, &[8; 16], NOW)
        .unwrap();
    restored.replace_group(&GROUP, &[8;16], &json!({"old_own":old,"old_peer":pair.alice.fingerprint().unwrap(),"own":fingerprint,"peer":pair.alice.fingerprint().unwrap()}).to_string(), NOW).unwrap();
    assert!(
        restored
            .cancel_group_predecessor(&GROUP, &[8; 16], NOW)
            .is_err()
    );
    assert!(pair.reload(&restored).create_group(&GROUP, NOW).is_err());
}

#[test]
fn changed_key_replacement_uses_fresh_provider_and_reserves_exact_group_without_history_transfer() {
    let mut pair = Pair::new();
    pair.join();
    let old_message = pair.alice.send("old history", NOW).unwrap();
    let a = pair.alice.fingerprint().unwrap();
    let b = pair.bob.fingerprint().unwrap();
    let stale_kp = pair.bob.key_package(NOW).unwrap();
    let id = device(BOB, 2, 2);
    let mut next = BoundMlsClient::new(&id.credential().unwrap(), &pair.authorities).unwrap();
    next.check_enrollment_predecessor(&pair.bob_token, &b, 1, NOW)
        .unwrap();
    let token = pair
        .b
        .binding(&id, &next.public_key(), 2, Status::Active, NOW);
    next.bind_self(&token, NOW).unwrap();
    next.confirm_peer(&pair.alice_token, &a, NOW).unwrap();
    let c = next.fingerprint().unwrap();
    let keys = json!({"old_own":a,"old_peer":b,"own":a,"peer":c}).to_string();
    assert!(
        pair.alice
            .replace_group(&GROUP, &[9; 16], &keys, NOW)
            .is_err()
    );
    pair.alice.observe_binding(&token, NOW).unwrap();
    pair.alice.accept_key_change(&token, &b, &c, NOW).unwrap();
    let mut wrong: Value = serde_json::from_str(&keys).unwrap();
    wrong["old_peer"] = json!(a);
    assert!(
        pair.alice
            .replace_group(&GROUP, &[9; 16], &wrong.to_string(), NOW)
            .is_err()
    );
    pair.alice
        .replace_group(&GROUP, &[9; 16], &keys, NOW)
        .unwrap();
    next.replace_group(
        &GROUP,
        &[9; 16],
        &json!({"old_own":b,"old_peer":a,"own":c,"peer":a}).to_string(),
        NOW,
    )
    .unwrap();
    assert_eq!(pair.alice.fingerprint().unwrap(), a);
    let mut alice = pair.reload(&pair.alice);
    let mut bob = pair.reload(&next);
    assert!(alice.create_group(&GROUP, NOW).is_err());
    assert!(bob.create_group(&[8; 16], NOW).is_err());
    alice.create_group(&[9; 16], NOW).unwrap();
    assert!(alice.invite(&stale_kp, NOW).is_err());
    let kp = bob.key_package(NOW).unwrap();
    let welcome: Invitation = serde_json::from_str(&alice.invite(&kp, NOW).unwrap()).unwrap();
    alice.merge_pending(NOW).unwrap();
    bob.join(&welcome.welcome, &[9; 16], NOW).unwrap();
    assert!(bob.receive(&old_message, NOW).is_err());
    let text = alice.send("new key only", NOW).unwrap();
    assert!(pair.bob.receive(&text, NOW).is_err());
    assert!(bob.receive(&text, NOW).unwrap().contains("new key only"));
    assert!(
        alice
            .receive(&bob.send("replacement works", NOW).unwrap(), NOW)
            .unwrap()
            .contains("replacement works")
    );
}

#[test]
fn replacement_cannot_skip_signed_predecessor_or_current_peer_revocation() {
    let mut pair = Pair::new();
    pair.join();
    let id = device(BOB, 2, 2);
    let mut next = BoundMlsClient::new(&id.credential().unwrap(), &pair.authorities).unwrap();
    let token = pair
        .b
        .binding(&id, &next.public_key(), 2, Status::Active, NOW);
    let a = pair.alice.fingerprint().unwrap();
    let b = pair.bob.fingerprint().unwrap();
    let c = next.fingerprint().unwrap();
    next.bind_self(&token, NOW).unwrap();
    next.confirm_peer(&pair.alice_token, &a, NOW).unwrap();
    let keys = json!({"old_own":b,"old_peer":a,"own":c,"peer":a}).to_string();
    assert!(next.replace_group(&GROUP, &[9; 16], &keys, NOW).is_err());
    next.check_enrollment_predecessor(&pair.bob_token, &b, 1, NOW)
        .unwrap();
    let revoked = pair.a.binding(
        &pair.alice_id,
        &pair.alice.public_key(),
        2,
        Status::Revoked,
        NOW,
    );
    next.observe_binding(&revoked, NOW).unwrap();
    assert!(next.replace_group(&GROUP, &[9; 16], &keys, NOW).is_err());
    assert!(
        pair.alice
            .replace_group(
                &GROUP,
                &[9; 16],
                &json!({"old_own":b,"old_peer":a,"own":c,"peer":a}).to_string(),
                NOW
            )
            .is_err()
    );
}

#[test]
fn abandoned_changed_key_admission_can_retire_both_groups_without_joining_the_failed_one() {
    let mut pair = Pair::new();
    pair.join();
    let a = pair.alice.fingerprint().unwrap();
    let b = pair.bob.fingerprint().unwrap();
    let old_wire = pair.bob.send("old group", NOW).unwrap();
    let id = device(BOB, 2, 2);
    let mut next = BoundMlsClient::new(&id.credential().unwrap(), &pair.authorities).unwrap();
    next.check_enrollment_predecessor(&pair.bob_token, &b, 1, NOW)
        .unwrap();
    let token = pair
        .b
        .binding(&id, &next.public_key(), 2, Status::Active, NOW);
    next.bind_self(&token, NOW).unwrap();
    next.confirm_peer(&pair.alice_token, &a, NOW).unwrap();
    let c = next.fingerprint().unwrap();
    pair.alice.observe_binding(&token, NOW).unwrap();
    pair.alice.accept_key_change(&token, &b, &c, NOW).unwrap();
    let failed = [9; 16];
    let fresh = [10; 16];
    // The new device already reserved a failed invitation and generated its KP.
    next.replace_group(
        &GROUP,
        &failed,
        &json!({"old_own":b,"old_peer":a,"own":c,"peer":a}).to_string(),
        NOW,
    )
    .unwrap();
    let stale_kp = next.key_package(NOW).unwrap();
    next.restart_group(&failed, &fresh, &c, &a, NOW).unwrap();
    // The unchanged device never joins or emits a KP for the failed group.
    pair.alice
        .replace_group(
            &GROUP,
            &failed,
            &json!({"old_own":a,"old_peer":b,"own":a,"peer":c}).to_string(),
            NOW,
        )
        .unwrap();
    let mut alice = pair.reload(&pair.alice);
    alice.restart_group(&failed, &fresh, &a, &c, NOW).unwrap();
    let mut alice = pair.reload(&alice);
    let mut bob = pair.reload(&next);
    for group in [&GROUP, &failed] {
        assert!(alice.create_group(group, NOW).is_err());
        assert!(bob.create_group(group, NOW).is_err());
    }
    assert_eq!(alice.fingerprint().unwrap(), a);
    assert_eq!(bob.fingerprint().unwrap(), c);
    alice.create_group(&fresh, NOW).unwrap();
    let stale_welcome: Invitation =
        serde_json::from_str(&alice.invite(&stale_kp, NOW).unwrap()).unwrap();
    assert!(bob.join(&stale_welcome.welcome, &fresh, NOW).is_err());
    // Roll back the inviter's disposable test branch, then use a fresh KP.
    let mut alice = pair.reload(&pair.alice);
    alice.restart_group(&failed, &fresh, &a, &c, NOW).unwrap();
    alice.create_group(&fresh, NOW).unwrap();
    let kp = bob.key_package(NOW).unwrap();
    let welcome: Invitation = serde_json::from_str(&alice.invite(&kp, NOW).unwrap()).unwrap();
    alice.merge_pending(NOW).unwrap();
    bob.join(&welcome.welcome, &fresh, NOW).unwrap();
    assert!(alice.receive(&old_wire, NOW).is_err());
    let wire = alice.send("fresh consent", NOW).unwrap();
    assert!(bob.receive(&wire, NOW).unwrap().contains("fresh consent"));
    assert!(pair.bob.receive(&wire, NOW).is_err());
}

#[test]
fn repeated_unjoined_restarts_preserve_identity_retirement_fences_and_only_the_final_key_package() {
    let mut pair = Pair::new();
    pair.join();
    let a = pair.alice.fingerprint().unwrap();
    let b = pair.bob.fingerprint().unwrap();
    let old_wire = pair.bob.send("retired conversation", NOW).unwrap();
    let failed = [9; 16];
    let final_group = [10; 16];
    pair.alice
        .restart_group(&GROUP, &failed, &a, &b, NOW)
        .unwrap();
    pair.bob
        .restart_group(&GROUP, &failed, &b, &a, NOW)
        .unwrap();
    let stale_kp = pair.bob.key_package(NOW).unwrap();
    let mut alice = pair.reload(&pair.alice);
    let mut bob = pair.reload(&pair.bob);
    alice
        .restart_group(&failed, &final_group, &a, &b, NOW)
        .unwrap();
    bob.restart_group(&failed, &final_group, &b, &a, NOW)
        .unwrap();
    let mut alice = pair.reload(&alice);
    let mut bob = pair.reload(&bob);
    for retired in [&GROUP, &failed] {
        assert!(alice.create_group(retired, NOW).is_err());
        assert!(bob.create_group(retired, NOW).is_err());
    }
    assert_eq!(alice.fingerprint().unwrap(), a);
    assert_eq!(bob.fingerprint().unwrap(), b);
    alice.create_group(&final_group, NOW).unwrap();
    let mut stale_inviter = pair.reload(&alice);
    let stale: Invitation =
        serde_json::from_str(&stale_inviter.invite(&stale_kp, NOW).unwrap()).unwrap();
    assert!(bob.join(&stale.welcome, &final_group, NOW).is_err());
    let kp = bob.key_package(NOW).unwrap();
    let welcome: Invitation = serde_json::from_str(&alice.invite(&kp, NOW).unwrap()).unwrap();
    alice.merge_pending(NOW).unwrap();
    bob.join(&welcome.welcome, &final_group, NOW).unwrap();
    assert!(alice.receive(&old_wire, NOW).is_err());
    let wire = bob.send("only final consent", NOW).unwrap();
    assert!(
        alice
            .receive(&wire, NOW)
            .unwrap()
            .contains("only final consent")
    );
}

fn activated_stop_origin(mode: &str) {
    let mut pair = Pair::new();
    pair.join();
    let original_wire = pair.bob.send("original secret", NOW).unwrap();
    let a = pair.alice.fingerprint().unwrap();
    let b = pair.bob.fingerprint().unwrap();
    let failed = [9; 16];
    let next = [10; 16];
    pair.alice
        .restart_group(&GROUP, &failed, &a, &b, NOW)
        .unwrap();
    pair.bob
        .restart_group(&GROUP, &failed, &b, &a, NOW)
        .unwrap();
    let mut failed_wire = None;
    if mode != "unjoined" {
        pair.alice.create_group(&failed, NOW).unwrap();
        if mode == "pending" || mode == "joined" {
            let kp = pair.bob.key_package(NOW).unwrap();
            let invitation: Invitation =
                serde_json::from_str(&pair.alice.invite(&kp, NOW).unwrap()).unwrap();
            if mode == "joined" {
                pair.alice.merge_pending(NOW).unwrap();
                pair.bob.join(&invitation.welcome, &failed, NOW).unwrap();
                failed_wire = Some(pair.bob.send("failed target secret", NOW).unwrap());
            }
        }
    }
    let (mut latest, token, historical) = third_generation(&pair);
    let peer = latest.fingerprint().unwrap();
    let before = pair.alice.checkpoint().unwrap();
    assert!(
        pair.alice
            .check_activated_replacement_origin(&GROUP, &failed, &a, &b, NOW)
            .is_err()
    );
    assert_eq!(&*before, &*pair.alice.checkpoint().unwrap());
    pair.alice.observe_binding(&token, NOW).unwrap();
    pair.alice
        .accept_key_change(&token, &b, &peer, NOW)
        .unwrap();
    let mut alice = pair.reload(&pair.alice);
    let before = alice.checkpoint().unwrap();
    assert_eq!(
        alice
            .check_activated_replacement_origin(&GROUP, &failed, &a, &b, NOW)
            .unwrap(),
        if mode == "pending" { "forming" } else { mode }
    );
    for (anchor, target, own, old_peer) in [
        (&[11; 16], &failed, &a, &b),
        (&GROUP, &[11; 16], &a, &b),
        (&GROUP, &failed, &b, &a),
        (&GROUP, &failed, &a, &peer),
    ] {
        assert!(
            alice
                .check_activated_replacement_origin(anchor, target, own, old_peer, NOW)
                .is_err()
        );
    }
    assert_eq!(&*before, &*alice.checkpoint().unwrap());
    let keys = json!({"old_own":a,"old_peer":b,"own":a,"peer":peer}).to_string();
    assert!(
        alice
            .restart_activated_replacement(&GROUP, &failed, &GROUP, &keys, NOW)
            .is_err()
    );
    assert_eq!(&*before, &*alice.checkpoint().unwrap());
    alice
        .restart_activated_replacement(&GROUP, &failed, &next, &keys, NOW)
        .unwrap();
    let retired = alice.checkpoint().unwrap();
    assert!(
        alice
            .restart_activated_replacement(&GROUP, &failed, &[11; 16], &keys, NOW)
            .is_err()
    );
    assert_eq!(&*retired, &*alice.checkpoint().unwrap());
    latest
        .check_group_predecessor(&historical, &b, &GROUP, &failed, NOW)
        .unwrap();
    latest
        .replace_group(
            &GROUP,
            &failed,
            &json!({"old_own":b,"old_peer":a,"own":peer,"peer":a}).to_string(),
            NOW,
        )
        .unwrap();
    latest
        .restart_group(&failed, &next, &peer, &a, NOW)
        .unwrap();
    let mut alice = pair.reload(&alice);
    for old in [&GROUP, &failed] {
        assert!(alice.create_group(old, NOW).is_err());
    }
    alice.create_group(&next, NOW).unwrap();
    let kp = latest.key_package(NOW).unwrap();
    let invitation: Invitation = serde_json::from_str(&alice.invite(&kp, NOW).unwrap()).unwrap();
    alice.merge_pending(NOW).unwrap();
    latest.join(&invitation.welcome, &next, NOW).unwrap();
    assert!(alice.receive(&original_wire, NOW).is_err());
    if let Some(wire) = failed_wire {
        assert!(alice.receive(&wire, NOW).is_err());
    }
    let wire = latest.send("fresh final text", NOW).unwrap();
    assert!(
        alice
            .receive(&wire, NOW)
            .unwrap()
            .contains("fresh final text")
    );
    assert!(pair.bob.receive(&wire, NOW).is_err());
    if mode == "joined" {
        let mut current = next;
        for i in 0..6 {
            let next = [20 + i; 16];
            alice
                .restart_group(&current, &next, &a, &peer, NOW)
                .unwrap();
            current = next;
        }
        let before = alice.checkpoint().unwrap();
        assert!(
            alice
                .restart_group(&current, &[30; 16], &a, &peer, NOW)
                .is_err()
        );
        assert_eq!(&*before, &*alice.checkpoint().unwrap());
    }
}
#[test]
fn activated_stop_retires_exact_unjoined_reservation_without_reopening_anchor() {
    activated_stop_origin("unjoined");
}
#[test]
fn activated_stop_retires_exact_forming_group_without_reopening_anchor() {
    activated_stop_origin("forming");
}
#[test]
fn activated_stop_discards_pending_commit_only_after_exact_origin_proof() {
    activated_stop_origin("pending");
}
#[test]
fn activated_stop_retires_exact_joined_group_preserves_fences_and_capacity() {
    activated_stop_origin("joined");
}
