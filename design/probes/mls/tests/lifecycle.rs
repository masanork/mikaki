use mikaki_mls_probe::{Invitation, MlsProbeClient, Received};
use openmls::prelude::{MlsMessageBodyIn, MlsMessageIn, tls_codec::*};
use zeroize::Zeroizing;

const GROUP: [u8; 16] = [1; 16];

fn reload(client: MlsProbeClient) -> MlsProbeClient {
    let state = Zeroizing::new(client.checkpoint().unwrap());
    drop(client);
    MlsProbeClient::restore(&state).unwrap()
}

fn pair(group: &[u8]) -> (MlsProbeClient, MlsProbeClient) {
    let mut alice = MlsProbeClient::new("alice/device-1").unwrap();
    let mut bob = MlsProbeClient::new("bob/device-1").unwrap();
    alice.create_group(group).unwrap();
    let invitation: Invitation =
        serde_json::from_str(&alice.invite(&bob.key_package().unwrap()).unwrap()).unwrap();
    alice.merge_pending().unwrap();
    bob.join(&invitation.welcome, group).unwrap();
    (alice, bob)
}

fn application(client: &mut MlsProbeClient, wire: &[u8], sender: &str, text: &str) {
    assert_eq!(
        serde_json::from_str::<Received>(&client.receive(wire).unwrap()).unwrap(),
        Received::Application {
            sender: sender.into(),
            text: text.into(),
        }
    );
}

#[test]
fn two_independent_devices_join_and_exchange_private_unicode_messages() {
    let (mut alice, mut bob) = pair(&GROUP);
    assert_ne!(alice.public_key(), bob.public_key());
    assert_eq!(alice.epoch().unwrap(), bob.epoch().unwrap());
    let text = "暗号化チャットの最初のメッセージ 🕊️";
    let sent = alice.send(text).unwrap();
    assert!(matches!(
        MlsMessageIn::tls_deserialize_exact(&sent)
            .unwrap()
            .extract(),
        MlsMessageBodyIn::PrivateMessage(_)
    ));
    assert!(
        !sent
            .windows(text.len())
            .any(|window| window == text.as_bytes())
    );
    application(&mut bob, &sent, "alice/device-1", text);
    application(
        &mut alice,
        &bob.send("受信できました").unwrap(),
        "bob/device-1",
        "受信できました",
    );
}

#[test]
fn exported_key_package_and_pending_invitation_survive_complete_client_recreation() {
    let mut alice = MlsProbeClient::new("alice/device-1").unwrap();
    let bob = MlsProbeClient::new("bob/device-1").unwrap();
    let package = bob.key_package().unwrap();
    let mut bob = reload(bob);
    alice.create_group(&GROUP).unwrap();
    let invitation: Invitation = serde_json::from_str(&alice.invite(&package).unwrap()).unwrap();
    let mut alice = reload(alice);
    assert!(alice.send("pending").is_err());
    alice.merge_pending().unwrap();
    bob.join(&invitation.welcome, &GROUP).unwrap();
    let mut alice = reload(alice);
    let mut bob = reload(bob);
    application(
        &mut bob,
        &alice.send("restored").unwrap(),
        "alice/device-1",
        "restored",
    );
}

#[test]
fn persisted_send_and_receive_ratchets_reject_replay_after_restart() {
    let (mut alice, mut bob) = pair(&GROUP);
    // Save the post-encryption state before releasing the exact ciphertext.
    // A durable atomic state/outbox transaction is a later product gate.
    let sent = alice.send("response may be lost").unwrap();
    let mut alice = reload(alice);
    application(&mut bob, &sent, "alice/device-1", "response may be lost");
    let mut bob = reload(bob);
    assert!(bob.receive(&sent).is_err());
    let next = alice.send("next generation").unwrap();
    assert_ne!(sent, next);
    application(&mut bob, &next, "alice/device-1", "next generation");
}

#[test]
fn same_epoch_messages_can_arrive_out_of_order_but_only_once() {
    let (mut alice, mut bob) = pair(&GROUP);
    let first = alice.send("first").unwrap();
    let second = alice.send("second").unwrap();
    application(&mut bob, &second, "alice/device-1", "second");
    let mut bob = reload(bob);
    application(&mut bob, &first, "alice/device-1", "first");
    assert!(bob.receive(&first).is_err());
    assert!(bob.receive(&second).is_err());
}

#[test]
fn pending_key_update_restores_and_both_devices_continue_at_the_new_epoch() {
    let (mut alice, mut bob) = pair(&GROUP);
    let epoch = alice.epoch().unwrap();
    let commit = alice.update().unwrap();
    assert!(alice.send("must wait").is_err());
    let mut alice = reload(alice);
    alice.merge_pending().unwrap();
    assert_eq!(alice.epoch().unwrap(), epoch + 1);
    assert_eq!(
        bob.receive(&commit).unwrap(),
        r#"{"kind":"commit","active":true}"#
    );
    let mut bob = reload(bob);
    assert_eq!(bob.epoch().unwrap(), alice.epoch().unwrap());
    application(
        &mut bob,
        &alice.send("new epoch").unwrap(),
        "alice/device-1",
        "new epoch",
    );
    application(
        &mut alice,
        &bob.send("reply").unwrap(),
        "bob/device-1",
        "reply",
    );
    assert!(bob.receive(&commit).is_err());
}

#[test]
fn removed_device_and_its_pre_removal_state_cannot_read_future_messages() {
    let (mut alice, mut bob) = pair(&GROUP);
    let old_bob = Zeroizing::new(bob.checkpoint().unwrap());
    let commit = alice.remove_peer().unwrap();
    let mut alice = reload(alice);
    alice.merge_pending().unwrap();
    let future = alice.send("after removal").unwrap();
    assert!(
        MlsProbeClient::restore(&old_bob)
            .unwrap()
            .receive(&future)
            .is_err()
    );
    assert_eq!(
        bob.receive(&commit).unwrap(),
        r#"{"kind":"commit","active":false}"#
    );
    assert!(!bob.active());
    assert!(bob.send("removed").is_err());
    assert!(bob.receive(&future).is_err());
    let mut bob = reload(bob);
    assert!(!bob.active());
    assert!(bob.send("still removed").is_err());
}

#[test]
fn modified_truncated_and_cross_group_messages_are_rejected() {
    let (mut alice, mut bob) = pair(&GROUP);
    let (_, mut other_bob) = pair(&[2; 16]);
    let sent = alice.send("authentic").unwrap();
    assert!(other_bob.receive(&sent).is_err());
    assert!(bob.receive(&sent[..sent.len() - 1]).is_err());
    let mut trailing = sent.clone();
    trailing.push(0);
    assert!(bob.receive(&trailing).is_err());
    let mut modified = sent.clone();
    *modified.last_mut().unwrap() ^= 1;
    assert!(bob.receive(&modified).is_err());
    application(&mut bob, &sent, "alice/device-1", "authentic");
    assert!(bob.receive(&bob.key_package().unwrap()).is_err());
}

#[test]
fn key_package_signature_and_intended_group_are_checked() {
    let mut alice = MlsProbeClient::new("alice/device-1").unwrap();
    let bob = MlsProbeClient::new("bob/device-1").unwrap();
    alice.create_group(&GROUP).unwrap();
    let package = bob.key_package().unwrap();
    let mut modified = package.clone();
    *modified.last_mut().unwrap() ^= 1;
    assert!(alice.invite(&modified).is_err());
    let mut trailing = package.clone();
    trailing.push(0);
    assert!(alice.invite(&trailing).is_err());
    let invitation: Invitation = serde_json::from_str(&alice.invite(&package).unwrap()).unwrap();
    // This checkpoint is intentionally held only in test memory.
    let saved_bob = Zeroizing::new(bob.checkpoint().unwrap());
    assert!(
        MlsProbeClient::restore(&saved_bob)
            .unwrap()
            .join(&invitation.welcome, &[2; 16])
            .is_err()
    );
    let mut outsider = MlsProbeClient::new("bob/device-1").unwrap();
    assert!(outsider.join(&invitation.welcome, &GROUP).is_err());
    let mut bob = MlsProbeClient::restore(&saved_bob).unwrap();
    bob.join(&invitation.welcome, &GROUP).unwrap();
    // Reset only the wrapper's group selector to ask OpenMLS to reuse a consumed
    // KeyPackage. Its private join material must already have been deleted.
    let state = Zeroizing::new(bob.checkpoint().unwrap());
    let mut value: serde_json::Value = serde_json::from_slice(&state).unwrap();
    value["group_id"] = serde_json::Value::Null;
    let consumed = Zeroizing::new(serde_json::to_vec(&value).unwrap());
    assert!(
        MlsProbeClient::restore(&consumed)
            .unwrap()
            .join(&invitation.welcome, &GROUP)
            .is_err()
    );
}

#[test]
fn input_bounds_and_checkpoint_versions_fail_closed() {
    assert!(MlsProbeClient::new("").is_err());
    assert!(MlsProbeClient::new("あ").is_err());
    let (mut alice, _) = pair(&GROUP);
    assert!(alice.send("").is_err());
    assert!(alice.send(&"a".repeat(4097)).is_err());
    assert!(alice.receive(&[]).is_err());
    assert!(alice.receive(&vec![0; 65_537]).is_err());
    assert!(MlsProbeClient::restore(&vec![0; 1_048_577]).is_err());
    let bytes = Zeroizing::new(alice.checkpoint().unwrap());
    let mut state: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    state["version"] = 2.into();
    assert!(MlsProbeClient::restore(&serde_json::to_vec(&state).unwrap()).is_err());
    state["version"] = 1.into();
    state["extra"] = true.into();
    assert!(MlsProbeClient::restore(&serde_json::to_vec(&state).unwrap()).is_err());
    state.as_object_mut().unwrap().remove("extra");
    let duplicate = state["storage"][0].clone();
    state["storage"].as_array_mut().unwrap().push(duplicate);
    assert!(MlsProbeClient::restore(&serde_json::to_vec(&state).unwrap()).is_err());
}
