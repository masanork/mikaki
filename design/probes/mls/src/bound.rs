//! MLS boundary enforcing application identity and reviewed device-key pins.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openmls_traits::signatures::Signer;

use super::*;
use crate::trust::{self, Authority, DeviceIdentity, Observation, RegistrationProof, TrustStore};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundCheckpoint {
    version: u8,
    identity: DeviceIdentity,
    peer: Option<DeviceIdentity>,
    trust: TrustStore,
    inner: Vec<u8>,
    #[serde(default)]
    retired_groups: Vec<Vec<u8>>,
    #[serde(default)]
    next_group: Option<Vec<u8>>,
    #[serde(default)]
    own_previous: Option<OwnPredecessor>,
    #[serde(default)]
    group_previous: Option<GroupPredecessor>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnPredecessor {
    device: DeviceIdentity,
    fingerprint: String,
    revision: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupPredecessor {
    old: OwnPredecessor,
    previous: Vec<u8>,
    next: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplacementKeys {
    old_own: String,
    old_peer: String,
    own: String,
    peer: String,
}
impl Drop for BoundCheckpoint {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Pre-adoption client: signed issuer bindings and explicit fingerprint review.
/// The issuer's actual SSO enrollment/storage adapter is not implemented here.
#[wasm_bindgen]
pub struct BoundMlsClient {
    inner: MlsProbeClient,
    identity: DeviceIdentity,
    peer: Option<DeviceIdentity>,
    trust: TrustStore,
    retired_groups: Vec<Vec<u8>>,
    next_group: Option<Vec<u8>>,
    own_previous: Option<OwnPredecessor>,
    group_previous: Option<GroupPredecessor>,
}

#[wasm_bindgen]
impl BoundMlsClient {
    #[wasm_bindgen(constructor)]
    pub fn new(identity: &str, authorities: &str) -> Result<BoundMlsClient, String> {
        let identity: DeviceIdentity = trust::parse(identity)?;
        let authorities: Vec<Authority> = trust::parse(authorities)?;
        if !authorities.iter().any(|a| a.issuer == identity.issuer) {
            return Err("own_issuer_untrusted".into());
        }
        let inner = MlsProbeClient::new(&identity.credential()?)?;
        Ok(Self {
            inner,
            identity,
            peer: None,
            trust: TrustStore::new(authorities)?,
            retired_groups: Vec::new(),
            next_group: None,
            own_previous: None,
            group_previous: None,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key()
    }

    pub fn identity_json(&self) -> Result<String, String> {
        Ok(self.identity.credential()?)
    }

    /// Revalidate the exact device keys before releasing a saved wire message.
    /// Removal commits need only the active sender, so a revoked peer cannot
    /// prevent its removal. The persistence adapter compares this context with
    /// the one recorded when that exact ciphertext was prepared.
    pub fn outgoing_context(&self, now: u64, require_peer: bool) -> Result<String, String> {
        self.check_self(now)?;
        let own = self.fingerprint()?;
        let peer = if require_peer {
            Some(
                self.trust
                    .current_fingerprint(self.peer.as_ref().ok_or("first_trust_required")?, now)?,
            )
        } else {
            None
        };
        serde_json::to_string(&(own, peer)).map_err(|_| "invalid_outgoing_context".into())
    }

    /// Pin a mailbox grant to this actual MLS group and the already reviewed
    /// leaf keys. Transport metadata never establishes peer trust.
    pub fn check_delivery(
        &self,
        group: &[u8],
        own: &str,
        peer: &str,
        now: u64,
    ) -> Result<(), String> {
        let expected =
            serde_json::to_string(&(own, Some(peer))).map_err(|_| "invalid_outgoing_context")?;
        self.check_roster(now)?;
        let current = self.inner.group.as_ref().ok_or("group_missing")?;
        if self.outgoing_context(now, true)? != expected
            || current.group_id().as_slice() != group
            || current.members().count() != 2
            || !self.inner.active()
        {
            return Err("delivery_context_mismatch".into());
        }
        Ok(())
    }

    /// Inspect only an already reviewed pair. A new group is created/joined by
    /// a separate witnessed operation, never by directory or transport data.
    pub fn check_bootstrap(
        &self,
        group: &[u8],
        own: &str,
        peer: &str,
        now: u64,
    ) -> Result<String, String> {
        self.check_new_group(group)?;
        let expected =
            serde_json::to_string(&(own, Some(peer))).map_err(|_| "invalid_outgoing_context")?;
        if group.len() != 16 || self.outgoing_context(now, true)? != expected {
            return Err("delivery_context_mismatch".into());
        }
        let Some(current) = self.inner.group.as_ref() else {
            return Ok("unjoined".into());
        };
        self.check_roster(now)?;
        if current.group_id().as_slice() != group || !self.inner.active() {
            return Err("delivery_context_mismatch".into());
        }
        Ok(if current.members().count() == 2 {
            "joined"
        } else {
            "forming"
        }
        .into())
    }

    /// A stop may freeze an original group or a fresh device, never an already
    /// advanced/reserved native group. This read changes no provider or fence.
    pub fn check_replacement_origin(&self, previous: &[u8], now: u64) -> Result<(), String> {
        self.check_self(now)?;
        if previous.len() != 16
            || self
                .next_group
                .as_ref()
                .is_some_and(|next| self.inner.group.is_none() || next.as_slice() != previous)
            || self.retired_groups.iter().any(|g| g == previous)
            || self
                .group_previous
                .as_ref()
                .is_some_and(|p| p.previous != previous)
            || self.inner.group.as_ref().is_some_and(|g| {
                g.group_id().as_slice() != previous
                    || g.members().count() != 2
                    || !self.inner.active()
            })
        {
            return Err("replacement_origin_advanced".into());
        }
        Ok(())
    }

    /// Read-only proof for the unchanged endpoint that already activated the
    /// failed replacement. Both the retired anchor and exact reserved/current
    /// target must survive. The newly reviewed peer must have another key.
    pub fn check_activated_replacement_origin(
        &self,
        previous: &[u8],
        failed: &[u8],
        own: &str,
        peer: &str,
        now: u64,
    ) -> Result<String, String> {
        self.check_self(now)?;
        let accepted = self
            .trust
            .accepted(self.peer.as_ref().ok_or("first_trust_required")?, now)?;
        if previous.len() != 16
            || failed.len() != 16
            || previous == failed
            || !self.retired_groups.iter().any(|g| g == previous)
            || self.retired_groups.iter().any(|g| g == failed)
            || self.next_group.as_deref() != Some(failed)
            || self.group_previous.is_some()
            || self.fingerprint()? != own
            || trust::decode(peer)?.len() != 32
            || trust::decode(own)?.len() != 32
            || trust::fingerprint(&accepted.device, &trust::decode(&accepted.public_key)?)? == peer
        {
            return Err("replacement_origin_advanced".into());
        }
        let Some(group) = self.inner.group.as_ref() else {
            return Ok("unjoined".into());
        };
        if group.group_id().as_slice() != failed || !self.inner.active() {
            return Err("replacement_origin_advanced".into());
        }
        let mut own_found = false;
        let mut peer_found = false;
        for member in group.members() {
            let id = identity(&member.credential)?;
            if id == self.identity && member.signature_key == self.public_key() && !own_found {
                own_found = true;
            } else if !peer_found
                && id.slot() == accepted.device.slot()
                && id.generation < accepted.device.generation
                && trust::fingerprint(&id, &member.signature_key)? == peer
            {
                peer_found = true;
            } else {
                return Err("replacement_roster_mismatch".into());
            }
        }
        if !own_found || group.members().count() != if peer_found { 2 } else { 1 } {
            return Err("replacement_roster_mismatch".into());
        }
        Ok(if peer_found { "joined" } else { "forming" }.into())
    }

    /// Retire the actual failed target exactly once, retaining the anchor's
    /// existing fence. No intermediate group is created and no wire is emitted.
    pub fn restart_activated_replacement(
        &mut self,
        previous: &[u8],
        failed: &[u8],
        next: &[u8],
        keys: &str,
        now: u64,
    ) -> Result<(), String> {
        let keys: ReplacementKeys = trust::parse(keys)?;
        self.transact(now, |client| {
            client.check_activated_replacement_origin(
                previous,
                failed,
                &keys.old_own,
                &keys.old_peer,
                now,
            )?;
            if next.len() != 16
                || next == failed
                || client.retired_groups.len() >= 8
                || client.retired_groups.iter().any(|g| g == next)
                || keys.old_own != keys.own
                || client.outgoing_context(now, true)?
                    != serde_json::to_string(&(&keys.own, Some(&keys.peer)))
                        .map_err(|_| "invalid_outgoing_context")?
            {
                return Err("invalid_group_restart".into());
            }
            let provider = OpenMlsRustCrypto::default();
            client
                .inner
                .signer
                .store(provider.storage())
                .map_err(|_| "signer_storage_failed")?;
            client.inner.group = None;
            client.inner.provider = provider;
            client.retired_groups.push(failed.to_vec());
            client.next_group = Some(next.to_vec());
            Ok(())
        })
    }

    pub fn fingerprint(&self) -> Result<String, String> {
        Ok(trust::fingerprint(&self.identity, &self.public_key())?)
    }

    /// A signed candidate is displayable without becoming a confirmed pin.
    /// The caller supplies independent confirmation in a separate operation.
    pub fn inspect_peer(&self, token: &str, now: u64) -> Result<String, String> {
        self.check_self(now)?;
        let binding = self
            .trust
            .verify(token, now, self.inner.provider.crypto())?;
        if (binding.device.issuer == self.identity.issuer
            && binding.device.account_id == self.identity.account_id)
            || self
                .peer
                .as_ref()
                .is_some_and(|p| p.slot() != binding.device.slot())
        {
            return Err("unexpected_peer".into());
        }
        serde_json::to_string(&binding.view()?).map_err(|_| "invalid_binding_view".into())
    }

    /// Only public, already verified pin metadata. An accepted replacement does
    /// not make old MLS leaves valid; group_usable remains false until admission.
    pub fn peer_trust(&self, now: u64) -> Result<String, String> {
        let peer = match &self.peer {
            Some(peer) => self.trust.view(peer, now)?,
            None => None,
        };
        let group_usable = if self.inner.group.is_some() {
            self.check_roster(now).is_ok()
        } else {
            self.outgoing_context(now, true).is_ok()
        };
        serde_json::to_string(&serde_json::json!({"peer":peer,"group_usable":group_usable}))
            .map_err(|_| "invalid_binding_view".into())
    }

    pub fn review_peer(&mut self, token: &str, now: u64) -> Result<String, String> {
        self.inspect_peer(token, now)?;
        if self.peer.is_some() {
            self.observe_binding(token, now)
        } else {
            Ok(self
                .trust
                .review_unconfirmed(token, now, self.inner.provider.crypto())?
                .into())
        }
    }

    pub fn registration_proof(&self, nonce: &str, now: u64) -> Result<String, String> {
        if trust::decode(nonce)?.len() != 32 || now > 9_007_199_254_740_931 {
            return Err("invalid_registration_challenge".into());
        }
        let key = self.public_key();
        let header = trust::Header {
            typ: trust::PROOF_TYPE.into(),
            alg: "EdDSA".into(),
            kid: trust::key_id(&key),
        };
        let claims = RegistrationProof {
            aud: self.identity.issuer.clone(),
            device: self.identity.clone(),
            public_key: B64.encode(key),
            nonce: nonce.into(),
            iat: now,
            exp: now + 60,
        };
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).map_err(|_| "proof_encoding_failed")?),
            B64.encode(serde_json::to_vec(&claims).map_err(|_| "proof_encoding_failed")?)
        );
        let signature = self
            .inner
            .signer
            .sign(input.as_bytes())
            .map_err(|_| "proof_signing_failed")?;
        Ok(format!("{input}.{}", B64.encode(signature)))
    }

    /// Explicit replacement enrollment on an empty device. The signed old head
    /// is checked before saving/publishing the new registration proof.
    pub fn check_enrollment_predecessor(
        &mut self,
        token: &str,
        expected: &str,
        revision: u64,
        now: u64,
    ) -> Result<(), String> {
        let old = self
            .trust
            .verify(token, now, self.inner.provider.crypto())?;
        if old.device.slot() != self.identity.slot()
            || old.device.generation.checked_add(1) != Some(self.identity.generation)
            || old.revision != revision
            || trust::fingerprint(&old.device, &trust::decode(&old.public_key)?)? != expected
            || trust::decode(&old.public_key)? == self.public_key()
            || self.inner.group.is_some()
        {
            return Err("enrollment_predecessor_mismatch".into());
        }
        self.own_previous = Some(OwnPredecessor {
            device: old.device,
            fingerprint: expected.into(),
            revision,
        });
        Ok(())
    }
    pub fn enrollment_binding_state(&self, token: &str, now: u64) -> Result<String, String> {
        let binding = self
            .trust
            .verify(token, now, self.inner.provider.crypto())?;
        if binding.device == self.identity
            && trust::decode(&binding.public_key)? == self.public_key()
        {
            return Ok("current".into());
        }
        if let Some(old) = &self.own_previous
            && binding.device == old.device
            && binding.revision == old.revision
            && trust::fingerprint(&binding.device, &trust::decode(&binding.public_key)?)?
                == old.fingerprint
        {
            return Ok("previous".into());
        }
        Err("enrollment_predecessor_mismatch".into())
    }

    /// Verify historical membership for an explicitly selected replacement.
    /// This never confirms a pin, changes enrollment ancestry or opens a group.
    pub fn check_group_predecessor(
        &mut self,
        token: &str,
        expected: &str,
        previous: &[u8],
        next: &[u8],
        now: u64,
    ) -> Result<(), String> {
        self.transact(now, |client| {
            client.check_self(now)?;
            let old = client
                .trust
                .verify(token, now, client.inner.provider.crypto())?;
            if old.device.slot() != client.identity.slot()
                || old.device.generation >= client.identity.generation
                || old.revision == 0
                || old.status != trust::Status::Revoked
                || trust::fingerprint(&old.device, &trust::decode(&old.public_key)?)? != expected
                || trust::decode(&old.public_key)? == client.public_key()
                || client.inner.group.is_some()
                || client.next_group.is_some()
                || previous.len() != 16
                || next.len() != 16
                || previous == next
                || client
                    .retired_groups
                    .iter()
                    .any(|g| g == previous || g == next)
            {
                return Err("replacement_predecessor_mismatch".into());
            }
            client.group_previous = Some(GroupPredecessor {
                old: OwnPredecessor {
                    device: old.device,
                    fingerprint: expected.into(),
                    revision: old.revision,
                },
                previous: previous.to_vec(),
                next: next.to_vec(),
            });
            Ok(())
        })
    }

    /// A separate witnessed transition, called only after both owners approved
    /// a server-linked successor. Exactly one member changes generation/key.
    pub fn replace_group(
        &mut self,
        previous: &[u8],
        next: &[u8],
        keys: &str,
        now: u64,
    ) -> Result<(), String> {
        let keys: ReplacementKeys = trust::parse(keys)?;
        self.transact(now, |client| {
            if previous.len() != 16
                || next.len() != 16
                || previous == next
                || client.retired_groups.len() >= 8
                || client
                    .retired_groups
                    .iter()
                    .any(|g| g == previous || g == next)
                || client.outgoing_context(now, true)?
                    != serde_json::to_string(&(&keys.own, Some(&keys.peer)))
                        .map_err(|_| "invalid_outgoing_context")?
            {
                return Err("invalid_group_replacement".into());
            }
            for fp in [&keys.old_own, &keys.old_peer, &keys.own, &keys.peer] {
                if trust::decode(fp)?.len() != 32 {
                    return Err("invalid_group_replacement".into());
                }
            }
            if let Some(group) = client.inner.group.as_ref() {
                if keys.old_own != keys.own
                    || keys.old_peer == keys.peer
                    || group.group_id().as_slice() != previous
                    || group.members().count() != 2
                {
                    return Err("replacement_roster_mismatch".into());
                }
                let mut own_found = false;
                for member in group.members() {
                    let id = identity(&member.credential)?;
                    if id == client.identity && member.signature_key == client.public_key() {
                        own_found = true;
                    } else {
                        let accepted = client
                            .trust
                            .accepted(client.peer.as_ref().ok_or("first_trust_required")?, now)?;
                        if id.slot() != accepted.device.slot()
                            || id.generation >= accepted.device.generation
                            || member.signature_key == trust::decode(&accepted.public_key)?
                            || trust::fingerprint(&id, &member.signature_key)? != keys.old_peer
                        {
                            return Err("replacement_roster_mismatch".into());
                        }
                    }
                }
                if !own_found {
                    return Err("replacement_roster_mismatch".into());
                }
            } else {
                let old = client
                    .group_previous
                    .as_ref()
                    .filter(|p| p.previous == previous && p.next == next)
                    .map(|p| &p.old)
                    .or(client.own_previous.as_ref())
                    .ok_or("replacement_predecessor_missing")?;
                if keys.old_own == keys.own
                    || keys.old_peer != keys.peer
                    || old.fingerprint != keys.old_own
                    || client.next_group.is_some()
                {
                    return Err("replacement_roster_mismatch".into());
                }
            }
            let provider = OpenMlsRustCrypto::default();
            client
                .inner
                .signer
                .store(provider.storage())
                .map_err(|_| "signer_storage_failed")?;
            client.inner.group = None;
            client.inner.provider = provider;
            client.retired_groups.push(previous.to_vec());
            client.next_group = Some(next.to_vec());
            client.group_previous = None;
            Ok(())
        })
    }

    /// Forget only an unused historical marker after a witnessed proposal veto.
    /// Revoked/expired peer pins remain revoked/expired; no wire is generated.
    pub fn cancel_group_predecessor(
        &mut self,
        previous: &[u8],
        next: &[u8],
        now: u64,
    ) -> Result<(), String> {
        self.transact(now, |client| {
            if previous.len() != 16
                || next.len() != 16
                || previous == next
                || client.inner.group.is_some()
                || client.next_group.is_some()
                || client
                    .group_previous
                    .as_ref()
                    .is_some_and(|p| p.previous != previous || p.next != next)
            {
                return Err("replacement_predecessor_mismatch".into());
            }
            client.group_previous = None;
            Ok(())
        })
    }

    pub fn bind_self(&mut self, token: &str, now: u64) -> Result<(), String> {
        let binding = self
            .trust
            .verify(token, now, self.inner.provider.crypto())?;
        if binding.device != self.identity
            || trust::decode(&binding.public_key)? != self.public_key()
        {
            return Err("own_binding_mismatch".into());
        }
        let expected = self.fingerprint()?;
        Ok(self
            .trust
            .confirm(token, &expected, now, self.inner.provider.crypto())?)
    }

    /// Refresh only this exact device/key; peer observations cannot stand in
    /// for a fresh own lease. Revocation is a retained observation, not an error
    /// for the persistence layer to discard.
    pub fn refresh_self(&mut self, token: &str, now: u64) -> Result<String, String> {
        let binding = self
            .trust
            .verify(token, now, self.inner.provider.crypto())?;
        if binding.device != self.identity
            || trust::decode(&binding.public_key)? != self.public_key()
        {
            return Err("own_binding_mismatch".into());
        }
        self.observe_binding(token, now)
    }

    /// expected must be confirmed through the invitation/fingerprint channel,
    /// independently of the directory response carrying token.
    pub fn confirm_peer(&mut self, token: &str, expected: &str, now: u64) -> Result<(), String> {
        self.trust.time(now)?;
        self.check_self(now)?;
        let binding = self
            .trust
            .verify(token, now, self.inner.provider.crypto())?;
        if self.peer.is_some()
            || (binding.device.issuer == self.identity.issuer
                && binding.device.account_id == self.identity.account_id)
        {
            return Err("unexpected_peer".into());
        }
        self.trust
            .confirm(token, expected, now, self.inner.provider.crypto())?;
        self.peer = Some(binding.device);
        Ok(())
    }

    /// A verified revocation/key change is an accepted observation which blocks
    /// use immediately. The returned status is not an error to discard/retry.
    pub fn observe_binding(&mut self, token: &str, now: u64) -> Result<String, String> {
        let observation = self
            .trust
            .observe(token, now, self.inner.provider.crypto())?;
        Ok(match observation {
            Observation::Current => "current",
            Observation::Revoked => "revoked",
            Observation::KeyChanged => "key_changed",
            Observation::RegistryConflict => "registry_conflict",
        }
        .into())
    }

    pub fn accept_key_change(
        &mut self,
        token: &str,
        previous: &str,
        replacement: &str,
        now: u64,
    ) -> Result<(), String> {
        Ok(self.trust.accept_change(
            token,
            previous,
            replacement,
            now,
            self.inner.provider.crypto(),
        )?)
    }

    pub fn key_package(&mut self, now: u64) -> Result<Vec<u8>, String> {
        self.trust.time(now)?;
        self.check_self(now)?;
        self.inner.key_package()
    }

    pub fn create_group(&mut self, group_id: &[u8], now: u64) -> Result<(), String> {
        self.transact(now, |client| {
            client.check_new_group(group_id)?;
            client.check_self(now)?;
            client.inner.create_group(group_id)
        })
    }

    pub fn invite(&mut self, package: &[u8], now: u64) -> Result<String, String> {
        bounded(package, MAX_WIRE)?;
        self.transact(now, |client| {
            client.check_roster(now)?;
            let package_verified = KeyPackageIn::tls_deserialize_exact(package)
                .map_err(|_| "invalid_key_package")?
                .validate(client.inner.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|_| "invalid_key_package")?;
            let leaf = package_verified.leaf_node();
            client.check_credential(leaf.credential(), leaf.signature_key().as_slice(), now)?;
            let peer = identity(leaf.credential())?;
            if client.peer.as_ref().map(DeviceIdentity::slot) != Some(peer.slot()) {
                return Err("unexpected_peer".into());
            }
            client.inner.invite(package)
        })
    }

    pub fn join(&mut self, welcome: &[u8], group_id: &[u8], now: u64) -> Result<(), String> {
        self.transact(now, |client| {
            client.check_new_group(group_id)?;
            client.check_self(now)?;
            if client.peer.is_none() {
                return Err("first_trust_required".into());
            }
            client.inner.join_inner(welcome, group_id)?;
            client.check_roster(now)
        })
    }

    pub fn send(&mut self, text: &str, now: u64) -> Result<Vec<u8>, String> {
        self.transact(now, |client| {
            client.check_roster(now)?;
            client.inner.send(text)
        })
    }

    pub fn receive(&mut self, message: &[u8], now: u64) -> Result<String, String> {
        bounded(message, MAX_WIRE)?;
        self.transact(now, |client| {
            client.check_self(now)?;
            if client
                .inner
                .group
                .as_ref()
                .is_some_and(|g| g.pending_commit().is_some())
            {
                return Err("commit_pending".into());
            }
            let trust = &client.trust;
            let own = &client.identity;
            let peer = &client.peer;
            let event = client.inner.receive_inner_checked(message, |member| {
                check_member(
                    trust,
                    own,
                    peer.as_ref(),
                    &member.credential,
                    &member.signature_key,
                    now,
                )
            })?;
            // Checks the resulting roster too: an authenticated peer must not
            // smuggle a different device/key through an MLS Add/Update/Commit.
            client.check_roster(now)?;
            let mut event: serde_json::Value =
                serde_json::from_str(&event).map_err(|_| "invalid_event")?;
            if let Some(sender) = event.get("sender").and_then(serde_json::Value::as_str) {
                let sender: DeviceIdentity = trust::parse(sender)?;
                event["sender"] = serde_json::to_value(sender).map_err(|_| "invalid_event")?;
            }
            serde_json::to_string(&event).map_err(|_| "invalid_event".into())
        })
    }

    pub fn update(&mut self, now: u64) -> Result<Vec<u8>, String> {
        self.transact(now, |client| {
            client.check_roster(now)?;
            client.inner.update()
        })
    }

    /// A revoked peer must not prevent the remaining active device removing it.
    pub fn remove_peer(&mut self, now: u64) -> Result<Vec<u8>, String> {
        self.transact(now, |client| {
            client.check_self(now)?;
            client.inner.remove_peer()
        })
    }

    pub fn merge_pending(&mut self, now: u64) -> Result<(), String> {
        self.transact(now, |client| {
            client.check_self(now)?;
            client.inner.merge_pending()?;
            client.check_roster(now)
        })
    }

    pub fn active(&self) -> bool {
        self.inner.active()
    }

    /// Only the witnessed recovery adapter calls this after durable channel
    /// termination and explicit bilateral consent to a fresh group. The device
    /// signing key and trust pins stay; old HPKE/KeyPackage/group state does not.
    pub fn restart_group(
        &mut self,
        previous: &[u8],
        next: &[u8],
        own: &str,
        peer: &str,
        now: u64,
    ) -> Result<(), String> {
        self.transact(now, |client| {
            let context = serde_json::to_string(&(own, Some(peer)))
                .map_err(|_| "invalid_outgoing_context")?;
            if previous.len() != 16
                || next.len() != 16
                || previous == next
                || client.retired_groups.len() >= 8
                || client
                    .retired_groups
                    .iter()
                    .any(|g| g == previous || g == next)
                || client.outgoing_context(now, true)? != context
            {
                return Err("invalid_group_restart".into());
            }
            if let Some(group) = client.inner.group.as_ref() {
                if group.group_id().as_slice() != previous {
                    return Err("previous_group_mismatch".into());
                }
                client.check_roster(now)?;
            } else if client.next_group.as_deref().is_some_and(|g| g != previous) {
                return Err("previous_group_mismatch".into());
            }
            let provider = OpenMlsRustCrypto::default();
            client
                .inner
                .signer
                .store(provider.storage())
                .map_err(|_| "signer_storage_failed")?;
            client.inner.group = None;
            client.inner.provider = provider;
            client.retired_groups.push(previous.to_vec());
            client.next_group = Some(next.to_vec());
            client.group_previous = None;
            Ok(())
        })
    }
    pub fn epoch(&self) -> Result<u64, String> {
        self.inner.epoch()
    }

    /// Plaintext private serialization for tests/the encrypted journal only.
    /// Never persist or expose these bytes without the journal's custody boundary.
    pub fn checkpoint(&self) -> Result<Vec<u8>, String> {
        let state = BoundCheckpoint {
            version: 1,
            identity: self.identity.clone(),
            peer: self.peer.clone(),
            trust: self.trust.clone(),
            inner: self.inner.checkpoint()?,
            retired_groups: self.retired_groups.clone(),
            next_group: self.next_group.clone(),
            own_previous: self.own_previous.clone(),
            group_previous: self.group_previous.clone(),
        };
        let mut bytes = serde_json::to_vec(&state).map_err(|_| "checkpoint_encoding_failed")?;
        if bytes.len() > 2 * MAX_CHECKPOINT {
            bytes.zeroize();
            return Err("checkpoint_too_large".into());
        }
        Ok(bytes)
    }

    pub fn restore(bytes: &[u8], authorities: &str) -> Result<BoundMlsClient, String> {
        bounded(bytes, 2 * MAX_CHECKPOINT)?;
        let state: BoundCheckpoint =
            serde_json::from_slice(bytes).map_err(|_| "invalid_checkpoint")?;
        let authorities: Vec<Authority> = trust::parse(authorities)?;
        TrustStore::new(authorities.clone())?;
        if state.version != 1 || !state.trust.same_authorities(&authorities) {
            return Err("checkpoint_trust_mismatch".into());
        }
        let inner = MlsProbeClient::restore(&state.inner)?;
        if state.retired_groups.len() > 8
            || state
                .retired_groups
                .iter()
                .enumerate()
                .any(|(i, g)| g.len() != 16 || state.retired_groups[..i].contains(g))
            || state
                .next_group
                .as_ref()
                .is_some_and(|g| g.len() != 16 || state.retired_groups.contains(g))
            || inner.group.as_ref().is_some_and(|g| {
                state
                    .retired_groups
                    .iter()
                    .any(|r| r.as_slice() == g.group_id().as_slice())
            })
            || inner.group.as_ref().is_some_and(|g| {
                state
                    .next_group
                    .as_deref()
                    .is_some_and(|next| next != g.group_id().as_slice())
            })
        {
            return Err("checkpoint_group_history_invalid".into());
        }
        if inner.identity != state.identity.credential()? {
            return Err("checkpoint_identity_mismatch".into());
        }
        if let Some(old) = &state.own_previous {
            old.device.validate()?;
            if old.device.slot() != state.identity.slot()
                || old.device.generation.checked_add(1) != Some(state.identity.generation)
                || old.revision == 0
                || trust::decode(&old.fingerprint)?.len() != 32
            {
                return Err("checkpoint_predecessor_invalid".into());
            }
        }
        if let Some(saved) = &state.group_previous {
            saved.old.device.validate()?;
            if saved.old.device.slot() != state.identity.slot()
                || saved.old.device.generation >= state.identity.generation
                || saved.old.revision == 0
                || trust::decode(&saved.old.fingerprint)?.len() != 32
                || saved.previous.len() != 16
                || saved.next.len() != 16
                || saved.previous == saved.next
                || state.retired_groups.contains(&saved.previous)
                || state.retired_groups.contains(&saved.next)
                || state.next_group.is_some()
                || inner.group.is_some()
            {
                return Err("checkpoint_predecessor_invalid".into());
            }
        }
        Ok(Self {
            inner,
            identity: state.identity.clone(),
            peer: state.peer.clone(),
            trust: state.trust.clone(),
            retired_groups: state.retired_groups.clone(),
            next_group: state.next_group.clone(),
            own_previous: state.own_previous.clone(),
            group_previous: state.group_previous.clone(),
        })
    }
}

fn identity(credential: &Credential) -> Result<DeviceIdentity, String> {
    let basic =
        BasicCredential::try_from(credential.clone()).map_err(|_| "basic_credential_required")?;
    let text = std::str::from_utf8(basic.identity()).map_err(|_| "invalid_device_identity")?;
    let identity: DeviceIdentity = trust::parse(text)?;
    if identity.credential()? != text {
        return Err("noncanonical_device_identity".into());
    }
    Ok(identity)
}

fn check_member(
    trust: &TrustStore,
    own: &DeviceIdentity,
    peer: Option<&DeviceIdentity>,
    credential: &Credential,
    key: &[u8],
    now: u64,
) -> Result<(), String> {
    let identity = identity(credential)?;
    if identity.slot() != own.slot() && peer.map(DeviceIdentity::slot) != Some(identity.slot()) {
        return Err("unexpected_peer".into());
    }
    Ok(trust.check(&identity, key, now)?)
}

impl BoundMlsClient {
    fn check_new_group(&self, group: &[u8]) -> Result<(), String> {
        if self.group_previous.is_some() {
            return Err("replacement_pending".into());
        }
        if self.retired_groups.iter().any(|g| g.as_slice() == group)
            || self.next_group.as_deref().is_some_and(|g| g != group)
        {
            return Err("retired_or_unexpected_group".into());
        }
        Ok(())
    }
    fn fork(&self) -> Result<Self, String> {
        Ok(Self {
            inner: MlsProbeClient::restore(&Zeroizing::new(self.inner.checkpoint()?))?,
            identity: self.identity.clone(),
            peer: self.peer.clone(),
            trust: self.trust.clone(),
            retired_groups: self.retired_groups.clone(),
            next_group: self.next_group.clone(),
            own_previous: self.own_previous.clone(),
            group_previous: self.group_previous.clone(),
        })
    }
    fn transact<T>(
        &mut self,
        now: u64,
        operation: impl FnOnce(&mut Self) -> Result<T, String>,
    ) -> Result<T, String> {
        self.trust.time(now)?;
        let mut candidate = self.fork()?;
        let result = operation(&mut candidate)?;
        std::mem::swap(self, &mut candidate);
        Ok(result)
    }
    fn check_self(&self, now: u64) -> Result<(), String> {
        Ok(self.trust.check(&self.identity, &self.public_key(), now)?)
    }
    fn check_credential(
        &self,
        credential: &Credential,
        key: &[u8],
        now: u64,
    ) -> Result<(), String> {
        check_member(
            &self.trust,
            &self.identity,
            self.peer.as_ref(),
            credential,
            key,
            now,
        )
    }
    fn check_roster(&self, now: u64) -> Result<(), String> {
        self.check_self(now)?;
        let group = self.inner.group.as_ref().ok_or("group_missing")?;
        if group.members().count() > 2 {
            return Err("probe_is_one_to_one".into());
        }
        for member in group.members() {
            self.check_credential(&member.credential, &member.signature_key, now)?;
        }
        Ok(())
    }
}
