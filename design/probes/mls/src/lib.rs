//! Isolated RFC 9420 qualification. No product endpoint or Vault keys.
//!
//! Raw probe credentials are synthetic labels. Bound clients require issuer
//! attestations and independently confirmed device fingerprints.
//! Checkpoints contain plaintext private state and MUST NOT enter product storage.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

mod bound;
pub mod trust;
pub use bound::BoundMlsClient;

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const SOURCE_REVISION: &str = "e0b21a70a55a9014b8de2772b36bf3d638adad51";
const MAX_WIRE: usize = 65_536;
const MAX_CHECKPOINT: usize = 1_048_576;
const MAX_TEXT: usize = 4_096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u8,
    source_revision: String,
    identity: String,
    public_key: Vec<u8>,
    group_id: Option<Vec<u8>>,
    storage: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Drop for Checkpoint {
    fn drop(&mut self) {
        for (_, value) in &mut self.storage {
            value.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Invitation {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Received {
    Application { sender: String, text: String },
    Commit { active: bool },
}

/// Experimental client, exported only by this isolated probe.
#[wasm_bindgen]
pub struct MlsProbeClient {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    identity: String,
    group: Option<MlsGroup>,
}

fn bounded(bytes: &[u8], max: usize) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > max {
        return Err("invalid_size".into());
    }
    Ok(())
}

fn wire(message: &MlsMessageOut) -> Result<Vec<u8>, String> {
    message
        .tls_serialize_detached()
        .map_err(|_| "wire_encoding_failed".into())
}

fn decode(bytes: &[u8]) -> Result<MlsMessageIn, String> {
    bounded(bytes, MAX_WIRE)?;
    MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| "invalid_wire_message".into())
}

fn credential(identity: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(identity.as_bytes().to_vec()).into(),
        signature_key: signer.public().into(),
    }
}

#[wasm_bindgen]
impl MlsProbeClient {
    #[wasm_bindgen(constructor)]
    pub fn new(identity: &str) -> Result<MlsProbeClient, String> {
        if identity.is_empty() || identity.len() > 1024 || !identity.is_ascii() {
            return Err("invalid_probe_identity".into());
        }
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm())
            .map_err(|_| "signer_generation_failed")?;
        signer
            .store(provider.storage())
            .map_err(|_| "signer_storage_failed")?;
        Ok(Self {
            provider,
            signer,
            identity: identity.to_owned(),
            group: None,
        })
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.signer.public().to_vec()
    }

    pub fn key_package(&self) -> Result<Vec<u8>, String> {
        KeyPackage::builder()
            .build(
                SUITE,
                &self.provider,
                &self.signer,
                credential(&self.identity, &self.signer),
            )
            .map_err(|_| "key_package_creation_failed")?
            .key_package()
            .tls_serialize_detached()
            .map_err(|_| "key_package_encoding_failed".into())
    }

    pub fn create_group(&mut self, group_id: &[u8]) -> Result<(), String> {
        if self.group.is_some() || group_id.len() != 16 {
            return Err("invalid_group_creation".into());
        }
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(SUITE)
            .use_ratchet_tree_extension(true)
            .build();
        self.group = Some(
            MlsGroup::new_with_group_id(
                &self.provider,
                &self.signer,
                &config,
                GroupId::from_slice(group_id),
                credential(&self.identity, &self.signer),
            )
            .map_err(|_| "group_creation_failed")?,
        );
        Ok(())
    }

    /// Returns wire Commit/Welcome; the caller explicitly merges the pending commit.
    pub fn invite(&mut self, key_package: &[u8]) -> Result<String, String> {
        bounded(key_package, MAX_WIRE)?;
        let package = KeyPackageIn::tls_deserialize_exact(key_package)
            .map_err(|_| "invalid_key_package")?
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| "invalid_key_package")?;
        if package.ciphersuite() != SUITE {
            return Err("unsupported_ciphersuite".into());
        }
        let group = self.group.as_mut().ok_or("group_missing")?;
        if group.members().count() != 1 {
            return Err("probe_is_one_to_one".into());
        }
        let (commit, welcome, _) = group
            .add_members(&self.provider, &self.signer, &[package])
            .map_err(|_| "add_member_failed")?;
        serde_json::to_string(&Invitation {
            commit: wire(&commit)?,
            welcome: wire(&welcome)?,
        })
        .map_err(|_| "invitation_encoding_failed".into())
    }

    pub fn join(&mut self, welcome: &[u8], expected_group_id: &[u8]) -> Result<(), String> {
        let mut candidate = Self::restore(&Zeroizing::new(self.checkpoint()?))?;
        candidate.join_inner(welcome, expected_group_id)?;
        std::mem::swap(self, &mut candidate);
        Ok(())
    }

    pub fn send(&mut self, text: &str) -> Result<Vec<u8>, String> {
        bounded(text.as_bytes(), MAX_TEXT)?;
        let group = self.group.as_mut().ok_or("group_missing")?;
        if group.pending_commit().is_some() {
            return Err("commit_pending".into());
        }
        let message = group
            .create_message(&self.provider, &self.signer, text.as_bytes())
            .map_err(|_| "send_failed")?;
        wire(&message)
    }

    /// OpenMLS can consume receive/join secrets before an error. Work on an
    /// isolated candidate so rejected traffic cannot corrupt the current state.
    /// This is an in-memory transaction, not a durable storage/outbox contract.
    pub fn receive(&mut self, message: &[u8]) -> Result<String, String> {
        bounded(message, MAX_WIRE)?;
        if self
            .group
            .as_ref()
            .is_some_and(|group| group.pending_commit().is_some())
        {
            return Err("commit_pending".into());
        }
        let mut candidate = Self::restore(&Zeroizing::new(self.checkpoint()?))?;
        let received = candidate.receive_inner(message)?;
        std::mem::swap(self, &mut candidate);
        Ok(received)
    }

    pub fn update(&mut self) -> Result<Vec<u8>, String> {
        let bundle = self
            .group
            .as_mut()
            .ok_or("group_missing")?
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .map_err(|_| "update_failed")?;
        wire(bundle.commit())
    }

    pub fn remove_peer(&mut self) -> Result<Vec<u8>, String> {
        let group = self.group.as_mut().ok_or("group_missing")?;
        let peer = group
            .members()
            .find(|member| member.index != group.own_leaf_index())
            .ok_or("peer_missing")?;
        let (commit, _, _) = group
            .remove_members(&self.provider, &self.signer, &[peer.index])
            .map_err(|_| "removal_failed")?;
        wire(&commit)
    }

    pub fn merge_pending(&mut self) -> Result<(), String> {
        let group = self.group.as_mut().ok_or("group_missing")?;
        if group.pending_commit().is_none() {
            return Err("pending_commit_missing".into());
        }
        group
            .merge_pending_commit(&self.provider)
            .map_err(|_| "pending_commit_merge_failed".into())
    }

    pub fn epoch(&self) -> Result<u64, String> {
        Ok(self.group.as_ref().ok_or("group_missing")?.epoch().as_u64())
    }

    pub fn active(&self) -> bool {
        self.group.as_ref().is_some_and(MlsGroup::is_active)
    }

    /// Plaintext synthetic secret state, for export/import qualification ONLY.
    pub fn checkpoint(&self) -> Result<Vec<u8>, String> {
        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| "storage_unavailable")?;
        let mut storage: Vec<_> = values.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        storage.sort_by(|left, right| left.0.cmp(&right.0));
        let checkpoint = Checkpoint {
            version: 1,
            source_revision: SOURCE_REVISION.into(),
            identity: self.identity.clone(),
            public_key: self.public_key(),
            group_id: self
                .group
                .as_ref()
                .map(|group| group.group_id().as_slice().to_vec()),
            storage,
        };
        let mut bytes =
            serde_json::to_vec(&checkpoint).map_err(|_| "checkpoint_encoding_failed")?;
        if bytes.len() > MAX_CHECKPOINT {
            bytes.zeroize();
            return Err("checkpoint_too_large".into());
        }
        Ok(bytes)
    }

    pub fn restore(bytes: &[u8]) -> Result<MlsProbeClient, String> {
        bounded(bytes, MAX_CHECKPOINT)?;
        let mut checkpoint: Checkpoint =
            serde_json::from_slice(bytes).map_err(|_| "invalid_checkpoint")?;
        if checkpoint.version != 1
            || checkpoint.source_revision != SOURCE_REVISION
            || checkpoint.identity.is_empty()
            || checkpoint.identity.len() > 1024
            || !checkpoint.identity.is_ascii()
            || checkpoint.public_key.len() != 32
            || checkpoint
                .group_id
                .as_ref()
                .is_some_and(|id| id.len() != 16)
        {
            return Err("invalid_checkpoint".into());
        }
        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| "storage_unavailable")?;
            for (key, value) in std::mem::take(&mut checkpoint.storage) {
                if values.insert(key, value).is_some() {
                    return Err("duplicate_storage_key".into());
                }
            }
        }
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &checkpoint.public_key,
            SUITE.signature_algorithm(),
        )
        .ok_or("signer_missing")?;
        let group = checkpoint
            .group_id
            .as_ref()
            .map(|id| {
                MlsGroup::load(provider.storage(), &GroupId::from_slice(id))
                    .map_err(|_| "group_load_failed")?
                    .ok_or("group_state_missing")
            })
            .transpose()?;
        Ok(Self {
            provider,
            signer,
            identity: checkpoint.identity.clone(),
            group,
        })
    }
}

impl MlsProbeClient {
    fn join_inner(&mut self, welcome: &[u8], expected_group_id: &[u8]) -> Result<(), String> {
        if self.group.is_some() || expected_group_id.len() != 16 {
            return Err("invalid_join".into());
        }
        let MlsMessageBodyIn::Welcome(welcome) = decode(welcome)?.extract() else {
            return Err("welcome_required".into());
        };
        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            None,
        )
        .map_err(|_| "invalid_welcome")?;
        if staged.group_context().group_id().as_slice() != expected_group_id
            || staged.group_context().ciphersuite() != SUITE
            || staged.members().count() != 2
        {
            return Err("unexpected_group".into());
        }
        self.group = Some(
            staged
                .into_group(&self.provider)
                .map_err(|_| "join_failed")?,
        );
        Ok(())
    }

    fn receive_inner(&mut self, message: &[u8]) -> Result<String, String> {
        self.receive_inner_checked(message, |_| Ok(()))
    }

    fn receive_inner_checked(
        &mut self,
        message: &[u8],
        check_sender: impl FnOnce(&Member) -> Result<(), String>,
    ) -> Result<String, String> {
        let protocol = decode(message)?
            .try_into_protocol_message()
            .map_err(|_| "protocol_message_required")?;
        let group = self.group.as_mut().ok_or("group_missing")?;
        let processed = group
            .process_message(&self.provider, protocol)
            .map_err(|_| "message_rejected")?;
        let Sender::Member(index) = processed.sender() else {
            return Err("member_sender_required".into());
        };
        let member = group
            .members()
            .find(|member| member.index == *index)
            .ok_or("sender_missing")?;
        if member.credential != *processed.credential() {
            return Err("sender_credential_mismatch".into());
        }
        check_sender(&member)?;
        let sender = BasicCredential::try_from(processed.credential().clone())
            .map_err(|_| "basic_credential_required")?;
        let sender =
            String::from_utf8(sender.identity().to_vec()).map_err(|_| "invalid_sender_label")?;
        let received = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                let bytes = application.into_bytes();
                bounded(&bytes, MAX_TEXT)?;
                Received::Application {
                    sender,
                    text: String::from_utf8(bytes).map_err(|_| "invalid_text")?,
                }
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                group
                    .merge_staged_commit(&self.provider, *commit)
                    .map_err(|_| "commit_merge_failed")?;
                Received::Commit {
                    active: group.is_active(),
                }
            }
            _ => return Err("unsupported_probe_message".into()),
        };
        serde_json::to_string(&received).map_err(|_| "event_encoding_failed".into())
    }
}

impl Drop for MlsProbeClient {
    fn drop(&mut self) {
        if let Ok(mut values) = self.provider.storage().values.write() {
            for value in values.values_mut() {
                value.zeroize();
            }
            values.clear();
        }
    }
}
