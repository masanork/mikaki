//! Native key custody adapter for the HAIP protocol core.
//! Issuance commands require an explicitly provisioned Android wallet registration and trust.
mod attester;
mod callback;
pub mod flow;
mod issuer;
use super::*;
#[cfg(any(target_os = "android", target_os = "ios"))]
pub use callback::receive;

use mikaki_identity::wallet_profile::CALLBACK;
use mikaki_identity::{
    android_attestation_evidence::UntrustedAndroidEvidence,
    client_attestation::AttesterTrust,
    key_attestation::Trust,
    wallet_authorization::{Authorization, Signer},
};

/// Native-only pending authorization. Callback events contain no OAuth parameters.
pub(super) struct Pending {
    pub session: Session,
    pub attestation: Zeroizing<String>,
    pub generation: u64,
    pub ready: bool,
    context: Option<issuer::Context>,
    pub configuration: String,
    pub browser_until: u64,
    pub as_nonce: Option<String>,
}
impl Signer for HolderKey {
    fn public(&self) -> Result<PublicJwk, String> {
        HolderKey::public(self)
    }
    fn sign(&self, header: Value, claims: Value) -> Result<String, String> {
        HolderKey::sign(self, header, claims)
    }
}
/// Each role gets a fresh distinct Android Keystore key (memory keys on host).
pub(super) struct Session {
    pub protocol: Authorization,
    instance: HolderKey,
    dpop: HolderKey,
    pub holder: Option<HolderKey>,
}
impl Session {
    fn distinct_encryption_key(&self, key: &PublicJwk) -> Result<(), String> {
        if *key == self.instance.public()?
            || *key == self.dpop.public()?
            || self
                .holder
                .as_ref()
                .map(HolderKey::public)
                .transpose()?
                .as_ref()
                == Some(key)
        {
            return Err("invalid_metadata".into());
        }
        Ok(())
    }
    /// Network enrollment retains all authentication material in the native session.
    pub async fn attest_holder(
        &mut self,
        app: &AppHandle,
        guard: &Gate,
        client_attestation: &str,
        client_trust: &[AttesterTrust],
        nonce: &str,
        key_trust: &Trust,
    ) -> Result<Zeroizing<String>, String> {
        let result = attester::holder(
            self,
            app,
            guard,
            client_attestation,
            client_trust,
            nonce,
            key_trust,
        )
        .await;
        if result.is_err() {
            self.protocol.cancel();
            self.holder = None;
        }
        result
    }
    pub fn attester_headers(
        &self,
        attestation: &str,
        trust: &[AttesterTrust],
    ) -> Result<Value, String> {
        let now = now()?;
        self.protocol.enrollment_available(now)?;
        attester_headers(
            &self.instance,
            self.protocol.client_id(),
            attestation,
            trust,
            now,
        )
    }
    pub fn enrollment_proof(&self, purpose: &str, challenge: &str) -> Result<String, String> {
        let key = match purpose {
            "client" => &self.instance,
            "holder" => self
                .holder
                .as_ref()
                .ok_or("wallet_transaction_unavailable")?,
            _ => return Err("invalid_attestation_proof".into()),
        };
        let now = now()?;
        self.protocol.enrollment_available(now)?;
        mikaki_identity::attester_proof::create(
            key,
            self.protocol.client_id(),
            &format!("{ROOT}/identity/attester"),
            challenge,
            purpose,
            now,
        )
    }
    /// Create the holder only after token exchange and the attester's nonce-bound challenge.
    pub fn attach_attested_holder(
        &mut self,
        app: &AppHandle,
        challenge: &[u8; 32],
    ) -> Result<UntrustedAndroidEvidence, String> {
        self.protocol.holder_binding_available(now()?)?;
        let (holder, evidence) = HolderKey::create_attested(app, challenge)?;
        self.protocol.bind_holder(holder.public()?, now()?)?;
        self.holder = Some(holder);
        Ok(evidence)
    }
    #[cfg(all(test, not(target_os = "android")))]
    fn from_keys(
        client: &str,
        callback: &str,
        configuration: &str,
        instance: HolderKey,
        dpop: HolderKey,
        holder: HolderKey,
    ) -> Result<Self, String> {
        let mut entropy = Zeroizing::new([0; 32]);
        UnwrapErr(SysRng).fill_bytes(&mut *entropy);
        let mut verifier = Zeroizing::new([0; 32]);
        UnwrapErr(SysRng).fill_bytes(&mut *verifier);
        let protocol = Authorization::new(
            ISSUER,
            client,
            callback,
            configuration,
            *entropy,
            *verifier,
            instance.public()?,
            dpop.public()?,
            holder.public()?,
            now()?,
        )?;
        Ok(Self {
            protocol,
            instance,
            dpop,
            holder: Some(holder),
        })
    }
    pub fn client_headers(
        &self,
        attestation: &str,
        trust: &[AttesterTrust],
    ) -> Result<Value, String> {
        self.protocol
            .client_headers(attestation, trust, &self.instance, &random(), now()?)
    }
    pub fn dpop(&self, endpoint: &str, nonce: Option<&str>) -> Result<String, String> {
        self.protocol
            .dpop(endpoint, nonce, &self.dpop, &random(), now()?)
    }
    pub fn credential_request(
        &self,
        nonce: &str,
        attestation: &str,
        trust: &Trust,
    ) -> Result<Value, String> {
        self.protocol.credential_request(
            nonce,
            attestation,
            trust,
            self.holder
                .as_ref()
                .ok_or("wallet_transaction_unavailable")?,
            now()?,
        )
    }
}

fn attester_headers(
    instance: &HolderKey,
    client: &str,
    attestation: &str,
    trust: &[AttesterTrust],
    now: u64,
) -> Result<Value, String> {
    let audience = format!("{ROOT}/identity/attester");
    let pop = instance.sign(
        json!({"typ":"oauth-client-attestation-pop+jwt","alg":"ES256"}),
        json!({"iss":client,"aud":audience,"iat":now,"exp":now.saturating_add(60),"jti":random()}),
    )?;
    let binding = mikaki_identity::client_attestation::verify(
        attestation,
        &pop,
        client,
        &audience,
        trust,
        now,
    )
    .map_err(str::to_string)?;
    if binding.thumbprint != instance.public()?.thumbprint().map_err(str::to_string)? {
        return Err("invalid_client".into());
    }
    Ok(json!({"OAuth-Client-Attestation":attestation,"OAuth-Client-Attestation-PoP":pop}))
}

/// Instance enrollment precedes PAR; holder enrollment follows token exchange.
/// Raw evidence is untrusted until the independent verifier and attester approve it.
pub(super) struct Enrollment {
    instance: HolderKey,
    client: String,
    until: u64,
}
impl Enrollment {
    pub async fn enroll(
        app: &AppHandle,
        guard: &Gate,
        client: &str,
        callback: &str,
        configuration: &str,
        trust: &[AttesterTrust],
    ) -> Result<(Session, Zeroizing<String>), String> {
        attester::enroll(app, guard, client, callback, configuration, trust).await
    }
    pub fn start(
        app: &AppHandle,
        client: &str,
        challenge: &[u8; 32],
    ) -> Result<(Self, UntrustedAndroidEvidence), String> {
        if client.is_empty() || client.len() > 256 {
            return Err("wallet_configuration_invalid".into());
        }
        let (instance, evidence) = HolderKey::create_attested(app, challenge)?;
        Ok((
            Self {
                instance,
                client: client.into(),
                until: now()?.saturating_add(60),
            },
            evidence,
        ))
    }
    pub fn proof(&self, challenge: &str) -> Result<String, String> {
        let now = now()?;
        if now >= self.until {
            return Err("wallet_transaction_unavailable".into());
        }
        mikaki_identity::attester_proof::create(
            &self.instance,
            &self.client,
            &format!("{ROOT}/identity/attester"),
            challenge,
            "client",
            now,
        )
    }
    /// Validate the resulting attestation before allocating an authorization session.
    pub fn begin(
        self,
        app: &AppHandle,
        callback: &str,
        configuration: &str,
        attestation: &str,
        trust: &[AttesterTrust],
    ) -> Result<Session, String> {
        let at = now()?;
        if at >= self.until {
            return Err("wallet_transaction_unavailable".into());
        }
        attester_headers(&self.instance, &self.client, attestation, trust, at)?;
        let dpop = HolderKey::create(app)?;
        let mut entropy = Zeroizing::new([0; 32]);
        UnwrapErr(SysRng).fill_bytes(&mut *entropy);
        let mut verifier = Zeroizing::new([0; 32]);
        UnwrapErr(SysRng).fill_bytes(&mut *verifier);
        let protocol = Authorization::new_pending_holder(
            ISSUER,
            &self.client,
            callback,
            configuration,
            *entropy,
            *verifier,
            self.instance.public()?,
            dpop.public()?,
            now()?,
        )?;
        Ok(Session {
            protocol,
            instance: self.instance,
            dpop,
            holder: None,
        })
    }
}
