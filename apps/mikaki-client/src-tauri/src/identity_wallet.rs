//! Android Keystore holder custody and authenticated, no-backup credential persistence.
#[cfg(target_os = "android")]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
pub use mikaki_identity::credential_receipt::CredentialTrust;
use mikaki_identity::{
    issuance::{self, PublicJwk},
    mdoc,
};
#[cfg(target_os = "android")]
use p256::ecdsa::Signature;
#[cfg(not(target_os = "android"))]
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
#[cfg(target_os = "android")]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tauri::AppHandle;
#[cfg(target_os = "android")]
use tauri_plugin_native_dpop::NativeDpopExt;
use zeroize::Zeroizing;
#[cfg(all(test, not(target_os = "android")))]
#[path = "identity_wallet/credential_trust_tests.rs"]
pub(crate) mod credential_trust_tests;

#[cfg(target_os = "android")]
pub struct OsHolder {
    app: AppHandle,
    id: String,
    persistent: AtomicBool,
}
#[cfg(target_os = "android")]
impl Drop for OsHolder {
    fn drop(&mut self) {
        if !self.persistent.load(Ordering::SeqCst) {
            let _ = self.app.native_dpop().delete_holder(&self.id);
        }
    }
}
#[derive(Clone)]
pub enum HolderKey {
    #[cfg(target_os = "android")]
    Os(Arc<OsHolder>),
    #[cfg(not(target_os = "android"))]
    Memory(SigningKey),
}
impl HolderKey {
    /// No fallback to an unattested or host memory key. The server challenge is
    /// attached at generation; existing keys cannot be retroactively attested.
    #[allow(dead_code)]
    pub fn create_attested(
        app: &AppHandle,
        challenge: &[u8; 32],
    ) -> Result<
        (
            Self,
            mikaki_identity::android_attestation_evidence::UntrustedAndroidEvidence,
        ),
        String,
    > {
        #[cfg(target_os = "android")]
        {
            use rand_core::{OsRng, RngCore};
            let mut bytes = [0; 16];
            OsRng.fill_bytes(&mut bytes);
            let id = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            let result = app
                .native_dpop()
                .create_attested_holder(&id, &B64.encode(challenge))?;
            let key = Self::Os(Arc::new(OsHolder {
                app: app.clone(),
                id,
                persistent: AtomicBool::new(false),
            }));
            let public = PublicJwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x: result.x,
                y: result.y,
            };
            if key.public()? != public {
                return Err("wallet_attestation_unavailable".into());
            }
            let evidence =
                mikaki_identity::android_attestation_evidence::UntrustedAndroidEvidence::collect(
                    challenge,
                    public,
                    result.certificate_chain,
                )
                .map_err(str::to_string)?;
            Ok((key, evidence))
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = (app, challenge);
            Err("wallet_attestation_unavailable".into())
        }
    }
    pub fn destroy(&self) -> Result<(), String> {
        #[cfg(target_os = "android")]
        {
            let Self::Os(key) = self;
            key.app.native_dpop().delete_holder(&key.id)?;
        }
        Ok(())
    }
    pub fn create(app: &AppHandle) -> Result<Self, String> {
        #[cfg(target_os = "android")]
        {
            use rand_core::{OsRng, RngCore};
            let mut bytes = [0; 16];
            OsRng.fill_bytes(&mut bytes);
            let id = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            app.native_dpop().create_holder(&id)?;
            Ok(Self::Os(Arc::new(OsHolder {
                app: app.clone(),
                id,
                persistent: AtomicBool::new(false),
            })))
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = app;
            Ok(Self::Memory(SigningKey::random(&mut rand_core::OsRng)))
        }
    }
    pub fn public(&self) -> Result<PublicJwk, String> {
        match self {
            #[cfg(target_os = "android")]
            Self::Os(key) => {
                let p = key.app.native_dpop().holder_public_key(&key.id)?;
                let jwk = PublicJwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: p.x,
                    y: p.y,
                };
                jwk.verifying_key().map_err(str::to_string)?;
                Ok(jwk)
            }
            #[cfg(not(target_os = "android"))]
            Self::Memory(key) => Ok(PublicJwk::from_key(key.verifying_key())),
        }
    }
    pub fn sign(&self, header: Value, claims: Value) -> Result<String, String> {
        match self {
            #[cfg(target_os = "android")]
            Self::Os(key) => {
                let input = format!(
                    "{}.{}",
                    B64.encode(serde_json::to_vec(&header).map_err(|_| "invalid_request")?),
                    B64.encode(serde_json::to_vec(&claims).map_err(|_| "invalid_request")?)
                );
                let der = Zeroizing::new(
                    B64.decode(key.app.native_dpop().sign_holder(&key.id, &input)?)
                        .map_err(|_| "wallet_key_unavailable")?,
                );
                let sig = Signature::from_der(&der).map_err(|_| "wallet_key_unavailable")?;
                Ok(format!("{input}.{}", B64.encode(sig.to_bytes())))
            }
            #[cfg(not(target_os = "android"))]
            Self::Memory(key) => issuance::sign_jwt(key, header, claims).map_err(str::to_string),
        }
    }
    pub fn sign_bytes(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        if input.len() > 12288 {
            return Err("invalid_signing_input".into());
        }
        match self {
            #[cfg(target_os = "android")]
            Self::Os(key) => {
                let encoded = Zeroizing::new(B64.encode(input));
                let der = key.app.native_dpop().sign_holder_bytes(&key.id, &encoded)?;
                Ok(
                    Signature::from_der(&B64.decode(der).map_err(|_| "invalid_signature")?)
                        .map_err(|_| "invalid_signature")?
                        .to_bytes()
                        .to_vec(),
                )
            }
            #[cfg(not(target_os = "android"))]
            Self::Memory(key) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = key.sign(input);
                Ok(sig.to_bytes().to_vec())
            }
        }
    }
    pub fn proof(&self, issuer: &str, nonce: &str, now: u64, jti: &str) -> Result<String, String> {
        self.sign(
            json!({"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":self.public()?}),
            json!({"aud":issuer,"nonce":nonce,"iat":now,"exp":now+90,"jti":jti}),
        )
    }
}
#[derive(Clone)]
pub struct Receipt {
    pub credential: Zeroizing<String>,
    pub format: String,
    pub key: HolderKey,
    pub expires_at: u64,
    pub issuer_key: PublicJwk,
    pub issuer_kid: String,
    pub credential_trust: Option<CredentialTrust>,
}
impl Receipt {
    pub fn validate(&self, issuer: &str, now: u64) -> Result<u64, String> {
        let holder = self.key.public()?;
        let expiry = match self.format.as_str() {
            "dc+sd-jwt" => issuance::verify_receipt(
                &self.credential,
                &self.issuer_key,
                &self.issuer_kid,
                &holder,
                issuer,
                now,
            )
            .map_err(str::to_string)?
            .get("exp")
            .and_then(|v| v.as_u64())
            .ok_or("invalid_credential".into()),
            "mso_mdoc" => mdoc::verify_receipt(&self.credential, &self.issuer_key, &holder, now)
                .map(|r| r.expires_at)
                .map_err(str::to_string),
            _ => Err("invalid_credential".into()),
        }?;
        if let Some(trust) = &self.credential_trust {
            trust.verify(
                &self.credential,
                &self.format,
                &self.issuer_key,
                now,
                expiry,
            )?;
        }
        Ok(expiry)
    }
}
#[cfg(any(target_os = "android", test))]
mod storage;
pub fn save_inventory(app: &AppHandle, receipts: &[Receipt]) -> Result<(), String> {
    if receipts.is_empty() || receipts.len() > 8 {
        return Err("wallet_inventory_full".into());
    }
    #[cfg(target_os = "android")]
    {
        let records: Result<Vec<_>, String> = receipts
            .iter()
            .map(|receipt| {
                let HolderKey::Os(key) = &receipt.key;
                Ok(storage::Record {
                    version: 2,
                    haip: Some(receipt.credential_trust.is_some()),
                    id: key.id.clone(),
                    credential: receipt.credential.to_string(),
                    format: receipt.format.clone(),
                    issuer_key: receipt.issuer_key.clone(),
                    issuer_kid: receipt.issuer_kid.clone(),
                    holder: receipt.key.public()?,
                    expires_at: receipt.expires_at,
                })
            })
            .collect();
        let plain = storage::encode(&records?, option_env!("MIKAKI_HAIP_WALLET").is_some())?;
        let encoded = Zeroizing::new(B64.encode(&*plain));
        let HolderKey::Os(key) = &receipts.last().ok_or("credential_required")?.key;
        app.native_dpop().store_wallet(&key.id, &encoded)?;
        for receipt in receipts {
            let HolderKey::Os(key) = &receipt.key;
            key.persistent.store(true, Ordering::SeqCst);
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, receipts);
    }
    Ok(())
}
#[cfg(any(target_os = "android", test))]
fn restoration_profile(version: u8, haip: Option<bool>, configured: bool) -> Result<bool, String> {
    match (version, haip) {
        (1, None) if !configured => Ok(false),
        (1, None) => Err("wallet_legacy_receipt".into()),
        (2, Some(true)) if !configured => Err("wallet_not_configured".into()),
        (2, Some(profile)) => Ok(profile),
        _ => Err("wallet_invalid".into()),
    }
}
pub fn restore_inventory(app: &AppHandle, issuer: &str, now: u64) -> Result<Vec<Receipt>, String> {
    #[cfg(target_os = "android")]
    {
        let Some(payload) = app.native_dpop().load_wallet()? else {
            return Ok(Vec::new());
        };
        let payload = Zeroizing::new(payload);
        if payload.len() > 512000 {
            return Err("wallet_invalid".into());
        }
        let bytes = Zeroizing::new(B64.decode(&*payload).map_err(|_| "wallet_invalid")?);
        let (records, migrate) =
            storage::decode(&bytes, option_env!("MIKAKI_HAIP_WALLET").is_some())?;
        let mut receipts = Vec::new();
        let mut expired = Vec::new();
        for mut r in records {
            if r.expires_at <= now {
                expired.push(r.id.clone());
                continue;
            }
            let key = HolderKey::Os(Arc::new(OsHolder {
                app: app.clone(),
                id: r.id.clone(),
                persistent: AtomicBool::new(true),
            }));
            if key.public()? != r.holder {
                return Err("wallet_key_mismatch".into());
            }
            let receipt = Receipt {
                credential: Zeroizing::new(std::mem::take(&mut r.credential)),
                format: r.format.clone(),
                key,
                expires_at: r.expires_at,
                issuer_key: r.issuer_key.clone(),
                issuer_kid: r.issuer_kid.clone(),
                credential_trust: if restoration_profile(
                    r.version,
                    r.haip,
                    option_env!("MIKAKI_HAIP_WALLET").is_some(),
                )? {
                    Some(crate::identity_issuance::haip::flow::restoration_trust()?)
                } else {
                    None
                },
            };
            if receipt.validate(issuer, now)? != receipt.expires_at {
                return Err("wallet_invalid".into());
            }
            receipts.push(receipt);
        }
        // Validate every surviving record before atomically migrating/pruning storage.
        // Keys are removed only after the new complete inventory is committed.
        if receipts.is_empty() {
            app.native_dpop().delete_wallet()?;
        } else if migrate || !expired.is_empty() {
            save_inventory(app, &receipts)?;
        }
        for id in expired {
            app.native_dpop().delete_holder(&id)?;
        }
        Ok(receipts)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, issuer, now);
        Ok(Vec::new())
    }
}
pub fn erase(app: &AppHandle) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        app.native_dpop().erase_wallet()?;
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
    }
    Ok(())
}
