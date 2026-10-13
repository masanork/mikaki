//! Opt-in Android wallet orchestration. IPC exposes phases, never OAuth or key material.
use super::*;

use mikaki_identity::wallet_profile::Configuration;
fn load_configuration() -> Result<Configuration, String> {
    if !cfg!(target_os = "android") {
        return Err("wallet_attestation_unavailable".into());
    }
    Configuration::parse(
        option_env!("MIKAKI_HAIP_WALLET").ok_or("wallet_not_configured")?,
        now()?,
    )
}
#[cfg(target_os = "android")]
pub(crate) fn restoration_trust() -> Result<identity_wallet::CredentialTrust, String> {
    Ok(load_configuration()?.credential_trust)
}
#[derive(Serialize)]
pub struct WalletStatus {
    available: bool,
    phase: &'static str,
}
fn expire(s: &mut Inner, at: u64) {
    if s.haip.as_ref().is_some_and(|p| {
        p.generation != s.generation
            || p.session.protocol.enrollment_available(at).is_err()
            || (!p.ready && at >= p.browser_until)
    }) {
        s.haip = None;
        s.haip_state = "expired";
    }
}
#[tauri::command]
pub fn identity_wallet_issuance_status(
    state: State<'_, IdentityState>,
) -> Result<WalletStatus, String> {
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    expire(&mut s, now()?);
    Ok(WalletStatus {
        available: load_configuration().is_ok(),
        phase: if s.haip_state.is_empty() {
            "idle"
        } else {
            s.haip_state
        },
    })
}
#[tauri::command]
pub fn cancel_identity_wallet_issuance(state: State<'_, IdentityState>) -> Result<(), String> {
    cancel(&state)
}
fn cancel(state: &IdentityState) -> Result<(), String> {
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    // This also invalidates a session temporarily owned by an in-flight async operation.
    s.generation = s.generation.wrapping_add(1);
    s.haip = None;
    s.haip_state = "cancelled";
    Ok(())
}
fn terminal(guard: &Gate, phase: &'static str) {
    if let Ok(mut s) = guard.state.lock() {
        if s.generation == guard.generation {
            s.haip = None;
            s.haip_state = phase;
        }
    }
}
#[tauri::command]
pub async fn start_identity_wallet_issuance(
    app: AppHandle,
    state: State<'_, IdentityState>,
    configuration: String,
    credential_count: Option<usize>,
) -> Result<WalletStatus, String> {
    let cfg = load_configuration()?;
    if !matches!(
        configuration.as_str(),
        "linked_document" | "linked_document_mdoc"
    ) {
        return Err("invalid_configuration".into());
    }
    let requested_count = credential_count.unwrap_or(1);
    if !(1..=mikaki_identity::age_batch::MAX_SIZE).contains(&requested_count) {
        return Err("invalid_age_pool".into());
    }
    let guard = gate(&state)?;
    {
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        s.restore_receipts(&app)?;
        if s.receipts
            .iter()
            .filter(|r| r.expires_at > now().unwrap_or(u64::MAX))
            .count()
            + requested_count
            > mikaki_identity::age_batch::MAX_SIZE
        {
            return Err("wallet_inventory_full".into());
        }
        s.haip = None;
        s.haip_state = "starting";
        s.flow = None;
        s.presentation = None;
    }
    let result = async {
        let context = issuer::metadata(&guard, &configuration).await?;
        let budget = if requested_count > 1 {
            Some(mikaki_identity::age_pool::Budget {
                size: requested_count,
                claims_json: context
                    .age_pool_claims
                    .clone()
                    .ok_or("age_pool_unavailable")?,
            })
        } else {
            None
        };
        let (mut session, attestation) = Enrollment::enroll(
            &app,
            &guard,
            &cfg.client_id,
            CALLBACK,
            &configuration,
            &cfg.client_trust,
        )
        .await?;
        if let Some(budget) = budget {
            session.protocol.request_age_pool(budget, now()?)?;
        }
        session
            .distinct_encryption_key(&context.encryption.request_key().map_err(str::to_string)?)?;
        let started = now()?;
        let (par, as_nonce) = issuer::form(
            &mut session,
            &guard,
            &attestation,
            &cfg.client_trust,
            "par",
            None,
            issuer::send,
        )
        .await?;
        let browser = session.protocol.accept_par(&par, now()?)?;
        let browser_until =
            started.saturating_add(par["expires_in"].as_u64().ok_or("invalid_response")?);
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        // Store before opening so an immediate callback can find this session.
        s.haip = Some(Pending {
            session,
            attestation,
            generation: guard.generation,
            ready: false,
            context: Some(context),
            configuration,
            browser_until,
            as_nonce,
            requested_count,
        });
        s.haip_state = "pending";
        app.opener()
            .open_url(browser.as_str(), None::<&str>)
            .map_err(|_| "browser_unavailable")?;
        Ok(WalletStatus {
            available: true,
            phase: "pending",
        })
    }
    .await;
    if result.is_err() {
        terminal(&guard, "failed");
    }
    result
}
#[tauri::command]
pub async fn receive_identity_wallet_credential(
    app: AppHandle,
    state: State<'_, IdentityState>,
) -> Result<ReceiveResult, String> {
    let cfg = load_configuration()?;
    let guard = gate(&state)?;
    let mut pending = {
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        expire(&mut s, now()?);
        if s.haip.as_ref().is_some_and(|p| !p.ready) {
            return Ok(ReceiveResult {
                state: "pending",
                credential_count: None,
                expires_at: None,
                format: None,
            });
        }
        let p = s.haip.take().ok_or("wallet_transaction_unavailable")?;
        s.haip_state = "receiving";
        p
    };
    let result = async {
        let (token, _) = issuer::form(
            &mut pending.session,
            &guard,
            &pending.attestation,
            &cfg.client_trust,
            "token",
            pending.as_nonce.as_deref(),
            issuer::send,
        )
        .await?;
        pending.session.protocol.accept_token(token, now()?)?;
        let context = pending
            .context
            .take()
            .ok_or("wallet_transaction_unavailable")?;
        let mut receipts = Vec::with_capacity(pending.requested_count);
        for _ in 0..pending.requested_count {
            let nonce = issuer::credential_nonce(&guard).await?;
            let attestation = pending
                .session
                .attest_holder(
                    &app,
                    &guard,
                    &pending.attestation,
                    &cfg.client_trust,
                    &nonce,
                    &cfg.key_trust,
                )
                .await?;
            pending.session.distinct_encryption_key(
                &context.encryption.request_key().map_err(str::to_string)?,
            )?;
            let payload =
                pending
                    .session
                    .credential_request(&nonce, &attestation, &cfg.key_trust)?;
            let issued =
                issuer::credential(&pending.session, &guard, &context, payload, issuer::send)
                    .await?;
            let receipt = verified_receipt(
                issued,
                &context,
                pending
                    .session
                    .holder
                    .take()
                    .ok_or("wallet_transaction_unavailable")?,
                &pending.configuration,
                cfg.credential_trust.clone(),
            )?;
            if let Some(claims) = &context.age_pool_claims {
                batch::validate_age_receipt(&receipt, claims, now()?)?;
            }
            pending
                .session
                .protocol
                .finish_receipt(&receipt.key.public()?, now()?)?;
            receipts.push(receipt);
        }
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        let result = ReceiveResult {
            state: "received",
            credential_count: Some(receipts.len()),
            expires_at: receipts.iter().map(|r| r.expires_at).min(),
            format: receipts.first().map(|r| r.format.clone()),
        };
        s.install_receipts(&app, receipts)?;
        s.haip_state = "received";
        pending.session.protocol.cancel();
        Ok(result)
    }
    .await;
    if result.is_err() {
        terminal(&guard, "failed");
    }
    result
}

pub(super) fn verified_receipt(
    issued: Value,
    context: &issuer::Context,
    key: HolderKey,
    configuration: &str,
    credential_trust: identity_wallet::CredentialTrust,
) -> Result<Receipt, String> {
    let format = match configuration {
        "linked_document" => "dc+sd-jwt",
        "linked_document_mdoc" => "mso_mdoc",
        _ => return Err("invalid_configuration".into()),
    };
    let credentials = issued["credentials"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("invalid_response")?;
    let credential = Zeroizing::new(
        credentials[0]["credential"]
            .as_str()
            .ok_or("invalid_response")?
            .to_owned(),
    );
    let mut receipt = Receipt {
        credential,
        format: format.into(),
        key,
        expires_at: 0,
        issuer_key: context.issuer_key.clone(),
        issuer_kid: context.issuer_kid.clone(),
        credential_trust: Some(credential_trust),
    };
    receipt.expires_at = receipt.validate(ISSUER, now()?)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_requires_explicit_pinned_authority_and_cancellation_invalidates_in_flight_work(
    ) {
        assert!(Configuration::parse("{}", now().unwrap()).is_err());
        assert!(Configuration::parse(&"x".repeat(49153), now().unwrap()).is_err());
        let root = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../crates/identity/tests/fixtures/trust/root.der"
        ));
        use base64::{engine::general_purpose::STANDARD, Engine};
        let root = base64::engine::general_purpose::STANDARD.encode(root);
        let mut cfg = json!({"client_id":"native","client_trust":[{"issuer":format!("{ROOT}/identity/attester"),"trust_anchors":[root]}],"key_trust":{"trust_anchors":[root],"key_storage":null,"user_authentication":null},"credential_trust":{"sd_jwt":{"trust_anchors":[STANDARD.encode(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../../crates/identity/tests/fixtures/credential/sd-ca.der")))]},"mdoc":{"trust_anchors":[STANDARD.encode(include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/../../../crates/identity/tests/fixtures/credential/mdoc-ca.der")))]}}});
        assert!(Configuration::parse(&cfg.to_string(), now().unwrap()).is_ok());
        cfg["client_trust"][0]["issuer"] = json!("https://evil.example");
        assert!(Configuration::parse(&cfg.to_string(), now().unwrap()).is_err());
        let state = IdentityState::default();
        let guard = gate(&state).unwrap();
        cancel(&state).unwrap();
        terminal(&guard, "received");
        assert_eq!(state.0.lock().unwrap().haip_state, "cancelled");
        assert_ne!(state.0.lock().unwrap().generation, guard.generation);
    }
}
