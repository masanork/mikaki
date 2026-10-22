//! Two-step native consent. Only saved owner-bound evidence can enter the network flow.
use super::*;
use mikaki_identity::passport::{self as model, credential as profile};
pub(super) struct Pending {
    id: String,
    owner: String,
    evidence: model::Evidence,
    key: HolderKey,
    created: Instant,
    haip: bool,
}
pub(super) struct PassportFlow {
    pub owner: String,
    pub evidence: model::Evidence,
}
// Consume every attempted decision, including a wrong ID, cancellation or owner change.
fn take_review(
    inner: &mut Inner,
    review_id: &str,
    approve: bool,
    owner: Option<&str>,
) -> Result<Option<(Pending, u64)>, String> {
    let pending = inner.passport_review.take().ok_or("review_required")?;
    if pending.id != review_id || pending.created.elapsed() >= Duration::from_secs(300) {
        return Err("review_expired".into());
    }
    if !approve {
        return Ok(None);
    }
    if owner != Some(pending.owner.as_str()) {
        return Err("document_login_required".into());
    }
    Ok(Some((pending, inner.passport_generation)))
}
pub(super) fn retain_receipts(receipts: &mut Vec<(String, Receipt)>, owner: Option<&str>, at: u64) {
    receipts.retain(|(who, r)| Some(who.as_str()) == owner && r.expires_at > at);
}
pub(super) fn clear_owner_session(inner: &mut Inner) {
    inner.passport_review = None;
    inner.passport_receipts.clear();
    inner.passport_generation = inner.passport_generation.wrapping_add(1);
    inner.invalidate_presentations();
    if inner.flow.as_ref().is_some_and(|p| p.passport.is_some()) {
        inner.flow = None;
    }
    if inner.haip.as_ref().is_some_and(|p| p.passport.is_some()) {
        inner.haip = None;
        inner.haip_state = "cancelled";
    }
}
#[derive(Serialize)]
pub struct Review {
    review_id: String,
    issuer: &'static str,
    holder_thumbprint: String,
    claims: model::Dg1Claims,
    expires_at: u64,
}
async fn metadata() -> Result<Value, String> {
    let metadata = body(
        client()?
            .get(format!(
                "{ROOT}/.well-known/openid-credential-issuer/identity/issuer"
            ))
            .send()
            .await
            .map_err(|_| "network_error")?,
    )
    .await?;
    if metadata["credential_issuer"] != ISSUER
        || metadata["credential_endpoint"] != format!("{ISSUER}/credential")
        || metadata["nonce_endpoint"] != format!("{ISSUER}/nonce")
        || metadata["credential_configurations_supported"][profile::CONFIGURATION]["format"]
            != "dc+sd-jwt"
        || metadata["credential_configurations_supported"][profile::CONFIGURATION]["vct"]
            != profile::vct(ISSUER)
    {
        return Err("passport_issuer_unavailable".into());
    }
    if requires_haip(&metadata) || option_env!("MIKAKI_HAIP_WALLET").is_some() {
        if !requires_haip(&metadata) {
            return Err("passport_issuer_unavailable".into());
        }
        super::haip::flow::load_configuration()?;
        let oauth = body(
            client()?
                .get(format!(
                    "{ROOT}/.well-known/oauth-authorization-server/identity/issuer"
                ))
                .send()
                .await
                .map_err(|_| "network_error")?,
        )
        .await?;
        mikaki_identity::wallet_profile::validate_metadata(
            &metadata,
            &oauth,
            profile::CONFIGURATION,
        )?;
    }
    Ok(metadata)
}
fn requires_haip(metadata: &Value) -> bool {
    metadata["credential_configurations_supported"][profile::CONFIGURATION]["proof_types_supported"]
        ["jwt"]["key_attestations_required"]
        .is_object()
}
#[tauri::command]
pub async fn passport_issuance_available() -> bool {
    metadata().await.is_ok()
}
fn policy() -> Result<model::Policy, String> {
    match option_env!("MIKAKI_PASSPORT_CRLS") {
        Some(json) => model::Policy::from_json(json).map_err(str::to_string),
        None => Ok(model::Policy::default()),
    }
}
#[tauri::command]
pub async fn review_passport_issuance(
    app: AppHandle,
    state: State<'_, IdentityState>,
) -> Result<Review, String> {
    let guard = gate(&state)?;
    let generation = state
        .0
        .lock()
        .map_err(|_| "identity_unavailable")?
        .passport_generation;
    let owner = crate::identity_documents::owner(&app)?;
    let metadata = metadata().await?; // Public metadata only; no evidence is transmitted before confirmation.
    let evidence = crate::identity_documents::saved_passport_evidence(&app)?;
    let time = now()?;
    let verified = evidence
        .verify(&policy()?, time)
        .map_err(|_| "passport_verification_required")?;
    let key = HolderKey::create(&app)?;
    let thumbprint = key.public()?.thumbprint().map_err(str::to_string)?;
    let id = random();
    if crate::identity_documents::owner(&app)? != owner {
        return Err("document_login_required".into());
    }
    let mut inner = state.0.lock().map_err(|_| "identity_unavailable")?;
    if inner.generation != guard.generation || inner.passport_generation != generation {
        return Err("cancelled".into());
    }
    let review = Review {
        review_id: id.clone(),
        issuer: ISSUER,
        holder_thumbprint: thumbprint,
        claims: verified.claims().clone(),
        expires_at: (time + 300).min(verified.evidence_valid_until()),
    };
    inner.passport_review = Some(Pending {
        id,
        owner,
        evidence,
        key,
        created: Instant::now(),
        haip: requires_haip(&metadata),
    });
    Ok(review)
}
#[tauri::command]
pub fn cancel_passport_issuance_review(state: State<'_, IdentityState>) -> Result<(), String> {
    let mut inner = state.0.lock().map_err(|_| "identity_unavailable")?;
    inner.passport_review = None;
    inner.passport_generation = inner.passport_generation.wrapping_add(1);
    Ok(())
}
pub(super) fn check_flow_owner(app: &AppHandle, flow: &Flow) -> Result<(), String> {
    if let Some(passport) = &flow.passport {
        if crate::identity_documents::owner(app)? != passport.owner {
            return Err("document_login_required".into());
        }
    }
    Ok(())
}
#[tauri::command]
pub async fn confirm_passport_issuance(
    app: AppHandle,
    state: State<'_, IdentityState>,
    review_id: String,
    approve: bool,
) -> Result<Option<LinkStarted>, String> {
    let guard = gate(&state)?;
    let owner = crate::identity_documents::owner(&app).ok();
    let decision = {
        let mut inner = state.0.lock().map_err(|_| "identity_unavailable")?;
        take_review(&mut inner, &review_id, approve, owner.as_deref())?
    };
    let Some((pending, generation)) = decision else {
        return Ok(None);
    };
    pending
        .evidence
        .verify(&policy()?, now()?)
        .map_err(|_| "passport_verification_required")?;
    let holder = pending.key.public()?;
    let response = body(
        json_request(
            &client()?,
            format!("{ROOT}/identity/passport/intake"),
            json!({"evidence":&pending.evidence,"holder_jwk":holder}),
        )?
        .send()
        .await
        .map_err(|_| "network_error")?,
    )
    .await?;
    let tx = response["transaction_id"]
        .as_str()
        .filter(|s| valid_id(s))
        .ok_or("invalid_response")?
        .to_owned();
    let secret = Zeroizing::new(
        response["poll_secret"]
            .as_str()
            .filter(|s| valid_id(s))
            .ok_or("invalid_response")?
            .to_owned(),
    );
    let url = format!("{ROOT}/identity/passport/approve?tx={tx}");
    let thumbprint = holder.thumbprint().map_err(str::to_string)?;
    let expiry = response["expires_in"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= 600)
        .ok_or("invalid_response")?;
    if response["approval_url"] != url || response["holder_thumbprint"] != thumbprint {
        return Err("invalid_response".into());
    }
    if crate::identity_documents::owner(&app)? != pending.owner {
        return Err("document_login_required".into());
    }
    if pending.haip {
        return super::haip::flow::start_passport(
            &app,
            &state,
            &guard,
            pending.key,
            &tx,
            PassportFlow {
                owner: pending.owner,
                evidence: pending.evidence,
            },
            generation,
            expiry,
        )
        .await
        .map(Some);
    }
    {
        let mut inner = state.0.lock().map_err(|_| "identity_unavailable")?;
        if inner.generation != guard.generation || inner.passport_generation != generation {
            return Err("cancelled".into());
        }
        inner.flow = Some(Flow {
            tx,
            secret,
            keys: vec![pending.key],
            batch_claims: None,
            created: Instant::now(),
            configuration: profile::CONFIGURATION.into(),
            passport: Some(PassportFlow {
                owner: pending.owner,
                evidence: pending.evidence,
            }),
        });
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|_| "browser_unavailable")?;
    Ok(Some(LinkStarted {
        holder_thumbprint: thumbprint.clone(),
        holder_thumbprints: vec![thumbprint],
        credential_count: 1,
        expires_in: expiry,
        haip: false,
    }))
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    fn pending() -> Pending {
        Pending {
            id: "review".into(),
            owner: "owner".into(),
            evidence: model::Evidence::from_bytes(
                include_bytes!("../../../../../crates/identity/src/passport/fixtures/dg1.bin")
                    .to_vec(),
                include_bytes!(
                    "../../../../../crates/identity/src/passport/fixtures/trust-rsa.sod"
                )
                .to_vec(),
            )
            .unwrap(),
            key: HolderKey::Memory(p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap()),
            created: Instant::now(),
            haip: false,
        }
    }
    #[test]
    fn evidence_transfer_requires_current_owner_and_one_use_unexpired_review() {
        for (id, owner, approve, age, accepted) in [
            ("review", Some("owner"), true, 0, true),
            ("wrong", Some("owner"), true, 0, false),
            ("review", Some("other"), true, 0, false),
            ("review", None, true, 0, false),
            ("review", Some("owner"), true, 300, false),
            ("review", Some("owner"), false, 0, false),
        ] {
            let mut pending = pending();
            pending.created -= Duration::from_secs(age);
            let mut inner = Inner {
                passport_review: Some(pending),
                ..Inner::default()
            };
            let result = take_review(&mut inner, id, approve, owner);
            assert_eq!(result.is_ok_and(|r| r.is_some()), accepted);
            assert!(inner.passport_review.is_none());
            assert!(take_review(&mut inner, "review", true, Some("owner")).is_err());
        }
    }
    #[test]
    fn logout_erases_passport_authority_and_invalidates_in_flight_work() {
        use crate::identity_wallet::credential_trust_tests::receipt_with;
        let legacy = receipt_with("dc+sd-jwt", 3, ISSUER);
        let mut inner = Inner {
            passport_review: Some(pending()),
            passport_receipts: vec![("owner".into(), legacy.clone())],
            receipts: vec![legacy],
            ..Inner::default()
        };
        let generation = inner.generation;
        let review_generation = inner.passport_generation;
        clear_owner_session(&mut inner);
        assert!(inner.passport_review.is_none());
        assert!(inner.passport_receipts.is_empty());
        assert_ne!(generation, inner.generation);
        assert_ne!(review_generation, inner.passport_generation);
        assert_eq!(inner.receipts.len(), 1);
    }
    #[test]
    fn transient_passport_credentials_disappear_at_expiry_or_account_change() {
        use crate::identity_wallet::credential_trust_tests::receipt_with;
        let receipt = receipt_with("dc+sd-jwt", 3, ISSUER);
        let end = receipt.expires_at;
        for (owner, at, remaining) in [
            (Some("owner"), end - 1, 1),
            (Some("owner"), end, 0),
            (Some("other"), end - 1, 0),
            (None, end - 1, 0),
        ] {
            let mut receipts = vec![("owner".into(), receipt.clone())];
            retain_receipts(&mut receipts, owner, at);
            assert_eq!(receipts.len(), remaining);
        }
    }
}
