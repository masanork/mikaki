//! Native inventory review snapshots and atomic encrypted confirmation.
use super::*;
use mikaki_identity::presentation::inventory::{InventoryRequest, VerifiedCredential};
#[derive(Serialize)]
pub(super) struct CredentialReview {
    query_id: String,
    format: String,
    values: Value,
    retained_fields: Vec<String>,
}
fn verified(receipts: &[Receipt], at: u64) -> (Vec<&Receipt>, Vec<VerifiedCredential>) {
    let mut native = Vec::new();
    let mut verified = Vec::new();
    for receipt in receipts {
        let Some(trust) = &receipt.credential_trust else {
            continue;
        };
        let Ok(holder) = receipt.key.public() else {
            continue;
        };
        if let Ok(credential) = VerifiedCredential::verify(
            receipt.credential.to_string(),
            &receipt.format,
            receipt.issuer_key.clone(),
            holder,
            ISSUER,
            &receipt.issuer_kid,
            trust.clone(),
            at,
        ) {
            native.push(receipt);
            verified.push(credential);
        }
    }
    (native, verified)
}
pub(super) fn single_selection<'a>(
    receipts: &'a [Receipt],
    request: &mikaki_identity::presentation::ApprovedRequest,
    at: u64,
) -> Result<(&'a Receipt, Value), String> {
    if receipts.len() > 8 || at >= request.expires_at() {
        return Err("invalid_inventory".into());
    }
    if receipts.is_empty() {
        return Err("credential_required".into());
    }
    for receipt in receipts.iter().rev() {
        if receipt.format != request.format()
            || receipt.expires_at <= at
            || receipt.validate(ISSUER, at).is_err()
            || request
                .check_credential_authorities(
                    &receipt.credential,
                    receipt.credential_trust.as_ref(),
                    &receipt.issuer_key,
                    at,
                    receipt.expires_at,
                )
                .is_err()
        {
            continue;
        }
        let values = if receipt.format == "mso_mdoc" {
            mdoc::verify_receipt(
                &receipt.credential,
                &receipt.issuer_key,
                &receipt.key.public()?,
                at,
            )
            .and_then(|r| mdoc::selected_values(&r, &request.fields))
        } else {
            mikaki_identity::presentation::select_disclosures(&receipt.credential, request)
                .map(|(_, v)| v)
        };
        if let Ok(values) = values {
            return Ok((receipt, values));
        }
    }
    Err("credential_does_not_match".into())
}

pub(super) fn prepare(
    app: &AppHandle,
    state: &IdentityState,
    guard: &Gate,
    expected_client: Option<&str>,
    request: InventoryRequest,
) -> Result<PresentationReview, String> {
    if expected_client.is_some_and(|id| id != request.client_id()) {
        return Err("untrusted_verifier".into());
    }
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    if s.generation != guard.generation {
        return Err("identity_cancelled".into());
    }
    s.restore_receipts(app)?;
    // Public/legacy single-receipt flows retain their existing profile and trust rules.
    if request.response_encryption().is_none()
        || !s.receipts.iter().any(|r| r.credential_trust.is_some())
    {
        drop(s);
        return prepare_checked_presentation(
            app,
            state,
            guard,
            expected_client,
            request.into_single().map_err(str::to_string)?,
        );
    }
    let (review, pending) = review(request, &s.receipts, now()?)?;
    let nonce_hash = credential_hash(&format!(
        "{}:{}",
        pending.request.client_id(),
        pending.request.nonce()
    ));
    if s.presented_nonces.contains(&nonce_hash) || s.presented_nonces.len() >= 256 {
        return Err("request_consumed".into());
    }
    s.presentation = Some(pending);
    Ok(review)
}
fn review(
    request: InventoryRequest,
    receipts: &[Receipt],
    at: u64,
) -> Result<(PresentationReview, PendingPresentation), String> {
    if receipts.len() > 8 {
        return Err("wallet_inventory_full".into());
    }
    let (native, verified) = verified(receipts, at);
    let prepared = request.select(&verified, at)?;
    let routing = prepared
        .selected()
        .first()
        .ok_or("credential_required")?
        .request()
        .clone();
    let mut credentials = Vec::new();
    let mut bindings = Vec::new();
    for selection in prepared.selected() {
        credentials.push(CredentialReview {
            query_id: selection.request().query_id().into(),
            format: selection.request().format().into(),
            values: selection.values(at)?,
            retained_fields: selection.request().retained_fields.clone(),
        });
        bindings.push((
            selection.request().query_id().into(),
            credential_hash(&native[selection.inventory_index()].credential),
        ));
    }
    let id = random();
    let review = PresentationReview {
        review_id: id.clone(),
        verifier_name: routing.verifier_name.clone(),
        response_uri: routing.response_uri().into(),
        values: json!({}),
        retained_fields: Vec::new(),
        expires_at: prepared.expires_at(),
        credentials,
    };
    let pending = PendingPresentation {
        id,
        request: routing,
        credential_hash: String::new(),
        expires_at: prepared.expires_at(),
        inventory: Some(request),
        bindings,
    };
    Ok((review, pending))
}
pub(super) fn response(
    pending: &PendingPresentation,
    receipts: &[Receipt],
    at: u64,
) -> Result<Zeroizing<String>, String> {
    if receipts.len() > 8 || at >= pending.expires_at {
        return Err("credential_expired".into());
    }
    let (native, verified) = verified(receipts, at);
    let prepared = pending
        .inventory
        .as_ref()
        .ok_or("review_required")?
        .select(&verified, at)?;
    validate_bindings(pending, &native, &prepared)?;
    let mut proofs = Zeroizing::new(Vec::new());
    for selection in prepared.selected() {
        proofs
            .push(sign(native[selection.inventory_index()], selection.request(), at)?.to_string());
    }
    let mut iv = [0; 12];
    OsRng.fill_bytes(&mut iv);
    prepared
        .encrypt_response(&proofs, at, p256::SecretKey::random(&mut OsRng), iv)
        .map(Zeroizing::new)
}
fn validate_bindings(
    pending: &PendingPresentation,
    native: &[&Receipt],
    prepared: &mikaki_identity::presentation::inventory::PreparedInventory<'_>,
) -> Result<(), String> {
    let bindings: Vec<_> = prepared
        .selected()
        .iter()
        .map(|s| {
            (
                s.request().query_id().to_string(),
                credential_hash(&native[s.inventory_index()].credential),
            )
        })
        .collect();
    if bindings != pending.bindings {
        return Err("credential_changed".into());
    }
    Ok(())
}
pub(super) fn validate(
    pending: &PendingPresentation,
    receipts: &[Receipt],
    at: u64,
) -> Result<(), String> {
    if at >= pending.expires_at || receipts.len() > 8 {
        return Err("credential_expired".into());
    }
    let (native, verified) = verified(receipts, at);
    let prepared = pending
        .inventory
        .as_ref()
        .ok_or("review_required")?
        .select(&verified, at)?;
    validate_bindings(pending, &native, &prepared)
}

fn sign(
    receipt: &Receipt,
    request: &mikaki_identity::presentation::ApprovedRequest,
    at: u64,
) -> Result<Zeroizing<String>, String> {
    if request.format() == "mso_mdoc" {
        let holder = receipt.key.public()?;
        let validated = mdoc::verify_receipt(&receipt.credential, &receipt.issuer_key, &holder, at)
            .map_err(str::to_string)?;
        let transcript = request.mdoc_transcript().map_err(str::to_string)?;
        let authentication = mdoc::device_authentication(&transcript).map_err(str::to_string)?;
        let signature = receipt
            .key
            .sign_bytes(&mdoc::signature_input(&authentication).map_err(str::to_string)?)?;
        mdoc::device_response(
            &validated,
            &request.fields,
            &transcript,
            &signature,
            &holder,
        )
        .map(Zeroizing::new)
        .map_err(str::to_string)
    } else {
        let selected = Zeroizing::new(
            mikaki_identity::presentation::select_disclosures(&receipt.credential, request)
                .map_err(str::to_string)?
                .0,
        );
        let binding = receipt.key.sign(
            json!({"typ":"kb+jwt","alg":"ES256"}),
            mikaki_identity::presentation::binding_claims(&selected, request, at)
                .map_err(str::to_string)?,
        )?;
        Ok(Zeroizing::new(format!("{}{binding}", &*selected)))
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;
    use mikaki_identity::presentation::{self, VerifierRegistration};
    const AT: u64 = 1791000000;
    fn request(nonce: u8) -> InventoryRequest {
        let signer = p256::ecdsa::SigningKey::from_slice(&[5; 32]).unwrap();
        let recipient = p256::ecdsa::SigningKey::from_slice(&[6; 32]).unwrap();
        let registry = VerifierRegistration {
            client_id: "fixture".into(),
            name: "Verifier".into(),
            response_uri: "https://verifier.example/response".into(),
            kid: "key".into(),
            jwk: PublicJwk::from_key(signer.verifying_key()),
            certificate_trust: None,
            profile: presentation::Profile::Oid4vpFinal,
            response_encryption: Some(presentation::encryption::ResponseEncryption {
                kid: "recipient".into(),
                alg: "ECDH-ES".into(),
                enc: "A256GCM".into(),
                jwk: PublicJwk::from_key(recipient.verifying_key()),
            }),
        };
        let claims = json!({"iss":"fixture","aud":"https://self-issued.me/v2","client_id":"fixture","response_type":"vp_token","response_mode":"direct_post.jwt","response_uri":registry.response_uri,"nonce":format!("{nonce:043}"),"state":"S".repeat(43),"iat":AT,"exp":AT+120,"dcql_query":{"credentials":[{"id":"name","format":"dc+sd-jwt","meta":{"vct_values":[format!("{ISSUER}/types/linked-document")]},"claims":[{"path":["name"]}]},{"id":"birth","format":"mso_mdoc","meta":{"doctype_value":mdoc::DOCTYPE},"claims":[{"path":[mdoc::NAMESPACE,"birthdate"],"intent_to_retain":true}]}]}});
        let compact = issuance::sign_jwt(
            &signer,
            json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"key"}),
            claims,
        )
        .unwrap();
        presentation::inventory::verify_request(
            &compact,
            &[registry],
            &format!("{ISSUER}/types/linked-document"),
            AT,
        )
        .unwrap()
    }
    fn receipts() -> Vec<Receipt> {
        use crate::identity_wallet::credential_trust_tests::receipt_with;
        vec![
            receipt_with("dc+sd-jwt", 3, ISSUER),
            receipt_with("mso_mdoc", 8, ISSUER),
        ]
    }
    #[test]
    fn identity_inventory_review_binds_each_credential_and_confirmation_is_atomic() {
        let mut receipts = receipts();
        let (review, pending) = review(request(1), &receipts, AT).unwrap();
        assert_eq!(review.credentials.len(), 2);
        assert_eq!(review.credentials[0].values, json!({"name":"Fixture"}));
        assert_eq!(
            review.credentials[1].values,
            json!({"birthdate":"1990-02-28"})
        );
        assert_eq!(review.credentials[1].retained_fields, ["birthdate"]);
        assert_eq!(pending.bindings.len(), 2);
        let encrypted = response(&pending, &receipts, AT).unwrap();
        assert_eq!(encrypted.split('.').count(), 5);
        if std::env::var("MIKAKI_NATIVE_INVENTORY_PEER").as_deref() == Ok("1") {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
            use std::{
                io::Write,
                process::{Command, Stdio},
            };
            let recipient_key = p256::ecdsa::SigningKey::from_slice(&[6; 32]).unwrap();
            let mut recipient =
                serde_json::to_value(PublicJwk::from_key(recipient_key.verifying_key())).unwrap();
            recipient["d"] = json!(B64.encode([6; 32]));
            let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../local/conformance/support/native-inventory-peer.ts");
            let mut child = Command::new("node")
                .arg(script)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(serde_json::to_string(&json!({"response":&*encrypted,"recipient":recipient,"issuer_key":receipts[0].issuer_key,"issuer":ISSUER,"holder_sd":receipts[0].key.public().unwrap(),"holder_mdoc":receipts[1].key.public().unwrap(),"at":AT,"nonce":pending.request.nonce()})).unwrap().as_bytes()).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "independent native peer failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"native inventory peer passed\n");
        }
        // Inventory order can change; the reviewed query/receipt bindings remain exact.
        receipts.swap(0, 1);
        assert!(response(&pending, &receipts, AT).is_ok());
        assert!(response(&pending, &receipts[..1], AT).is_err());
        assert!(response(&pending, &receipts, AT + 120).is_err());
        receipts[0].key = HolderKey::Memory(p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap());
        assert!(response(&pending, &receipts, AT).is_err());
    }
    #[test]
    fn identity_inventory_cancel_replay_and_changed_receipt_cannot_send_a_partial_batch() {
        let mut receipts = receipts();
        let (review, pending) = review(request(2), &receipts, AT).unwrap();
        let mut state = Inner {
            presentation: Some(pending),
            receipts: receipts.clone(),
            ..Inner::default()
        };
        assert!(state.consume_review("different").is_err());
        let consumed = state.consume_review(&review.review_id).unwrap();
        assert!(consumed.inventory.is_some());
        assert!(state.consume_review(&review.review_id).is_err());
        let (_, same) = super::review(request(2), &receipts, AT).unwrap();
        state.presentation = Some(same);
        assert!(state
            .consume_review(&state.presentation.as_ref().unwrap().id.clone())
            .is_err());
        let (_, fresh) = super::review(request(3), &receipts, AT).unwrap();
        let id = fresh.id.clone();
        state.presentation = Some(fresh);
        state.invalidate_presentations();
        assert!(state.consume_review(&id).is_err());
        receipts[1].credential = Zeroizing::new("tampered".into());
        assert!(response(&consumed, &receipts, AT).is_err());
        assert!(super::review(request(4), &receipts, AT).is_err());
    }
    #[test]
    fn identity_inventory_single_receipt_adapter_finds_the_reviewed_format_not_the_latest_slot() {
        let mut receipts = receipts();
        let (_, pending) = review(request(5), &receipts, AT).unwrap();
        for receipt in &mut receipts {
            receipt.credential_trust = None;
        }
        let (selected, values) = single_selection(&receipts, &pending.request, AT).unwrap();
        assert_eq!(selected.format, "dc+sd-jwt");
        assert_eq!(values, json!({"name":"Fixture"}));
        assert!(single_selection(&receipts[1..], &pending.request, AT).is_err());
    }
}
