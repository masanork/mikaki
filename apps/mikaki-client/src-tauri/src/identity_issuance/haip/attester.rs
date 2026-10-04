//! Fixed-origin, bounded native broker transport. No IPC-supplied endpoints or trust.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use serde::de::DeserializeOwned;
use serde::Deserialize;

const ERROR: &str = "wallet_attestation_unavailable";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeResponse {
    challenge: String,
    expires_in: u64,
    purpose: String,
}
struct Challenge {
    encoded: String,
    bytes: [u8; 32],
    until: Instant,
}
impl ChallengeResponse {
    fn validate(self, purpose: &str, started: Instant) -> Result<Challenge, String> {
        if self.purpose != purpose || !(1..=60).contains(&self.expires_in) {
            return Err(ERROR.into());
        }
        let bytes: [u8; 32] = B64
            .decode(&self.challenge)
            .map_err(|_| ERROR)?
            .try_into()
            .map_err(|_| ERROR)?;
        if B64.encode(bytes) != self.challenge {
            return Err(ERROR.into());
        }
        let until = started + Duration::from_secs(self.expires_in);
        if Instant::now() >= until {
            return Err(ERROR.into());
        }
        Ok(Challenge {
            encoded: self.challenge,
            bytes,
            until,
        })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationResponse {
    attestation: String,
    expires_in: u64,
}
impl AttestationResponse {
    fn validate(self, purpose: &str) -> Result<Zeroizing<String>, String> {
        let token = Zeroizing::new(self.attestation);
        let (ttl, size) = match purpose {
            "client" => (300, 24576),
            "holder" => (60, 16384),
            _ => return Err(ERROR.into()),
        };
        if !(1..=ttl).contains(&self.expires_in)
            || token.is_empty()
            || token.len() > size
            || token.split('.').count() != 3
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(ERROR.into());
        }
        Ok(token)
    }
}
fn live(guard: &Gate) -> Result<(), String> {
    if !guard
        .state
        .lock()
        .is_ok_and(|s| s.generation == guard.generation)
    {
        return Err("cancelled".into());
    }
    Ok(())
}
async fn response<T: DeserializeOwned>(mut response: Response, limit: usize) -> Result<T, String> {
    if response.status().as_u16() != 200
        || response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            .is_none_or(|v| !v.eq_ignore_ascii_case("application/json"))
        || response.content_length().is_some_and(|n| n > limit as u64)
    {
        return Err(ERROR.into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| ERROR)? {
        if bytes.len() + chunk.len() > limit {
            return Err(ERROR.into());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| ERROR.into())
}
async fn post<T: DeserializeOwned>(
    guard: &Gate,
    path: &str,
    body: Value,
    headers: Value,
    limit: usize,
) -> Result<T, String> {
    live(guard)?;
    let bytes = Zeroizing::new(serde_json::to_vec(&body).map_err(|_| ERROR)?);
    if bytes.len() > 65536 || !matches!(path, "challenge" | "attestation") {
        return Err(ERROR.into());
    }
    let mut request = client()?
        .post(format!("{ROOT}/identity/attester/{path}"))
        .timeout(Duration::from_secs(10))
        .header("content-type", "application/json")
        .body(bytes.to_vec());
    for (key, value) in headers.as_object().ok_or(ERROR)? {
        if !matches!(
            key.as_str(),
            "OAuth-Client-Attestation" | "OAuth-Client-Attestation-PoP"
        ) {
            return Err(ERROR.into());
        }
        request = request.header(key, value.as_str().ok_or(ERROR)?);
    }
    let value = response(request.send().await.map_err(|_| ERROR)?, limit).await?;
    live(guard)?;
    Ok(value)
}
fn redemption(
    evidence: UntrustedAndroidEvidence,
    client: &str,
    purpose: &str,
    proof: String,
    nonce: Option<&str>,
) -> Result<Value, String> {
    let mut body = serde_json::to_value(evidence).map_err(|_| ERROR)?;
    let object = body.as_object_mut().ok_or(ERROR)?;
    object.insert("client_id".into(), json!(client));
    object.insert("purpose".into(), json!(purpose));
    object.insert("proof".into(), json!(proof));
    if let Some(nonce) = nonce {
        object.insert("c_nonce".into(), json!(nonce));
    }
    Ok(body)
}
pub(super) async fn enroll(
    app: &AppHandle,
    guard: &Gate,
    client: &str,
    callback: &str,
    configuration: &str,
    trust: &[AttesterTrust],
) -> Result<(Session, Zeroizing<String>), String> {
    // Provisioned trust only. Refuse unknown authority before allocating keys or contacting it.
    if callback != CALLBACK
        || !matches!(configuration, "linked_document" | "linked_document_mdoc")
        || client.is_empty()
        || client.len() > 256
        || trust.len() != 1
        || trust[0].issuer != format!("{ROOT}/identity/attester")
    {
        return Err("wallet_configuration_invalid".into());
    }
    mikaki_identity::certificate::validate_attester_roots(&trust[0].trust_anchors)
        .map_err(|_| "wallet_configuration_invalid")?;
    let started = Instant::now();
    let challenge: ChallengeResponse = post(
        guard,
        "challenge",
        json!({"client_id":client,"purpose":"client"}),
        json!({}),
        4096,
    )
    .await?;
    let challenge = challenge.validate("client", started)?;
    live(guard)?;
    let (enrollment, evidence) = Enrollment::start(app, client, &challenge.bytes)?;
    let proof = enrollment.proof(&challenge.encoded)?;
    if Instant::now() >= challenge.until {
        return Err(ERROR.into());
    }
    let issued: AttestationResponse = post(
        guard,
        "attestation",
        redemption(evidence, client, "client", proof, None)?,
        json!({}),
        32768,
    )
    .await?;
    let token = issued.validate("client")?;
    let session = enrollment.begin(app, callback, configuration, &token, trust)?;
    live(guard)?;
    Ok((session, token))
}
pub(super) async fn holder(
    session: &mut Session,
    app: &AppHandle,
    guard: &Gate,
    client_attestation: &str,
    client_trust: &[AttesterTrust],
    nonce: &str,
    key_trust: &Trust,
) -> Result<Zeroizing<String>, String> {
    session.protocol.holder_binding_available(now()?)?;
    key_trust.validate().map_err(str::to_string)?;
    if !valid_id(nonce) {
        return Err(ERROR.into());
    }
    let started = Instant::now();
    let challenge: ChallengeResponse = post(
        guard,
        "challenge",
        json!({"client_id":session.protocol.client_id(),"purpose":"holder","c_nonce":nonce}),
        session.attester_headers(client_attestation, client_trust)?,
        4096,
    )
    .await?;
    let challenge = challenge.validate("holder", started)?;
    live(guard)?;
    let evidence = session.attach_attested_holder(app, &challenge.bytes)?;
    let proof = session.enrollment_proof("holder", &challenge.encoded)?;
    if Instant::now() >= challenge.until {
        return Err(ERROR.into());
    }
    // Separate fresh instance PoP for each request; the server replay ledger is one-use.
    let issued: AttestationResponse = post(
        guard,
        "attestation",
        redemption(
            evidence,
            session.protocol.client_id(),
            "holder",
            proof,
            Some(nonce),
        )?,
        session.attester_headers(client_attestation, client_trust)?,
        24576,
    )
    .await?;
    let token = issued.validate("holder")?;
    let verified = mikaki_identity::key_attestation::verify(&token, nonce, key_trust, true, now()?)
        .map_err(str::to_string)?;
    if verified.holder != session.holder.as_ref().ok_or(ERROR)?.public()? {
        return Err(ERROR.into());
    }
    live(guard)?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn broker_contract_rejects_ambiguous_expired_or_wrong_purpose_challenges() {
        let good = json!({"challenge":B64.encode([7;32]),"expires_in":60,"purpose":"client"});
        let parse = |v: Value, purpose: &str, at| {
            serde_json::from_value::<ChallengeResponse>(v)
                .unwrap()
                .validate(purpose, at)
        };
        assert!(parse(good.clone(), "client", Instant::now()).is_ok());
        assert!(parse(good.clone(), "holder", Instant::now()).is_err());
        assert!(parse(
            good.clone(),
            "client",
            Instant::now() - Duration::from_secs(61)
        )
        .is_err());
        for (field, value) in [
            ("challenge", json!(format!("{}=", B64.encode([7; 32])))),
            ("expires_in", json!(0)),
            ("expires_in", json!(61)),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(parse(bad, "client", Instant::now()).is_err());
        }
        assert!(serde_json::from_slice::<ChallengeResponse>(
            br#"{"challenge":"x","challenge":"y","expires_in":60,"purpose":"client"}"#
        )
        .is_err());
        assert!(serde_json::from_value::<AttestationResponse>(
            json!({"attestation":"a.b.c","expires_in":60,"extra":true})
        )
        .is_err());
        for (purpose, ttl, accepted) in [
            ("client", 300, true),
            ("client", 301, false),
            ("holder", 60, true),
            ("holder", 61, false),
            ("holder", 0, false),
        ] {
            assert_eq!(
                AttestationResponse {
                    attestation: "a.b.c".into(),
                    expires_in: ttl
                }
                .validate(purpose)
                .is_ok(),
                accepted
            );
        }
    }
    #[test]
    fn response_checks_media_status_size_duplicates_and_cancellation() {
        tauri::async_runtime::block_on(async {
            for (status, mime, bytes, ok) in [
                (
                    200,
                    "application/json",
                    br#"{"attestation":"a.b.c","expires_in":60}"#.to_vec(),
                    true,
                ),
                (302, "application/json", b"{}".to_vec(), false),
                (200, "text/html", b"{}".to_vec(), false),
                (200, "application/json", vec![b' '; 32769], false),
                (
                    200,
                    "application/json",
                    br#"{"attestation":"a.b.c","attestation":"d.e.f","expires_in":60}"#.to_vec(),
                    false,
                ),
            ] {
                let wire: Response = openidconnect::http::Response::builder()
                    .status(status)
                    .header("content-type", mime)
                    .body(bytes)
                    .unwrap()
                    .into();
                assert_eq!(
                    response::<AttestationResponse>(wire, 32768).await.is_ok(),
                    ok
                );
            }
        });
        let state = IdentityState::default();
        let guard = gate(&state).unwrap();
        assert!(live(&guard).is_ok());
        state.0.lock().unwrap().generation += 1;
        assert_eq!(live(&guard).unwrap_err(), "cancelled");
    }
}
