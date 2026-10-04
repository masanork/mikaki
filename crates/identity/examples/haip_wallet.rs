//! Bounded host interoperability bridge, using the production wallet protocol core.
//! The fixture attester is external to this process; private wallet keys never leave it.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_identity::{
    client_attestation::AttesterTrust,
    credential_receipt::CredentialTrust,
    issuance::{self, PublicJwk},
    issuance_encryption::WalletEncryption,
    key_attestation::Trust,
    mdoc,
    presentation::{self, VerifierRegistration},
    wallet_authorization::{Authorization, Signer},
};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, Write},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
struct Key(SigningKey);
impl Signer for Key {
    fn public(&self) -> Result<PublicJwk, String> {
        Ok(PublicJwk::from_key(self.0.verifying_key()))
    }
    fn sign(&self, h: Value, c: Value) -> Result<String, String> {
        issuance::sign_jwt(&self.0, h, c).map_err(str::to_owned)
    }
}
fn entropy() -> [u8; 32] {
    let mut b = [0; 32];
    OsRng.fill_bytes(&mut b);
    b
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn line(input: &mut impl BufRead) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Err("missing fixture command".into());
        }
        let count = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |i| i + 1);
        if bytes.len() + count > 128 * 1024 {
            return Err("oversized fixture command".into());
        }
        let done = available[count - 1] == b'\n';
        bytes.extend_from_slice(&available[..count]);
        input.consume(count);
        if done {
            break;
        }
    }
    Ok(Zeroizing::new(String::from_utf8(std::mem::take(
        &mut *bytes,
    ))?))
}
fn emit(body: Value) -> Result<(), Box<dyn std::error::Error>> {
    println!("{body}");
    io::stdout().flush()?;
    Ok(())
}
fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    v[name].as_str().ok_or("missing fixture field".into())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = io::stdin().lock();
    let first: Value = serde_json::from_str(&line(&mut input)?)?;
    let instance = Key(SigningKey::random(&mut OsRng));
    let dpop = Key(SigningKey::random(&mut OsRng));
    let holder = Key(SigningKey::random(&mut OsRng));
    let mut auth = Authorization::new_pending_holder(
        field(&first, "issuer")?,
        field(&first, "client")?,
        field(&first, "callback")?,
        field(&first, "configuration")?,
        entropy(),
        entropy(),
        instance.public()?,
        dpop.public()?,
        now(),
    )?;
    let policies: Vec<AttesterTrust> = serde_json::from_value(first["client_trust"].clone())?;
    let trust: Trust = serde_json::from_value(first["key_trust"].clone())?;
    trust.validate()?;
    let credential_trust: CredentialTrust =
        serde_json::from_value(first["credential_trust"].clone())?;
    credential_trust.validate(now())?;
    let issuer_key: PublicJwk = serde_json::from_value(first["issuer_key"].clone())?;
    let issuer_kid = field(&first, "issuer_kid")?;
    let format = match field(&first, "configuration")? {
        "linked_document" => "dc+sd-jwt",
        "linked_document_mdoc" => "mso_mdoc",
        _ => return Err("invalid configuration".into()),
    };
    let mut receipt: Option<Zeroizing<String>> = None;
    let mut presented = std::collections::HashSet::new();
    let mut retrieval: Option<presentation::retrieval::RequestRetrieval> = None;
    let encryption =
        WalletEncryption::from_metadata(&first["metadata"], entropy(), "rust-haip-recipient")?
            .ok_or("encryption required for fixture")?;
    for key in [instance.public()?, dpop.public()?, holder.public()?] {
        if encryption.request_key()? == key {
            return Err("encryption key role collision".into());
        }
    }
    emit(json!({"instance":instance.public()?,"dpop":dpop.public()?,"holder":holder.public()?}))?;
    // Includes issuance, the selected official suite and independent multi-query probes.
    for _ in 0..80 {
        let v: Value = serde_json::from_str(&line(&mut input)?)?;
        let at = now();
        match field(&v, "command")? {
            "enroll" => {
                let purpose = field(&v, "purpose")?;
                let signer = match purpose {
                    "client" => &instance,
                    "holder" => &holder,
                    _ => return Err("invalid enrollment purpose".into()),
                };
                let challenge = field(&v, "challenge")?;
                let proof = mikaki_identity::attester_proof::create(
                    signer,
                    field(&first, "client")?,
                    field(&first, "attester")?,
                    challenge,
                    purpose,
                    at,
                )?;
                emit(
                    json!({"client_id":field(&first,"client")?,"purpose":purpose,"challenge":challenge,"public_key":signer.public()?,"proof":proof}),
                )?;
            }
            "attester_headers" => {
                let attestation = field(&v, "attestation")?;
                let audience = field(&first, "attester")?;
                let pop=instance.sign(json!({"typ":"oauth-client-attestation-pop+jwt","alg":"ES256"}),
                    json!({"iss":field(&first,"client")?,"aud":audience,"iat":at,"exp":at+60,"jti":B64.encode(entropy())}))?;
                mikaki_identity::client_attestation::verify(
                    attestation,
                    &pop,
                    field(&first, "client")?,
                    audience,
                    &policies,
                    at,
                )?;
                emit(
                    json!({"OAuth-Client-Attestation":attestation,"OAuth-Client-Attestation-PoP":pop}),
                )?;
            }
            "par" | "token" => {
                let endpoint = field(&v, "command")?;
                let mut headers = auth.client_headers(
                    field(&v, "attestation")?,
                    &policies,
                    &instance,
                    &B64.encode(entropy()),
                    at,
                )?;
                headers["DPoP"] = json!(auth.dpop(
                    endpoint,
                    v["nonce"].as_str(),
                    &dpop,
                    &B64.encode(entropy()),
                    at
                )?);
                let body = if endpoint == "par" {
                    auth.par_parameters(at)?
                } else {
                    auth.token_parameters(at)?
                };
                emit(json!({"headers":headers,"body":body}))?;
            }
            "pushed" => emit(json!({"url":auth.accept_par(&v["response"],at)?.as_str()}))?,
            "callback" => emit(json!({"accepted":auth.accept_callback(field(&v,"url")?,at)?}))?,
            "token_received" => {
                auth.accept_token(v["response"].clone(), at)?;
                auth.bind_holder(holder.public()?, at)?;
                emit(json!({"accepted":true}))?;
            }
            "credential" => {
                let payload = auth.credential_request(
                    field(&v, "credential_nonce")?,
                    field(&v, "attestation")?,
                    &trust,
                    &holder,
                    at,
                )?;
                let mut iv = [0; 12];
                OsRng.fill_bytes(&mut iv);
                let body = encryption.prepare_request(payload, entropy(), iv)?;
                emit(
                    json!({"headers":{"Authorization":&*auth.authorization_header(at)?,"DPoP":auth.dpop("credential",v["nonce"].as_str(),&dpop,&B64.encode(entropy()),at)?},"body":body}),
                )?;
            }
            "received" => {
                if receipt.is_some() {
                    return Err("receipt already received".into());
                }
                let plain = encryption.decrypt_response(field(&v, "response")?)?;
                let issued: Value = serde_json::from_slice(&plain)?;
                let credentials = issued["credentials"]
                    .as_array()
                    .filter(|a| a.len() == 1)
                    .ok_or("invalid credentials")?;
                let credential = Zeroizing::new(field(&credentials[0], "credential")?.to_owned());
                validate_receipt(
                    &credential,
                    format,
                    &issuer_key,
                    issuer_kid,
                    &holder.public()?,
                    field(&first, "issuer")?,
                    &credential_trust,
                    at,
                )?;
                receipt = Some(credential);
                emit(issued)?;
                auth.cancel();
            }
            "request_uri" => {
                if retrieval.is_some() {
                    return Err("pending request retrieval".into());
                }
                let registry: Vec<VerifierRegistration> =
                    serde_json::from_value(first["verifiers"].clone())?;
                let registered = if let Some(client) = v["client_id"].as_str() {
                    registry
                        .iter()
                        .find(|r| r.client_id == client)
                        .ok_or("unregistered verifier")?
                } else {
                    registry.first().ok_or("missing fixture verifier")?
                };
                let context = presentation::retrieval::RequestRetrieval::new(
                    registered,
                    match v["method"].as_str() {
                        None | Some("post") => presentation::retrieval::Method::Post,
                        Some("get") => presentation::retrieval::Method::Get,
                        _ => return Err("invalid retrieval method".into()),
                    },
                    at,
                    entropy(),
                )?;
                emit(json!({"method":context.method(),"form":context.form()?}))?;
                retrieval = Some(context);
            }
            "present" => {
                let result = (|| -> Result<Value, Box<dyn std::error::Error>> {
                    let registry: Vec<VerifierRegistration> =
                        serde_json::from_value(first["verifiers"].clone())?;
                    let vct = format!("{}/types/linked-document", field(&first, "issuer")?);
                    let request = match retrieval.take() {
                        Some(mut context) => {
                            match context.evaluate(field(&v, "request")?, &registry, &vct, at)? {
                                presentation::error_response::Outcome::Approved(request) => {
                                    *request
                                }
                                presentation::error_response::Outcome::Error(error) => {
                                    if !presented.insert(error.request_hash().to_owned()) {
                                        return Err("request replay".into());
                                    }
                                    let uri = error.response_uri().to_owned();
                                    let code = error.code();
                                    let mut iv = [0; 12];
                                    OsRng.fill_bytes(&mut iv);
                                    let response = error.encrypt(
                                        at,
                                        p256::SecretKey::random(&mut OsRng),
                                        iv,
                                    )?;
                                    return Ok(
                                        json!({"state":"protocol_error","response":response,"response_uri":uri,"error":code}),
                                    );
                                }
                            }
                        }
                        None => presentation::verify_request(
                            field(&v, "request")?,
                            &registry,
                            &vct,
                            at,
                        )?,
                    };
                    let credential = receipt.as_ref().ok_or("missing receipt")?;
                    let expiry = validate_receipt(
                        credential,
                        format,
                        &issuer_key,
                        issuer_kid,
                        &holder.public()?,
                        field(&first, "issuer")?,
                        &credential_trust,
                        at,
                    )?;
                    if request.format() != format || request.response_encryption().is_none() {
                        return Err("invalid presentation profile".into());
                    }
                    request.check_credential_authorities(
                        credential,
                        Some(&credential_trust),
                        &issuer_key,
                        at,
                        expiry,
                    )?;
                    if !presented.insert(request.request_hash.clone()) {
                        return Err("request replay".into());
                    }
                    if v["consent"] != json!(true) {
                        return Err("consent required".into());
                    }
                    let vp = if format == "dc+sd-jwt" {
                        let (selected, _) = presentation::select_disclosures(credential, &request)?;
                        presentation::present(&holder.0, &selected, &request, at)?
                    } else {
                        let validated =
                            mdoc::verify_receipt(credential, &issuer_key, &holder.public()?, at)?;
                        let transcript = request.mdoc_transcript()?;
                        let signature: Signature =
                            holder
                                .0
                                .sign(&mdoc::signature_input(&mdoc::device_authentication(
                                    &transcript,
                                )?)?);
                        mdoc::device_response(
                            &validated,
                            &request.fields,
                            &transcript,
                            &signature.to_bytes(),
                            &holder.public()?,
                        )?
                    };
                    let mut iv = [0; 12];
                    OsRng.fill_bytes(&mut iv);
                    let response = presentation::encryption::encrypt_response(
                        &vp,
                        &request,
                        at,
                        p256::SecretKey::random(&mut OsRng),
                        iv,
                    )?;
                    Ok(json!({"state":"presented","response":response}))
                })();
                match result {
                    Ok(response) => emit(response)?,
                    Err(_) => emit(json!({"state":"rejected"}))?,
                }
            }
            "completion" => {
                let registrations: Vec<presentation::completion::Registration> =
                    serde_json::from_value(first["completion_uris"].clone())?;
                let uri = presentation::completion::parse(
                    field(&v, "acknowledgement")?.as_bytes(),
                    field(&v, "client_id")?,
                    &registrations,
                )?
                .ok_or("missing completion URI")?;
                emit(json!({"uri":uri.as_str()}))?;
            }
            "finish" => {
                emit(json!({"state":"closed"}))?;
                return Ok(());
            }
            _ => return Err("unknown fixture command".into()),
        }
    }
    Err("fixture command bound exceeded".into())
}
// Mirror the issuer/holder/trust inputs used by the native receipt validator.
#[allow(clippy::too_many_arguments)]
fn validate_receipt(
    credential: &str,
    format: &str,
    issuer_key: &PublicJwk,
    kid: &str,
    holder: &PublicJwk,
    issuer: &str,
    trust: &CredentialTrust,
    at: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let expiry = if format == "dc+sd-jwt" {
        issuance::verify_receipt(credential, issuer_key, kid, holder, issuer, at)?["exp"]
            .as_u64()
            .ok_or("invalid expiry")?
    } else {
        mdoc::verify_receipt(credential, issuer_key, holder, at)?.expires_at
    };
    trust.verify(credential, format, issuer_key, at, expiry)?;
    Ok(expiry)
}
