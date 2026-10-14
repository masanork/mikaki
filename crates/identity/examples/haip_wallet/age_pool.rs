//! Host age-pool qualification. Software keys/volatile custody, no device claims.
use super::*;
use mikaki_identity::{
    age_pool::{Budget, Mode},
    claim_profile::ClaimProfile,
};
type Error = Box<dyn std::error::Error>;

pub(super) fn run(first: Value, input: &mut impl BufRead) -> Result<(), Error> {
    let budget = Budget::parse(&first["age_pool"].to_string())?;
    let profile = budget.validate()?;
    let batch = budget.mode == Mode::Batch;
    if first["metadata"]["mikaki_age_pool"]["max_size"].as_u64() != Some(8)
        || (batch && first["metadata"]["mikaki_age_batch"]["batch_size"].as_u64() != Some(8))
    {
        return Err("age pool unavailable".into());
    }
    let instance = Key(SigningKey::generate_from_rng(&mut UnwrapErr(SysRng)));
    let dpop = Key(SigningKey::generate_from_rng(&mut UnwrapErr(SysRng)));
    let holders: Vec<_> = (0..budget.size)
        .map(|_| Key(SigningKey::generate_from_rng(&mut UnwrapErr(SysRng))))
        .collect();
    let issuer = field(&first, "issuer")?;
    let configuration = field(&first, "configuration")?;
    let format = match configuration {
        issuance::CONFIGURATION => "dc+sd-jwt",
        mdoc::CONFIGURATION => "mso_mdoc",
        _ => return Err("invalid configuration".into()),
    };
    let mut auth = Authorization::new_pending_holder(
        issuer,
        field(&first, "client")?,
        field(&first, "callback")?,
        configuration,
        entropy(),
        entropy(),
        instance.public()?,
        dpop.public()?,
        now(),
    )?;
    auth.request_age_pool(budget.clone(), now())?;
    let policies: Vec<AttesterTrust> = serde_json::from_value(first["client_trust"].clone())?;
    let trust: Trust = serde_json::from_value(first["key_trust"].clone())?;
    trust.validate()?;
    let credential_trust: CredentialTrust =
        serde_json::from_value(first["credential_trust"].clone())?;
    credential_trust.validate(now())?;
    let issuer_key: PublicJwk = serde_json::from_value(first["issuer_key"].clone())?;
    let issuer_kid = field(&first, "issuer_kid")?;
    let encryption =
        WalletEncryption::from_metadata(&first["metadata"], entropy(), "age-pool-recipient")?
            .ok_or("missing encryption")?;
    for key in [instance.public()?, dpop.public()?].into_iter().chain(
        holders
            .iter()
            .map(Key::public)
            .collect::<Result<Vec<_>, _>>()?,
    ) {
        if key == encryption.request_key()? {
            return Err("encryption role collision".into());
        }
    }
    emit(
        json!({"instance":instance.public()?,"dpop":dpop.public()?,"holder":holders[0].public()?,"holders":holders.iter().map(Key::public).collect::<Result<Vec<_>,_>>()?}),
    )?;
    let mut slot = 0;
    let mut receipts: Vec<Zeroizing<String>> = Vec::new();
    let mut used = vec![false; budget.size];
    let mut presented = std::collections::HashSet::new();
    // Includes eight independent enrollments, DPoP challenges and presentation of all slots.
    for _ in 0..128 {
        let v = mikaki_identity::wallet_profile::strict_json(line(input)?.as_bytes())?;
        let at = now();
        match field(&v, "command")? {
            "enroll" => {
                let purpose = field(&v, "purpose")?;
                let signer = match purpose {
                    "client" => &instance,
                    "holder" => holders.get(slot).ok_or("holder exhausted")?,
                    _ => return Err("invalid purpose".into()),
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
                let pop=instance.sign(json!({"typ":"oauth-client-attestation-pop+jwt","alg":"ES256"}),json!({"iss":field(&first,"client")?,"aud":audience,"iat":at,"exp":at+60,"jti":B64.encode(entropy())}))?;
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
                auth.bind_holder(holders[0].public()?, at)?;
                emit(json!({"accepted":true}))?;
            }
            "stage" => {
                auth.stage_credential_proof(
                    field(&v, "credential_nonce")?,
                    field(&v, "attestation")?,
                    &trust,
                    holders.get(slot).ok_or("holder exhausted")?,
                    at,
                )?;
                slot += 1;
                if slot < holders.len() {
                    auth.bind_holder(holders[slot].public()?, at)?;
                }
                emit(json!({"staged":slot}))?;
            }
            "credential" => {
                let payload = if batch {
                    auth.batch_credential_request(at)?
                } else {
                    auth.credential_request(
                        field(&v, "credential_nonce")?,
                        field(&v, "attestation")?,
                        &trust,
                        holders.get(slot).ok_or("holder exhausted")?,
                        at,
                    )?
                };
                let mut iv = [0; 12];
                UnwrapErr(SysRng).fill_bytes(&mut iv);
                let body = if batch {
                    encryption.prepare_batch_request(payload, entropy(), iv)?
                } else {
                    encryption.prepare_request(payload, entropy(), iv)?
                };
                emit(
                    json!({"headers":{"Authorization":&*auth.authorization_header(at)?,"DPoP":auth.dpop("credential",v["nonce"].as_str(),&dpop,&B64.encode(entropy()),at)?},"body":body}),
                )?;
            }
            "received" => {
                if receipts.len() == budget.size {
                    return Err("already received".into());
                }
                let plain = if batch {
                    encryption.decrypt_batch_response(field(&v, "response")?)?
                } else {
                    encryption.decrypt_response(field(&v, "response")?)?
                };
                let issued = mikaki_identity::wallet_profile::strict_json(&plain)?;
                let entries = issued["credentials"]
                    .as_array()
                    .filter(|a| a.len() == if batch { budget.size } else { 1 })
                    .ok_or("invalid count")?;
                let mut incoming = Vec::new();
                for (i, entry) in entries.iter().enumerate() {
                    if entry.as_object().is_none_or(|o| o.len() != 1) {
                        return Err("invalid entry".into());
                    }
                    let key = &holders[if batch { i } else { slot }];
                    let credential = Zeroizing::new(field(entry, "credential")?.to_owned());
                    validate_receipt(
                        &credential,
                        format,
                        &issuer_key,
                        issuer_kid,
                        &key.public()?,
                        issuer,
                        &credential_trust,
                        at,
                    )?;
                    exact_age_values(
                        &credential,
                        format,
                        &issuer_key,
                        issuer_kid,
                        &key.public()?,
                        issuer,
                        &profile,
                        at,
                    )?;
                    incoming.push(credential);
                }
                if batch {
                    auth.finish_batch(
                        &holders
                            .iter()
                            .map(Key::public)
                            .collect::<Result<Vec<_>, _>>()?,
                        at,
                    )?;
                } else {
                    auth.finish_receipt(&holders[slot].public()?, at)?;
                    slot += 1;
                    if slot < holders.len() {
                        auth.bind_holder(holders[slot].public()?, at)?;
                    }
                }
                receipts.extend(incoming);
                if receipts.len() == budget.size {
                    emit(
                        json!({"state":"received","credentials":receipts.iter().map(|r|json!({"credential":r.as_str()})).collect::<Vec<_>>()}),
                    )?;
                } else {
                    emit(json!({"state":"buffered","count":receipts.len()}))?;
                }
            }
            "present" => {
                let result = (|| -> Result<Value, Error> {
                    if receipts.len() != budget.size {
                        return Err("incomplete receive".into());
                    }
                    let index = v["index"]
                        .as_u64()
                        .and_then(|n| usize::try_from(n).ok())
                        .ok_or("missing index")?;
                    let credential = receipts.get(index).ok_or("unknown receipt")?;
                    if used[index] {
                        return Err("used receipt".into());
                    }
                    let registry: Vec<VerifierRegistration> =
                        serde_json::from_value(first["verifiers"].clone())?;
                    let request = presentation::verify_request(
                        field(&v, "request")?,
                        &registry,
                        &format!("{issuer}/types/linked-document"),
                        at,
                    )?;
                    let expiry = validate_receipt(
                        credential,
                        format,
                        &issuer_key,
                        issuer_kid,
                        &holders[index].public()?,
                        issuer,
                        &credential_trust,
                        at,
                    )?;
                    if request.format() != format || request.response_encryption().is_none() {
                        return Err("invalid profile".into());
                    }
                    request.check_credential_authorities(
                        credential,
                        Some(&credential_trust),
                        &issuer_key,
                        at,
                        expiry,
                    )?;
                    if !presented.insert(request.request_hash.clone())
                        || v["consent"] != json!(true)
                    {
                        return Err("consent/replay".into());
                    }
                    let response = presentation_response(
                        credential,
                        format,
                        &issuer_key,
                        &holders[index],
                        &request,
                        at,
                    )?;
                    // Volatile fixture custody only. Native persistence/retirement is tested separately.
                    used[index] = true;
                    Ok(json!({"state":"presented","response":response}))
                })();
                emit(result.unwrap_or_else(|_| json!({"state":"rejected"})))?;
            }
            "finish" => {
                emit(json!({"state":"closed"}))?;
                return Ok(());
            }
            _ => return Err("unknown command".into()),
        }
    }
    Err("fixture command bound exceeded".into())
}
#[allow(clippy::too_many_arguments)]
fn exact_age_values(
    credential: &str,
    format: &str,
    issuer_key: &PublicJwk,
    kid: &str,
    holder: &PublicJwk,
    issuer: &str,
    profile: &ClaimProfile,
    at: u64,
) -> Result<(), Error> {
    let values = if format == "dc+sd-jwt" {
        issuance::verify_receipt(credential, issuer_key, kid, holder, issuer, at)?
    } else {
        mdoc::verify_receipt(credential, issuer_key, holder, at)?.values
    };
    let expected: Vec<String> = serde_json::from_str(&profile.to_json())?;
    let names: Vec<_> = values
        .as_object()
        .ok_or("invalid claims")?
        .keys()
        .filter(|n| mikaki_identity::claim_profile::supported(n))
        .collect();
    if names.len() != expected.len()
        || names.iter().any(|n| !expected.contains(n))
        || expected.iter().any(|n| !values[n].is_boolean())
    {
        return Err("unexpected age claims".into());
    }
    Ok(())
}
