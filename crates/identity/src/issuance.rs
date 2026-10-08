//! Narrow OID4VCI 1.0 profile: ES256 proof, dc+sd-jwt, dedicated holder key.
use crate::evidence::VerifiedDocument;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const CONFIGURATION: &str = "linked_document";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}
impl PublicJwk {
    pub fn from_key(key: &VerifyingKey) -> Self {
        let point = key.to_sec1_point(false);
        Self {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: B64.encode(point.x().expect("uncompressed")),
            y: B64.encode(point.y().expect("uncompressed")),
        }
    }
    pub fn verifying_key(&self) -> Result<VerifyingKey, &'static str> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err("invalid_key");
        }
        let x = B64.decode(&self.x).map_err(|_| "invalid_key")?;
        let y = B64.decode(&self.y).map_err(|_| "invalid_key")?;
        if x.len() != 32 || y.len() != 32 || B64.encode(&x) != self.x || B64.encode(&y) != self.y {
            return Err("invalid_key");
        }
        let mut point = vec![4];
        point.extend(x);
        point.extend(y);
        VerifyingKey::from_sec1_bytes(&point).map_err(|_| "invalid_key")
    }
    pub fn thumbprint(&self) -> Result<String, &'static str> {
        self.verifying_key()?;
        Ok(B64.encode(Sha256::digest(format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            self.x, self.y
        ))))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    d: String,
    kid: String,
}
pub fn issuer_key(raw: &str) -> Result<(SigningKey, String), &'static str> {
    let mut jwk: PrivateJwk = serde_json::from_str(raw).map_err(|_| "invalid_issuer_key")?;
    let mut d = B64.decode(&jwk.d).map_err(|_| "invalid_issuer_key")?;
    use zeroize::Zeroize;
    jwk.d.zeroize();
    let result = SigningKey::from_slice(&d).map_err(|_| "invalid_issuer_key");
    d.zeroize();
    let key = result?;
    if PublicJwk::from_key(key.verifying_key())
        != (PublicJwk {
            kty: jwk.kty,
            crv: jwk.crv,
            x: jwk.x,
            y: jwk.y,
        })
        || jwk.kid.is_empty()
        || jwk.kid.len() > 128
    {
        return Err("invalid_issuer_key");
    }
    Ok((key, jwk.kid))
}
pub fn sign_jwt(key: &SigningKey, header: Value, claims: Value) -> Result<String, &'static str> {
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).map_err(|_| "invalid_json")?),
        B64.encode(serde_json::to_vec(&claims).map_err(|_| "invalid_json")?)
    );
    let sig: Signature = key.sign(input.as_bytes());
    Ok(format!("{input}.{}", B64.encode(sig.to_bytes())))
}
fn parts(compact: &str) -> Result<(&str, Vec<u8>, Vec<u8>), &'static str> {
    if compact.len() > 16384 {
        return Err("invalid_jwt");
    }
    let (input, _signature) = compact.rsplit_once('.').ok_or("invalid_jwt")?;
    let (header, payload) = input.split_once('.').ok_or("invalid_jwt")?;
    if payload.contains('.') {
        return Err("invalid_jwt");
    }
    Ok((
        input,
        B64.decode(header).map_err(|_| "invalid_jwt")?,
        B64.decode(payload).map_err(|_| "invalid_jwt")?,
    ))
}
// Standard JOSE metadata does not change the EC key identity. Never accept private material.
pub(crate) fn proof_jwk<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<PublicJwk, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Jwk {
        kty: String,
        crv: String,
        x: String,
        y: String,
        kid: Option<String>,
        alg: Option<String>,
        #[serde(rename = "use")]
        usage: Option<String>,
        key_ops: Option<Vec<String>>,
    }
    let jwk = Jwk::deserialize(deserializer)?;
    if jwk.kid.is_some_and(|s| s.is_empty() || s.len() > 128)
        || jwk.alg.is_some_and(|s| s != "ES256")
        || jwk.usage.is_some_and(|s| s != "sig")
        || jwk
            .key_ops
            .is_some_and(|ops| ops.len() != 1 || ops[0] != "verify")
    {
        return Err(serde::de::Error::custom("invalid_proof_key"));
    }
    let public = PublicJwk {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
    };
    public.verifying_key().map_err(serde::de::Error::custom)?;
    Ok(public)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofHeader {
    typ: String,
    alg: String,
    #[serde(deserialize_with = "proof_jwk")]
    jwk: PublicJwk,
    key_attestation: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofClaims {
    aud: String,
    iat: u64,
    nonce: String,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    iss: Option<String>,
}
pub fn verify_proof(
    compact: &str,
    holder: &PublicJwk,
    issuer: &str,
    nonce: &str,
    now: u64,
) -> Result<(), &'static str> {
    let (_, header, _) = parts(compact)?;
    let header: ProofHeader = serde_json::from_slice(&header).map_err(|_| "invalid_proof")?;
    if header.key_attestation.is_some() {
        return Err("invalid_proof");
    }
    verify_proof_signature(compact, holder, issuer, nonce, now)
}
fn verify_proof_signature(
    compact: &str,
    holder: &PublicJwk,
    issuer: &str,
    nonce: &str,
    now: u64,
) -> Result<(), &'static str> {
    let (input, header, claims) = parts(compact)?;
    let header: ProofHeader = serde_json::from_slice(&header).map_err(|_| "invalid_proof")?;
    let claims: ProofClaims = serde_json::from_slice(&claims).map_err(|_| "invalid_proof")?;
    if header.typ != "openid4vci-proof+jwt"
        || header.alg != "ES256"
        || &header.jwk != holder
        || claims.aud != issuer
        || claims.nonce != nonce
        || claims.iat > now.saturating_add(30)
        || now.saturating_sub(claims.iat) > 60
        || claims
            .exp
            .is_some_and(|exp| exp <= now || exp > claims.iat.saturating_add(120))
        || claims
            .jti
            .as_ref()
            .is_some_and(|jti| jti.len() < 16 || jti.len() > 128)
        || claims.iss.as_ref().is_some_and(|s| s.len() > 256)
    {
        return Err("invalid_proof");
    }
    let sig = B64
        .decode(compact.rsplit_once('.').ok_or("invalid_proof")?.1)
        .map_err(|_| "invalid_proof")?;
    let sig = Signature::from_slice(&sig).map_err(|_| "invalid_proof")?;
    holder
        .verifying_key()?
        .verify(input.as_bytes(), &sig)
        .map_err(|_| "invalid_proof")
}
/// Verify possession of a wallet-selected key. An optional issuer claim must name
/// the client whose authorization-code grant permits this credential request.
pub fn verify_wallet_proof(
    compact: &str,
    issuer: &str,
    nonce: &str,
    client_id: &str,
    now: u64,
) -> Result<PublicJwk, &'static str> {
    let (_, header, claims) = parts(compact)?;
    let header: ProofHeader = serde_json::from_slice(&header).map_err(|_| "invalid_proof")?;
    let claims: ProofClaims = serde_json::from_slice(&claims).map_err(|_| "invalid_proof")?;
    if claims.iss.as_deref().is_some_and(|iss| iss != client_id) {
        return Err("invalid_proof");
    }
    verify_proof(compact, &header.jwk, issuer, nonce, now)?;
    Ok(header.jwk)
}
/// JWT proof plus an independently trusted, nonce-bound key attestation.
pub fn verify_attested_wallet_proof(
    compact: &str,
    issuer: &str,
    nonce: &str,
    client_id: &str,
    policy: &crate::key_attestation::Trust,
    now: u64,
) -> Result<(PublicJwk, u64), &'static str> {
    let (_, header, claims) = parts(compact)?;
    let header: ProofHeader = serde_json::from_slice(&header).map_err(|_| "invalid_proof")?;
    let claims: ProofClaims = serde_json::from_slice(&claims).map_err(|_| "invalid_proof")?;
    if claims.iss.as_deref().is_some_and(|iss| iss != client_id) {
        return Err("invalid_proof");
    }
    let attestation = crate::key_attestation::verify(
        header.key_attestation.as_deref().ok_or("invalid_proof")?,
        nonce,
        policy,
        true,
        now,
    )?;
    if attestation.holder != header.jwk {
        return Err("invalid_proof");
    }
    verify_proof_signature(compact, &header.jwk, issuer, nonce, now)?;
    Ok((header.jwk, attestation.expires_at))
}
pub fn create_proof(
    key: &SigningKey,
    issuer: &str,
    nonce: &str,
    now: u64,
    jti: &str,
) -> Result<String, &'static str> {
    sign_jwt(
        key,
        json!({"typ":"openid4vci-proof+jwt","alg":"ES256","jwk":PublicJwk::from_key(key.verifying_key())}),
        json!({"aud":issuer,"iat":now,"exp":now+90,"nonce":nonce,"jti":jti}),
    )
}

/// Short lived Mikaki linked-document credential, never a government PID/mDL.
/// Immutable validity of this issuance; all upper bounds are exclusive.
#[derive(Clone, Copy)]
pub struct Validity {
    issued_at: u64,
    expires_at: u64,
}
impl Validity {
    pub fn new(document: &VerifiedDocument, now: u64, deadline: u64) -> Result<Self, &'static str> {
        let mut expires_at = now
            .checked_add(300)
            .ok_or("invalid_validity")?
            .min(deadline);
        if let Some(date) = document.attributes.expiry_date.as_deref() {
            expires_at = expires_at.min(crate::evidence::date_end(date).ok_or("invalid_validity")?);
        } else if document.attributes.document_type == crate::card::DocumentType::DrivingLicense {
            return Err("invalid_validity");
        }
        if expires_at <= now {
            return Err("invalid_validity");
        }
        Ok(Self {
            issued_at: now,
            expires_at,
        })
    }
    /// HAIP privacy policy: minute grid, never extend any verified deadline.
    /// A credential with less than one grid interval remaining is not issued.
    pub fn rounded_minutes(self, not_before: u64) -> Result<Self, &'static str> {
        let issued_at = (self.issued_at / 60 * 60).max(not_before);
        if issued_at > self.issued_at {
            return Err("invalid_validity");
        }
        let expires_at =
            (self.expires_at / 60 * 60).min(issued_at.checked_add(300).ok_or("invalid_validity")?);
        if expires_at <= self.issued_at {
            return Err("invalid_validity");
        }
        Ok(Self {
            issued_at,
            expires_at,
        })
    }
    pub fn expires_at(self) -> u64 {
        self.expires_at
    }
    pub fn issued_at(self) -> u64 {
        self.issued_at
    }
}
/// Also used when verifying restored receipts, independently of the issuer implementation.
pub(crate) fn check_document_expiry(values: &Value, expires_at: u64) -> Result<(), &'static str> {
    if let Some(value) = values.get("document_expiry_date") {
        let date = value.as_str().ok_or("invalid_credential")?;
        if expires_at > crate::evidence::date_end(date).ok_or("invalid_credential")? {
            return Err("invalid_credential");
        }
    }
    Ok(())
}

pub fn issue(
    key: &SigningKey,
    kid: &str,
    issuer: &str,
    holder: &PublicJwk,
    document: &VerifiedDocument,
    now: u64,
    salts: &[[u8; 16]],
) -> Result<String, &'static str> {
    issue_with_validity(
        key,
        kid,
        issuer,
        holder,
        document,
        Validity::new(document, now, u64::MAX)?,
        salts,
    )
}
pub fn issue_with_validity(
    key: &SigningKey,
    kid: &str,
    issuer: &str,
    holder: &PublicJwk,
    document: &VerifiedDocument,
    validity: Validity,
    salts: &[[u8; 16]],
) -> Result<String, &'static str> {
    issue_with_header(
        key,
        json!({"typ":"dc+sd-jwt","alg":"ES256","kid":kid}),
        issuer,
        holder,
        document,
        validity,
        salts,
    )
}
// Keep the explicit signing inputs aligned with issue(); trust adds one policy input.
#[allow(clippy::too_many_arguments)]
pub fn issue_with_certificate_trust(
    key: &SigningKey,
    kid: &str,
    issuer: &str,
    holder: &PublicJwk,
    document: &VerifiedDocument,
    validity: Validity,
    salts: &[[u8; 16]],
    trust: &crate::credential_certificate::SigningTrust,
) -> Result<String, &'static str> {
    let (_, deadline) = crate::credential_certificate::verify(
        trust,
        &PublicJwk::from_key(key.verifying_key()),
        crate::credential_certificate::Purpose::SdJwt,
        validity.issued_at(),
    )?;
    let validity = Validity::new(
        document,
        validity.issued_at(),
        validity.expires_at().min(deadline),
    )?;
    issue_with_header(
        key,
        json!({"typ":"dc+sd-jwt","alg":"ES256","kid":kid,"x5c":trust.chain}),
        issuer,
        holder,
        document,
        validity,
        salts,
    )
}
fn issue_with_header(
    key: &SigningKey,
    header: Value,
    issuer: &str,
    holder: &PublicJwk,
    document: &VerifiedDocument,
    validity: Validity,
    salts: &[[u8; 16]],
) -> Result<String, &'static str> {
    // Rebind even a validity constructed for another document to this document's expiry.
    let validity = Validity::new(document, validity.issued_at, validity.expires_at)?;
    let now = validity.issued_at;
    holder.verifying_key()?;
    let a = &document.attributes;
    let mut claims = vec![
        ("name", json!(a.name)),
        ("address", json!({"formatted":a.address})),
        ("birthdate", json!(a.birth_date)),
    ];
    if !a.gender.is_empty() {
        claims.push(("gender", json!(a.gender)));
    }
    if let Some(date) = &a.expiry_date {
        claims.push(("document_expiry_date", json!(date)));
    }
    if salts.len() != claims.len() {
        return Err("invalid_salts");
    }
    let mut disclosures = Vec::new();
    let mut hashes = Vec::new();
    for ((name, value), salt) in claims.into_iter().zip(salts) {
        let disclosure = B64.encode(
            serde_json::to_vec(&json!([B64.encode(salt), name, value]))
                .map_err(|_| "invalid_json")?,
        );
        hashes.push(B64.encode(Sha256::digest(disclosure.as_bytes())));
        disclosures.push(disclosure);
    }
    let token = sign_jwt(
        key,
        header,
        json!({"iss":issuer,"iat":now,"exp":validity.expires_at,"vct":format!("{issuer}/types/linked-document"),"cnf":{"jwk":holder},"_sd_alg":"sha-256","_sd":hashes,"document_type":a.document_type,"evidence":{"assurance":document.assurance,"verified_at":document.verified_at,"trusted_key_id":document.trusted_key_id,"attributes_source":document.attributes_source,"live_possession_verified":false,"government_credential":false}}),
    )?;
    Ok(format!("{token}~{}~", disclosures.join("~")))
}

pub fn verify_receipt(
    compact: &str,
    issuer_key: &PublicJwk,
    kid: &str,
    holder: &PublicJwk,
    issuer: &str,
    now: u64,
) -> Result<Value, &'static str> {
    if compact.len() > 24000 || !compact.ends_with('~') {
        return Err("invalid_credential");
    }
    let mut segments = compact.split('~');
    let jwt = segments.next().ok_or("invalid_credential")?;
    let (input, header, payload) = parts(jwt)?;
    let header: Value = serde_json::from_slice(&header).map_err(|_| "invalid_credential")?;
    let mut bare = header.clone();
    let chain = bare
        .as_object_mut()
        .ok_or("invalid_credential")?
        .remove("x5c");
    if bare != json!({"typ":"dc+sd-jwt","alg":"ES256","kid":kid}) {
        return Err("invalid_credential");
    }
    let certificate_deadline = if let Some(chain) = chain {
        let chain: Vec<String> = serde_json::from_value(chain).map_err(|_| "invalid_credential")?;
        if chain.is_empty() || chain.len() > 4 {
            return Err("invalid_credential");
        }
        let bytes = chain
            .iter()
            .map(|s| crate::certificate::decode_certificate(s))
            .collect::<Result<Vec<_>, _>>()?;
        crate::credential_certificate::pinned_leaf(
            &bytes[0],
            issuer_key,
            crate::credential_certificate::Purpose::SdJwt,
            now,
        )?
    } else {
        u64::MAX
    };
    let sig = B64
        .decode(jwt.rsplit_once('.').ok_or("invalid_credential")?.1)
        .map_err(|_| "invalid_credential")?;
    issuer_key
        .verifying_key()?
        .verify(
            input.as_bytes(),
            &Signature::from_slice(&sig).map_err(|_| "invalid_credential")?,
        )
        .map_err(|_| "invalid_credential")?;
    let mut claims: Value = serde_json::from_slice(&payload).map_err(|_| "invalid_credential")?;
    if claims["iss"] != issuer
        || claims["vct"] != format!("{issuer}/types/linked-document")
        || claims["cnf"]["jwk"] != serde_json::to_value(holder).map_err(|_| "invalid_key")?
        || claims["_sd_alg"] != "sha-256"
        || claims["exp"].as_u64().is_none_or(|exp| {
            exp <= now
                || exp > certificate_deadline
                || exp > now.saturating_add(330)
                || claims["iat"]
                    .as_u64()
                    .is_none_or(|iat| exp <= iat || exp > iat.saturating_add(300))
        })
        || claims["iat"]
            .as_u64()
            .is_none_or(|iat| iat > now.saturating_add(30) || now.saturating_sub(iat) > 330)
    {
        return Err("invalid_credential");
    }
    let hashes = claims["_sd"]
        .as_array()
        .ok_or("invalid_credential")?
        .clone();
    let mut seen = std::collections::HashSet::new();
    for disclosure in segments.filter(|s| !s.is_empty()) {
        let hash = B64.encode(Sha256::digest(disclosure.as_bytes()));
        if !hashes.contains(&json!(hash)) || !seen.insert(hash) {
            return Err("invalid_credential");
        }
        let array: Value =
            serde_json::from_slice(&B64.decode(disclosure).map_err(|_| "invalid_credential")?)
                .map_err(|_| "invalid_credential")?;
        let array = array
            .as_array()
            .filter(|a| a.len() == 3)
            .ok_or("invalid_credential")?;
        let name = array[1].as_str().ok_or("invalid_credential")?;
        if !matches!(
            name,
            "name" | "address" | "birthdate" | "gender" | "document_expiry_date"
        ) || claims.get(name).is_some()
        {
            return Err("invalid_credential");
        }
        claims[name] = array[2].clone();
    }
    if seen.len() != hashes.len() {
        return Err("invalid_credential");
    }
    check_document_expiry(&claims, claims["exp"].as_u64().ok_or("invalid_credential")?)?;
    Ok(claims)
}

pub fn proof_nonce(compact: &str) -> Result<String, &'static str> {
    let (_, _, payload) = parts(compact)?;
    #[derive(Deserialize)]
    struct Nonce {
        nonce: String,
    }
    let claims: Nonce = serde_json::from_slice(&payload).map_err(|_| "invalid_proof")?;
    // Extract only a routing hint. The caller verifies the proof signature before
    // checking the issued nonce ledger; an unissued nonce is invalid_nonce.
    Ok(claims.nonce)
}
pub type IssuerSigningKey = SigningKey;
