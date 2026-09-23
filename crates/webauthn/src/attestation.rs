use super::*;
use std::collections::BTreeMap;
use x509_cert::{
    Certificate,
    der::{Decode, asn1::OctetString},
};

/// Server acceptance policy, distinct from browser conveyance preferences.
#[derive(Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPolicy {
    #[default]
    Optional,
    RequiredTrusted,
}

/// Produced only after successful registration verification.
/// ```compile_fail
/// let forged = sakimori_webauthn::AttestationEvidence {
///     format: "packed", kind: "trusted", aaguid: String::new(), trust: None,
/// };
/// ```
/// AAGUID alone is not evidence of authenticator provenance.
/// ```compile_fail
/// let forged: sakimori_webauthn::AttestationEvidence = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Serialize)]
pub struct AttestationEvidence {
    format: &'static str,
    kind: &'static str,
    aaguid: String,
    trust: Option<TrustEvidence>,
}
impl AttestationEvidence {
    pub fn format(&self) -> &str {
        self.format
    }
    pub fn kind(&self) -> &str {
        self.kind
    }
    pub fn aaguid(&self) -> &str {
        &self.aaguid
    }
    pub fn trust(&self) -> Option<&TrustEvidence> {
        self.trust.as_ref()
    }
}
#[derive(Serialize)]
pub struct TrustEvidence {
    metadata_key: String,
    anchor_sha256: String,
    verified_at: u64,
}
impl TrustEvidence {
    pub fn metadata_key(&self) -> &str {
        &self.metadata_key
    }
    pub fn anchor_sha256(&self) -> &str {
        &self.anchor_sha256
    }
    pub fn verified_at(&self) -> u64 {
        self.verified_at
    }
}

/// Authenticated metadata selected by server policy. Never populate from a client response.
#[derive(Deserialize)]
pub struct Trust {
    pub now: u64,
    pub entries: Vec<Metadata>,
}
#[derive(Deserialize, Serialize)]
pub struct StatusReport {
    pub status: String,
    #[serde(flatten)]
    pub details: BTreeMap<String, serde_json::Value>,
}
#[derive(Deserialize, Serialize)]
pub struct Metadata {
    /// Canonical base64url AAGUID, or an empty string for a U2F entry.
    pub aaguid: String,
    #[serde(default)]
    pub key_ids: Vec<String>,
    pub roots: Vec<String>,
    pub types: Vec<String>,
    pub allowed: bool,
    #[serde(default)]
    pub authenticator_version: Option<u32>,
    #[serde(default)]
    pub status_reports: Vec<StatusReport>,
    #[serde(default)]
    pub time_of_last_status_change: Option<String>,
}
fn bytes<'a>(s: &'a Value, name: &str) -> Result<&'a [u8]> {
    Ok(text_field(s, name)?
        .as_bytes()
        .ok_or(Invalid::Attestation)?)
}
fn algorithm(s: &Value) -> Result<i32> {
    i32::try_from(i128::from(
        text_field(s, "alg")?
            .as_integer()
            .ok_or(Invalid::Attestation)?,
    ))
    .map_err(|_| Invalid::Attestation)
}
fn certs(s: &Value) -> Result<Vec<Vec<u8>>> {
    let list = text_field(s, "x5c")?
        .as_array()
        .ok_or(Invalid::Attestation)?;
    require(!list.is_empty() && list.len() <= 6)?;
    list.iter()
        .map(|c| c.as_bytes().cloned().ok_or(Invalid::Attestation))
        .collect()
}
fn trusted(
    ctx: &Context,
    data: &[u8],
    chain: &[Vec<u8>],
    u2f: bool,
) -> Result<(Certificate, TrustEvidence)> {
    let trust = ctx.attestation.as_ref().ok_or(Invalid::Trust)?;
    require(trust.entries.len() <= 256)?;
    let leaf = certificate::parse(chain.first().ok_or(Invalid::Attestation)?)?;
    let aaguid = B64.encode(&data[37..53]);
    let key_id = sha1::Sha1::digest(
        leaf.tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .ok_or(Invalid::Attestation)?,
    )
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect::<String>();
    let entry = trust
        .entries
        .iter()
        .find(|m| {
            if u2f {
                m.key_ids.contains(&key_id)
            } else {
                m.aaguid == aaguid
            }
        })
        .ok_or(Invalid::Trust)?;
    ensure(entry.allowed, Invalid::Revoked)?;
    ensure(
        entry
            .types
            .iter()
            .any(|s| matches!(s.as_str(), "basic_full" | "attca" | "anonca")),
        Invalid::Trust,
    )?;
    let roots = entry
        .roots
        .iter()
        .map(|r| decode(r, 16384))
        .collect::<Result<Vec<_>>>()?;
    let (cert, anchor_sha256) = certificate::path(chain, &roots, trust.now)?;
    Ok((
        cert,
        TrustEvidence {
            metadata_key: if u2f { key_id } else { aaguid },
            anchor_sha256,
            verified_at: trust.now,
        },
    ))
}
fn aaguid(cert: &Certificate, data: &[u8]) -> Result<()> {
    for ext in cert.tbs_certificate().extensions().into_iter().flatten() {
        if ext.extn_id.to_string() == "1.3.6.1.4.1.45724.1.1.4" {
            require(!ext.critical)?;
            let id = OctetString::from_der(ext.extn_value.as_bytes())
                .map_err(|_| Invalid::Attestation)?;
            require(id.as_bytes() == &data[37..53])?;
        }
    }
    Ok(())
}
fn packed_subject(cert: &Certificate) -> Result<()> {
    require(
        cert.tbs_certificate()
            .get_extension::<x509_cert::ext::pkix::BasicConstraints>()
            .map_err(|_| Invalid::Attestation)?
            .is_some_and(|(_, b)| !b.ca),
    )?;
    let country = cert
        .tbs_certificate()
        .subject()
        .country()
        .map_err(|_| Invalid::Attestation)?
        .ok_or(Invalid::Attestation)?;
    require(
        country.as_str().len() == 2 && country.as_str().bytes().all(|c| c.is_ascii_uppercase()),
    )?;
    require(cert.tbs_certificate().version() == x509_cert::certificate::Version::V3)?;
    let name = cert.tbs_certificate().subject();
    let attr = |oid: &str| {
        name.iter()
            .filter(|a| a.oid.to_string() == oid)
            .collect::<Vec<_>>()
    };
    for oid in ["2.5.4.6", "2.5.4.10", "2.5.4.3"] {
        let values = attr(oid);
        require(values.len() == 1 && !values[0].value.value().is_empty())?;
    }
    let ou = attr("2.5.4.11");
    require(ou.len() == 1 && ou[0].value.value() == b"Authenticator Attestation")
}
pub(super) fn verify(
    ctx: &Context,
    object: &Value,
    data: &[u8],
    client: &[u8],
    key: &PublicKey,
    id: &[u8],
) -> Result<AttestationEvidence> {
    let statement = text_field(object, "attStmt")?;
    let map = statement.as_map().ok_or(Invalid::Attestation)?;
    let hash = Sha256::digest(client);
    let mut signed = data.to_vec();
    signed.extend(hash);
    let (format, kind, trust) = match text_field(object, "fmt")?.as_text() {
        Some("none") => {
            require(map.is_empty())?;
            ("none", "none", None)
        }
        Some("packed") => {
            let alg = algorithm(statement)?;
            let sig = bytes(statement, "sig")?;
            if text_field(statement, "x5c").is_ok() {
                require(map.len() == 3)?;
                let chain = certs(statement)?;
                let (cert, trust) = trusted(ctx, data, &chain, false)?;
                packed_subject(&cert)?;
                aaguid(&cert, data)?;
                certificate::verify(&cert, alg, &signed, sig)?;
                ("packed", "trusted", Some(trust))
            } else {
                require(map.len() == 2 && alg == key.algorithm())?;
                key.verify(&signed, sig)?;
                ("packed", "self", None)
            }
        }
        Some("fido-u2f") => {
            require(map.len() == 2 && data[37..53] == [0; 16])?;
            let chain = certs(statement)?;
            require(chain.len() == 1)?;
            let (cert, trust) = trusted(ctx, data, &chain, true)?;
            let PublicKey::Es256(key) = key else {
                return Err(Invalid::Attestation);
            };
            let mut message = vec![0];
            message.extend(&data[..32]);
            message.extend(hash);
            message.extend(id);
            message.extend(key.to_sec1_point(false).as_bytes());
            certificate::verify(&cert, -7, &message, bytes(statement, "sig")?)?;
            ("fido-u2f", "trusted", Some(trust))
        }
        Some("tpm") => {
            require(map.len() == 6 && text_field(statement, "ver")?.as_text() == Some("2.0"))?;
            let chain = certs(statement)?;
            let (cert, trust) = trusted(ctx, data, &chain, false)?;
            aaguid(&cert, data)?;
            tpm::verify(statement, key, &signed, &cert)?;
            ("tpm", "trusted", Some(trust))
        }
        _ => return Err(Invalid::Attestation),
    };
    ensure(
        ctx.attestation_policy != AttestationPolicy::RequiredTrusted || trust.is_some(),
        Invalid::AttestationPolicy,
    )?;
    Ok(AttestationEvidence {
        format,
        kind,
        aaguid: B64.encode(&data[37..53]),
        trust,
    })
}
mod tpm;

/// Untrusted lookup hint; register() independently matches the authenticated metadata.
pub fn hint(encoded: &str) -> Result<String> {
    let bytes = decode(encoded, 65536)?;
    let (object, used) = cbor(&bytes, 8)?;
    require(used == bytes.len())?;
    let data = text_field(&object, "authData")?
        .as_bytes()
        .ok_or(Invalid::Attestation)?;
    require(data.len() >= 53)?;
    if text_field(&object, "fmt")?.as_text() == Some("fido-u2f") {
        let chain = certs(text_field(&object, "attStmt")?)?;
        let cert = certificate::parse(&chain[0])?;
        Ok(sha1::Sha1::digest(
            cert.tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .as_bytes()
                .ok_or(Invalid::Attestation)?,
        )
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
    } else {
        Ok(B64.encode(&data[37..53]))
    }
}

fn require(ok: bool) -> Result<()> {
    ensure(ok, Invalid::Attestation)
}
