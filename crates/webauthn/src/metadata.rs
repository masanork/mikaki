//! Offline MDS verification. Transport supplies bounded BLOB/CRLs and a pinned root SPKI.
use super::*;
use base64::engine::general_purpose::STANDARD;
use x509_cert::{
    der::{Decode, Encode},
    ext::pkix::{
        CrlDistributionPoints, KeyUsage,
        name::{DistributionPointName, GeneralName},
    },
};
#[derive(Deserialize)]
pub struct MdsInput {
    pub jwt: String,
    pub anchor_spki: String,
    pub now: u64,
    pub crls: Vec<String>,
}
#[derive(Serialize)]
pub struct VerifiedMds {
    pub number: u64,
    pub issued_at: u64,
    pub next_update: Option<u64>,
    pub entries: Vec<Metadata>,
}
#[derive(Deserialize)]
struct Header {
    alg: String,
    x5c: Vec<String>,
    x5u: Option<String>,
    iat: u64,
    crit: Option<Vec<String>>,
}
fn header(jwt: &str) -> Result<(Header, &str, &str)> {
    ensure(jwt.len() <= 4_194_304, Invalid::Limit)?;
    let (signed, sig) = jwt.rsplit_once('.').ok_or(Invalid::Metadata)?;
    let (h, _) = signed.split_once('.').ok_or(Invalid::Metadata)?;
    let bytes = decode(h, 131072)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Invalid::Metadata)?;
    strict_json(text, 131072, 8)?;
    Ok((
        serde_json::from_str(text).map_err(|_| Invalid::Metadata)?,
        signed,
        sig,
    ))
}
fn chain(header: &Header) -> Result<Vec<x509_cert::Certificate>> {
    require(!header.x5c.is_empty() && header.x5c.len() <= 6)?;
    header
        .x5c
        .iter()
        .map(|s| {
            require(s.len() <= 22000)?;
            certificate::parse(&STANDARD.decode(s).map_err(|_| Invalid::Metadata)?)
        })
        .collect()
}
/// URLs are untrusted hints. The transport must enforce an independent destination allow-list.
pub fn mds_crl_urls(jwt: &str) -> Result<Vec<String>> {
    let (h, _, _) = header(jwt)?;
    require(h.x5u.is_none())?;
    let mut urls = vec![];
    for cert in chain(&h)? {
        let (_, points) = cert
            .tbs_certificate()
            .get_extension::<CrlDistributionPoints>()
            .map_err(|_| Invalid::Metadata)?
            .ok_or(Invalid::Metadata)?;
        for p in points.0 {
            require(p.reasons.is_none() && p.crl_issuer.is_none())?;
            let Some(DistributionPointName::FullName(names)) = p.distribution_point else {
                return Err(Invalid::Metadata);
            };
            for n in names {
                if let GeneralName::UniformResourceIdentifier(uri) = n {
                    urls.push(uri.to_string());
                }
            }
        }
    }
    require(!urls.is_empty() && urls.len() <= 12)?;
    Ok(urls)
}
pub fn verify_mds(input: MdsInput) -> Result<VerifiedMds> {
    let (h, signed, sig) = header(&input.jwt)?;
    require(h.crit.as_ref().is_none_or(Vec::is_empty) && h.alg == "ES256" && h.x5u.is_none())?;
    let certs = chain(&h)?;
    let anchor =
        x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&decode(&input.anchor_spki, 2048)?)
            .map_err(|_| Invalid::Metadata)?;
    ensure(
        !input.crls.is_empty() && input.crls.len() <= 12,
        Invalid::Crl,
    )?;
    let crls = input
        .crls
        .iter()
        .map(|s| {
            x509_cert::crl::CertificateList::from_der(&decode(s, 1048576)?)
                .map_err(|_| Invalid::Crl)
        })
        .collect::<Result<Vec<_>>>()?;
    for (i, cert) in certs.iter().enumerate() {
        certificate::valid(
            cert,
            input.now,
            if i == 0 { None } else { Some(i - 1) },
            false,
        )?;
        require(!certs[..i].contains(cert))?;
        let parent = certs.get(i + 1);
        let spki = parent
            .map(|p| p.tbs_certificate().subject_public_key_info())
            .unwrap_or(&anchor);
        if let Some(parent) = parent {
            certificate::link(cert, parent)?;
            require(
                parent
                    .tbs_certificate()
                    .get_extension::<KeyUsage>()
                    .map_err(|_| Invalid::Metadata)?
                    .is_none_or(|(_, u)| u.crl_sign()),
            )?;
        } else {
            require(cert.tbs_certificate().signature() == cert.signature_algorithm())?;
            certificate::signature_spki(
                spki,
                cert.signature_algorithm(),
                &cert
                    .tbs_certificate()
                    .to_der()
                    .map_err(|_| Invalid::Metadata)?,
                cert.signature().as_bytes().ok_or(Invalid::Metadata)?,
            )?;
        }
        let mut found = false;
        for crl in &crls {
            let t = &crl.tbs_cert_list;
            if &t.issuer != cert.tbs_certificate().issuer() {
                continue;
            }
            ensure(t.signature == crl.signature_algorithm, Invalid::Crl)?;
            ensure(
                t.this_update.to_unix_duration().as_secs() <= input.now
                    && t.next_update
                        .is_some_and(|n| input.now <= n.to_unix_duration().as_secs()),
                Invalid::CrlExpired,
            )?;
            // Full, direct CRLs only; delta/indirect/reason-scoped CRLs are unsupported.
            ensure(
                t.crl_extensions.as_ref().is_none_or(|e| {
                    e.iter().all(|x| {
                        !x.critical
                            && !matches!(x.extn_id.to_string().as_str(), "2.5.29.27" | "2.5.29.28")
                    })
                }),
                Invalid::Crl,
            )?;
            certificate::signature_spki(
                spki,
                &crl.signature_algorithm,
                &t.to_der().map_err(|_| Invalid::Metadata)?,
                crl.signature.as_bytes().ok_or(Invalid::Metadata)?,
            )?;
            ensure(
                t.revoked_certificates.as_ref().is_none_or(|rs| {
                    rs.iter()
                        .all(|r| &r.serial_number != cert.tbs_certificate().serial_number())
                }),
                Invalid::Revoked,
            )?;
            found = true;
        }
        ensure(found, Invalid::Crl)?;
    }
    let sig = Signature::from_slice(&decode(sig, 64)?).map_err(|_| Invalid::Metadata)?;
    certificate::verify(&certs[0], -7, signed.as_bytes(), sig.to_der().as_bytes())?;
    let (_, payload) = signed.split_once('.').ok_or(Invalid::Metadata)?;
    let bytes = decode(payload, 3_145_728)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Invalid::Metadata)?;
    strict_json(text, 3_145_728, 32)?;
    let payload: serde_json::Value = serde_json::from_str(text).map_err(|_| Invalid::Metadata)?;
    let next_update = match payload.get("nextUpdate") {
        None => None,
        Some(value) => Some(
            parse_date(value.as_str().ok_or(Invalid::Metadata)?)?
                .unix_duration()
                .as_secs(),
        ),
    };
    let number = payload["no"].as_u64().ok_or(Invalid::Metadata)?;
    let list = payload["entries"].as_array().ok_or(Invalid::Metadata)?;
    require(list.len() <= 10000)?;
    let mut entries = vec![];
    for e in list {
        let Some(m) = e.get("metadataStatement") else {
            return Err(Invalid::Metadata);
        };
        let raw_key_ids = match e.get("attestationCertificateKeyIdentifiers") {
            None => vec![],
            Some(value) => {
                let ids = value.as_array().ok_or(Invalid::Metadata)?;
                require(!ids.is_empty())?;
                ids.clone()
            }
        };
        let key_ids = raw_key_ids
            .iter()
            .map(|v| {
                let id = v.as_str().ok_or(Invalid::Metadata)?;
                require(
                    id.len() == 40
                        && id
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                )?;
                Ok(id.to_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        let id = match e.get("aaguid") {
            None => None,
            Some(value) => Some(value.as_str().ok_or(Invalid::Metadata)?),
        };
        if id.is_none() && key_ids.is_empty() {
            // UAF-only AAID entries do not identify a WebAuthn authenticator.
            continue;
        }
        require(id.is_none() || key_ids.is_empty())?;
        let aaguid = if let Some(id) = id {
            require(m["aaguid"].as_str() == Some(id))?;
            require(
                id.len() == 36
                    && id.as_bytes()[8] == b'-'
                    && id.as_bytes()[13] == b'-'
                    && id.as_bytes()[18] == b'-'
                    && id.as_bytes()[23] == b'-',
            )?;
            let hex = id.replace('-', "");
            require(hex.len() == 32 && hex.is_ascii())?;
            B64.encode(
                (0..32)
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| Invalid::Metadata))
                    .collect::<Result<Vec<_>>>()?,
            )
        } else {
            require(e.get("aaid").is_none())?;
            String::new()
        };
        let roots = m["attestationRootCertificates"]
            .as_array()
            .ok_or(Invalid::Metadata)?
            .iter()
            .map(|s| {
                let der = STANDARD
                    .decode(s.as_str().ok_or(Invalid::Metadata)?)
                    .map_err(|_| Invalid::Metadata)?;
                certificate::parse(&der)?;
                Ok(B64.encode(der))
            })
            .collect::<Result<Vec<_>>>()?;
        let types = m["attestationTypes"]
            .as_array()
            .ok_or(Invalid::Metadata)?
            .iter()
            .map(|t| t.as_str().map(str::to_owned).ok_or(Invalid::Metadata))
            .collect::<Result<Vec<_>>>()?;
        let reports = e["statusReports"].as_array().ok_or(Invalid::Metadata)?;
        require(!reports.is_empty() && reports.len() <= 64)?;
        let status_reports = reports
            .iter()
            .map(|r| {
                let mut fields = r.as_object().ok_or(Invalid::Metadata)?.clone();
                require(fields.values().all(|v| !v.is_null()))?;
                let status = fields
                    .remove("status")
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .ok_or(Invalid::Metadata)?;
                require(!status.is_empty())?;
                Ok(StatusReport {
                    status,
                    details: fields.into_iter().collect(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let allowed = reports.iter().all(|r| {
            r["status"].as_str().is_some_and(|s| {
                !matches!(
                    s,
                    "USER_VERIFICATION_BYPASS"
                        | "ATTESTATION_KEY_COMPROMISE"
                        | "USER_KEY_REMOTE_COMPROMISE"
                        | "USER_KEY_PHYSICAL_COMPROMISE"
                        | "REVOKED"
                )
            })
        });
        let time_of_last_status_change = e["timeOfLastStatusChange"]
            .as_str()
            .ok_or(Invalid::Metadata)?
            .to_owned();
        let authenticator_version = match m.get("authenticatorVersion") {
            None => None,
            Some(v) => Some(
                u32::try_from(v.as_u64().ok_or(Invalid::Metadata)?)
                    .map_err(|_| Invalid::Metadata)?,
            ),
        };
        entries.push(Metadata {
            aaguid,
            key_ids,
            roots,
            types,
            allowed,
            authenticator_version,
            status_reports,
            time_of_last_status_change: Some(time_of_last_status_change),
        });
    }
    Ok(VerifiedMds {
        number,
        issued_at: h.iat,
        next_update,
        entries,
    })
}

fn parse_date(date: &str) -> Result<x509_cert::der::DateTime> {
    require(date.len() == 10 && date.is_ascii() && &date[4..5] == "-" && &date[7..8] == "-")?;
    x509_cert::der::DateTime::new(
        date[..4].parse().map_err(|_| Invalid::Metadata)?,
        date[5..7].parse().map_err(|_| Invalid::Metadata)?,
        date[8..].parse().map_err(|_| Invalid::Metadata)?,
        0,
        0,
        0,
    )
    .map_err(|_| Invalid::Metadata)
}

fn require(ok: bool) -> Result<()> {
    ensure(ok, Invalid::Metadata)
}
