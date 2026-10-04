//! Fixed-origin first-party native wallet profile; shared by runtime and device preflight.
use crate::issuance::PublicJwk;
use crate::{client_attestation::AttesterTrust, key_attestation::Trust, mdoc};
use serde::{
    Deserialize,
    de::{self, Deserializer, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Value, json};
use std::fmt;
pub const ROOT: &str = "https://auth.mikaki.org";
pub const ISSUER: &str = "https://auth.mikaki.org/identity/issuer";
pub const CALLBACK: &str = "https://app.mikaki.org/identity/issuance/callback";
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(json!(v)))
            }
            fn visit_none<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = a.next_element::<Strict>()? {
                    if values.len() >= 1024 {
                        return Err(de::Error::custom("array limit"));
                    }
                    values.push(v.0);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((k, v)) = a.next_entry::<String, Strict>()? {
                    if values.len() >= 256 || values.insert(k, v.0).is_some() {
                        return Err(de::Error::custom("duplicate or oversized object"));
                    }
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn strict_json(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > 128 * 1024 {
        return Err("invalid_response".into());
    }
    serde_json::from_slice::<Strict>(bytes)
        .map(|v| v.0)
        .map_err(|_| "invalid_response".into())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub client_id: String,
    pub client_trust: Vec<AttesterTrust>,
    pub key_trust: Trust,
    pub credential_trust: crate::credential_receipt::CredentialTrust,
}
impl Configuration {
    pub fn parse(raw: &str, at: u64) -> Result<Self, String> {
        if raw.len() > 49152 {
            return Err("wallet_configuration_invalid".into());
        }
        let cfg: Self = serde_json::from_value(strict_json(raw.as_bytes())?)
            .map_err(|_| "wallet_configuration_invalid")?;
        if cfg.client_id.is_empty()
            || cfg.client_id.len() > 256
            || cfg.client_trust.len() != 1
            || cfg.client_trust[0].issuer != format!("{ROOT}/identity/attester")
        {
            return Err("wallet_configuration_invalid".into());
        }
        crate::certificate::validate_attester_roots(&cfg.client_trust[0].trust_anchors)
            .map_err(|_| "wallet_configuration_invalid")?;
        cfg.key_trust
            .validate()
            .map_err(|_| "wallet_configuration_invalid")?;
        cfg.credential_trust
            .validate(at)
            .map_err(|_| "wallet_configuration_invalid")?;
        // Distinct purposes require separately provisioned authorities in this profile.
        let sd = &cfg.credential_trust.sd_jwt.trust_anchors;
        let mdoc = &cfg.credential_trust.mdoc.trust_anchors;
        if sd.iter().any(|r| mdoc.contains(r))
            || sd.iter().chain(mdoc).any(|r| {
                cfg.client_trust[0].trust_anchors.contains(r)
                    || cfg.key_trust.trust_anchors.contains(r)
            })
        {
            return Err("wallet_configuration_invalid".into());
        }
        Ok(cfg)
    }
}
fn contains(v: &Value, wanted: Value) -> bool {
    v.as_array()
        .is_some_and(|a| a.len() <= 16 && a.contains(&wanted))
}
pub fn validate_metadata(
    metadata: &Value,
    oauth: &Value,
    configuration: &str,
) -> Result<(), String> {
    let c = &metadata["credential_configurations_supported"][configuration];
    if metadata["credential_issuer"] != ISSUER
        || metadata["credential_endpoint"] != format!("{ISSUER}/credential")
        || metadata["nonce_endpoint"] != format!("{ISSUER}/nonce")
        || metadata
            .get("authorization_servers")
            .is_some_and(|v| v != &json!([ISSUER]))
        || oauth["issuer"] != ISSUER
        || oauth["token_endpoint"] != format!("{ISSUER}/token")
        || oauth["jwks_uri"] != format!("{ISSUER}/jwks")
        || oauth["authorization_endpoint"] != format!("{ISSUER}/authorize")
        || oauth["pushed_authorization_request_endpoint"] != format!("{ISSUER}/par")
        || oauth["require_pushed_authorization_requests"] != true
        || oauth["authorization_response_iss_parameter_supported"] != true
        || oauth["pre-authorized_grant_anonymous_access_supported"] != false
        || !contains(
            &oauth["token_endpoint_auth_methods_supported"],
            json!("attest_jwt_client_auth"),
        )
        || !contains(&oauth["grant_types_supported"], json!("authorization_code"))
        || !contains(&oauth["response_types_supported"], json!("code"))
        || !contains(&oauth["code_challenge_methods_supported"], json!("S256"))
        || !contains(&oauth["dpop_signing_alg_values_supported"], json!("ES256"))
        || !contains(
            &oauth["client_attestation_signing_alg_values_supported"],
            json!("ES256"),
        )
        || !contains(
            &oauth["client_attestation_pop_signing_alg_values_supported"],
            json!("ES256"),
        )
        || c["scope"] != configuration
        || !contains(
            &c["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"],
            json!("ES256"),
        )
        || !c["proof_types_supported"]["jwt"]["key_attestations_required"].is_object()
    {
        return Err("invalid_metadata".into());
    }
    let valid = match configuration {
        "linked_document" => {
            contains(&c["cryptographic_binding_methods_supported"], json!("jwk"))
                && c["format"] == "dc+sd-jwt"
                && c["vct"] == format!("{ISSUER}/types/linked-document")
                && contains(
                    &c["credential_signing_alg_values_supported"],
                    json!("ES256"),
                )
        }
        "linked_document_mdoc" => {
            contains(
                &c["cryptographic_binding_methods_supported"],
                json!("cose_key"),
            ) && c["format"] == "mso_mdoc"
                && c["doctype"] == mdoc::DOCTYPE
                && contains(&c["credential_signing_alg_values_supported"], json!(-7))
        }
        _ => false,
    };
    if !valid {
        return Err("invalid_metadata".into());
    }
    Ok(())
}

pub fn issuer_key(jwks: &Value) -> Result<(PublicJwk, String), String> {
    let keys = jwks["keys"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("invalid_issuer_key")?;
    let k = &keys[0];
    if k["alg"] != "ES256" || k["use"] != "sig" || k.get("d").is_some() {
        return Err("invalid_issuer_key".into());
    }
    let key = PublicJwk {
        kty: k["kty"].as_str().ok_or("invalid_issuer_key")?.into(),
        crv: k["crv"].as_str().ok_or("invalid_issuer_key")?.into(),
        x: k["x"].as_str().ok_or("invalid_issuer_key")?.into(),
        y: k["y"].as_str().ok_or("invalid_issuer_key")?.into(),
    };
    key.verifying_key().map_err(str::to_string)?;
    let kid = k["kid"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .ok_or("invalid_issuer_key")?
        .to_owned();
    Ok((key, kid))
}
