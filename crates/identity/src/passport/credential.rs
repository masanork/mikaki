//! Mikaki-issued DG1 authenticity attestation, not a government DTC or travel entitlement.
use super::VerifiedDg1;
use crate::{
    credential_certificate::{self, Purpose, SigningTrust},
    issuance::{self, PublicJwk},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
pub const CONFIGURATION: &str = "passport_dg1";
pub const FIELDS: [&str; 6] = [
    "name_mrz",
    "issuing_state",
    "nationality",
    "birth_date_mrz",
    "expiry_date_mrz",
    "sex_mrz",
];
pub fn vct(issuer: &str) -> String {
    format!("{issuer}/types/passport-dg1")
}

#[allow(clippy::too_many_arguments)]
pub fn issue(
    key: &issuance::IssuerSigningKey,
    kid: &str,
    issuer: &str,
    holder: &PublicJwk,
    document: &VerifiedDg1,
    now: u64,
    deadline: u64,
    salts: &[[u8; 16]],
    trust: Option<&SigningTrust>,
) -> Result<(String, u64), &'static str> {
    if document.report().checked_at != Some(now)
        || salts.len() != FIELDS.len()
        || kid.is_empty()
        || kid.len() > 128
    {
        return Err("passport_revalidation_required");
    }
    holder.verifying_key()?;
    let mut end = now
        .checked_add(300)
        .ok_or("invalid_validity")?
        .min(deadline)
        .min(document.evidence_valid_until());
    let mut header = json!({"typ":"dc+sd-jwt","alg":"ES256","kid":kid});
    if let Some(trust) = trust {
        let (chain, until) = credential_certificate::verify(
            trust,
            &PublicJwk::from_key(key.verifying_key()),
            Purpose::SdJwt,
            now,
        )?;
        end = end.min(until);
        header["x5c"] = json!(chain.iter().map(|c| STANDARD.encode(c)).collect::<Vec<_>>());
    }
    if end <= now {
        return Err("invalid_validity");
    }
    let fields = serde_json::to_value(document.claims()).map_err(|_| "invalid_passport_claims")?;
    let mut disclosures = Vec::new();
    let mut hashes = Vec::new();
    for (field, salt) in FIELDS.iter().zip(salts) {
        let value = fields.get(field).ok_or("invalid_passport_claims")?;
        let disclosure = B64.encode(
            serde_json::to_vec(&json!([B64.encode(salt), field, value]))
                .map_err(|_| "invalid_passport_claims")?,
        );
        hashes.push(B64.encode(Sha256::digest(disclosure.as_bytes())));
        disclosures.push(disclosure);
    }
    let token = issuance::sign_jwt(
        key,
        header,
        json!({"iss":issuer,"iat":now,"exp":end,"vct":vct(issuer),"cnf":{"jwk":holder},"_sd_alg":"sha-256","_sd":hashes,"document_type":"passport","evidence":{"assurance":"issuer_authenticated_dg1","checked_data_groups":[1],"verified_at":now,"evidence_valid_until":document.evidence_valid_until(),"document_validity_verified":false,"live_possession_verified":false,"government_credential":false}}),
    )?;
    Ok((format!("{token}~{}~", disclosures.join("~")), end))
}
pub(crate) fn validate_claims(claims: &Value) -> Result<(), &'static str> {
    let e = &claims["evidence"];
    let allowed = [
        "iss",
        "iat",
        "exp",
        "vct",
        "cnf",
        "_sd_alg",
        "_sd",
        "document_type",
        "evidence",
    ];
    if claims.as_object().is_none_or(|m| {
        m.keys()
            .any(|k| !allowed.contains(&k.as_str()) && !FIELDS.contains(&k.as_str()))
    }) || claims["_sd"]
        .as_array()
        .is_none_or(|a| a.len() != FIELDS.len())
    {
        return Err("invalid_credential");
    }
    if claims["document_type"] != "passport"
        || e.as_object().is_none_or(|m| m.len() != 7)
        || e["assurance"] != "issuer_authenticated_dg1"
        || e["checked_data_groups"] != json!([1])
        || e["verified_at"] != claims["iat"]
        || e["document_validity_verified"] != false
        || e["live_possession_verified"] != false
        || e["government_credential"] != false
        || e["evidence_valid_until"]
            .as_u64()
            .is_none_or(|end| claims["exp"].as_u64().is_none_or(|exp| exp > end))
        || FIELDS.iter().any(|f| {
            claims
                .get(f)
                .and_then(Value::as_str)
                .is_none_or(|s| s.is_empty() || s.len() > 80)
        })
        || ["birth_date_mrz", "expiry_date_mrz"]
            .iter()
            .any(|f| !super::mrz::date(claims[f].as_str().unwrap_or("").as_bytes()))
        || !["M", "F", "<"].contains(&claims["sex_mrz"].as_str().unwrap_or(""))
        || ["issuing_state", "nationality"].iter().any(|f| {
            let code = claims[f].as_str().unwrap_or("");
            code.len() != 3 || !code.bytes().all(|b| b.is_ascii_uppercase() || b == b'<')
        })
        || claims["name_mrz"]
            .as_str()
            .is_none_or(|s| s.len() > 39 || !s.bytes().all(|b| b.is_ascii_uppercase() || b == b' '))
    {
        return Err("invalid_credential");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presentation::{self, VerifierRegistration};
    use p256::ecdsa::{Signature, SigningKey, signature::Verifier};
    const ISSUER: &str = "https://issuer.example/identity/issuer";
    fn keys() -> (SigningKey, SigningKey) {
        (
            SigningKey::from_slice(&[3; 32]).unwrap(),
            SigningKey::from_slice(&[7; 32]).unwrap(),
        )
    }
    #[test]
    fn independently_authenticated_dg1_issues_holder_bound_six_field_credential_and_selective_vp() {
        let verified = super::super::authentication::test_verified_fixture();
        let now = verified.report().checked_at.unwrap();
        let (issuer, holder) = keys();
        let holder_jwk = PublicJwk::from_key(holder.verifying_key());
        let (credential, end) = issue(
            &issuer,
            "issuer",
            ISSUER,
            &holder_jwk,
            &verified,
            now,
            now + 100,
            &[[1; 16]; 6],
            None,
        )
        .unwrap();
        assert_eq!(end, now + 100);
        let receipt = issuance::verify_receipt(
            &credential,
            &PublicJwk::from_key(issuer.verifying_key()),
            "issuer",
            &holder_jwk,
            ISSUER,
            now,
        )
        .unwrap();
        assert_eq!(receipt["birth_date_mrz"], "690806");
        assert_eq!(receipt["evidence"]["document_validity_verified"], false);
        for field in [
            "birthdate",
            "address",
            "document_number",
            "personal_number",
            "age_over_18",
        ] {
            assert!(receipt.get(field).is_none());
        }
        let verifier = SigningKey::from_slice(&[9; 32]).unwrap();
        let registry = VerifierRegistration {
            client_id: "verifier".into(),
            name: "Verifier".into(),
            response_uri: "https://verifier.example/response".into(),
            kid: "verifier".into(),
            jwk: PublicJwk::from_key(verifier.verifying_key()),
            certificate_trust: None,
            response_encryption: None,
            profile: presentation::Profile::Oid4vpFinal,
        };
        let claims = json!({"iss":"verifier","aud":"https://self-issued.me/v2","client_id":"verifier","response_type":"vp_token","response_mode":"direct_post","response_uri":registry.response_uri,"nonce":"N".repeat(43),"state":"S".repeat(43),"iat":now,"exp":now+60,"dcql_query":{"credentials":[{"id":"passport","format":"dc+sd-jwt","meta":{"vct_values":[vct(ISSUER)]},"claims":[{"path":["name_mrz"]}]}]}});
        let signed = issuance::sign_jwt(
            &verifier,
            json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"verifier"}),
            claims,
        )
        .unwrap();
        let request =
            presentation::verify_request(&signed, &[registry], &vct(ISSUER), now).unwrap();
        let (selected, values) = presentation::select_disclosures(&credential, &request).unwrap();
        assert_eq!(values, json!({"name_mrz":"ERIKSSON ANNA MARIA"}));
        assert_eq!(selected.split('~').filter(|v| !v.is_empty()).count(), 2);
        let vp = presentation::present(&holder, &selected, &request, now).unwrap();
        let kb = vp.rsplit('~').next().unwrap();
        let (input, sig) = kb.rsplit_once('.').unwrap();
        holder
            .verifying_key()
            .verify(
                input.as_bytes(),
                &Signature::from_slice(&B64.decode(sig).unwrap()).unwrap(),
            )
            .unwrap();
        let kb_claims: Value =
            serde_json::from_slice(&B64.decode(input.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!(
            kb_claims["sd_hash"],
            B64.encode(Sha256::digest(selected.as_bytes()))
        );
        assert_eq!(kb_claims["nonce"], "N".repeat(43));
        assert_eq!(kb_claims["aud"], "verifier");
        assert!(
            issuance::verify_receipt(
                &credential,
                &PublicJwk::from_key(issuer.verifying_key()),
                "issuer",
                &PublicJwk::from_key(verifier.verifying_key()),
                ISSUER,
                now
            )
            .is_err()
        );
        assert!(
            issuance::verify_receipt(
                &credential,
                &PublicJwk::from_key(issuer.verifying_key()),
                "issuer",
                &holder_jwk,
                ISSUER,
                end
            )
            .is_err()
        );
    }
    #[test]
    fn profile_and_validity_cannot_invent_full_dates_or_upgrade_document_authority() {
        let mut verified = super::super::authentication::test_verified_fixture();
        let now = verified.report().checked_at.unwrap();
        let (issuer, holder) = keys();
        let holder_jwk = PublicJwk::from_key(holder.verifying_key());
        verified.report.valid_until = Some(now + 20);
        let (credential, end) = issue(
            &issuer,
            "issuer",
            ISSUER,
            &holder_jwk,
            &verified,
            now,
            now + 300,
            &[[1; 16]; 6],
            None,
        )
        .unwrap();
        assert_eq!(end, now + 20);
        assert!(
            issue(
                &issuer,
                "issuer",
                ISSUER,
                &holder_jwk,
                &verified,
                now + 1,
                now + 300,
                &[[1; 16]; 6],
                None
            )
            .is_err()
        );
        let mut pieces = credential.split('~');
        let jwt = pieces.next().unwrap();
        let header: Value =
            serde_json::from_slice(&B64.decode(jwt.split('.').next().unwrap()).unwrap()).unwrap();
        let original: Value =
            serde_json::from_slice(&B64.decode(jwt.split('.').nth(1).unwrap()).unwrap()).unwrap();
        let disclosures = pieces.collect::<Vec<_>>().join("~");
        for (field, value) in [
            ("vct", json!(format!("{ISSUER}/types/linked-document"))),
            ("birthdate", json!("1969-08-06")),
            ("document_number", json!("L898902C")),
            ("evidence", {
                let mut e = original["evidence"].clone();
                e["document_validity_verified"] = json!(true);
                e
            }),
            ("evidence", {
                let mut e = original["evidence"].clone();
                e["document_number"] = json!("L898902C");
                e
            }),
        ] {
            let mut claims = original.clone();
            claims[field] = value;
            let changed = format!(
                "{}~{disclosures}",
                issuance::sign_jwt(&issuer, header.clone(), claims).unwrap()
            );
            assert!(
                issuance::verify_receipt(
                    &changed,
                    &PublicJwk::from_key(issuer.verifying_key()),
                    "issuer",
                    &holder_jwk,
                    ISSUER,
                    now
                )
                .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn inventory_selects_actual_passport_vct_without_cross_matching_linked_document() {
        use crate::{
            credential_receipt::CredentialTrust, evidence::VerifiedDocument, issuance::Validity,
        };
        let verified = super::super::authentication::test_verified_fixture();
        let now = verified.report().checked_at.unwrap();
        let issuer = SigningKey::from_slice(&[4; 32]).unwrap();
        let holder = SigningKey::from_slice(&[7; 32]).unwrap();
        let public = PublicJwk::from_key(holder.verifying_key());
        let roots = CredentialTrust {
            sd_jwt: crate::credential_receipt::CredentialRoots {
                trust_anchors: vec![
                    STANDARD.encode(include_bytes!("../../tests/fixtures/credential/sd-ca.der")),
                ],
                revocation: None,
            },
            mdoc: crate::credential_receipt::CredentialRoots {
                trust_anchors: vec![STANDARD.encode(include_bytes!(
                    "../../tests/fixtures/credential/mdoc-ca.der"
                ))],
                revocation: None,
            },
        };
        let trust = SigningTrust {
            chain: vec![STANDARD.encode(include_bytes!(
                "../../tests/fixtures/credential/sd-signer.der"
            ))],
            trust_anchors: roots.sd_jwt.trust_anchors.clone(),
            revocation: None,
        };
        let (passport, _) = issue(
            &issuer,
            "issuer",
            ISSUER,
            &public,
            &verified,
            now,
            now + 300,
            &[[1; 16]; 6],
            Some(&trust),
        )
        .unwrap();
        let legacy: VerifiedDocument = serde_json::from_value(json!({"attributes":{"name":"Fixture","address":"Private","birth_date":"1990-02-28","gender":"1","verification":"issuer_signed_static_data","document_type":"my_number_card","expiry_date":null,"backend_verifiable":true},"trusted_key_id":"fixture","verified_at":now,"assurance":"issuer_signed_static_data","attributes_source":"input_support_ef"})).unwrap();
        let linked = issuance::issue_with_certificate_trust(
            &issuer,
            "issuer",
            ISSUER,
            &public,
            &legacy,
            Validity::new(&legacy, now, now + 300).unwrap(),
            &[[1; 16]; 4],
            &trust,
        )
        .unwrap();
        let inventory = [linked, passport]
            .into_iter()
            .map(|credential| {
                presentation::inventory::VerifiedCredential::verify(
                    credential,
                    "dc+sd-jwt",
                    PublicJwk::from_key(issuer.verifying_key()),
                    public.clone(),
                    ISSUER,
                    "issuer",
                    roots.clone(),
                    now,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let verifier = SigningKey::from_slice(&[9; 32]).unwrap();
        let registry = VerifierRegistration {
            client_id: "verifier".into(),
            name: "Verifier".into(),
            response_uri: "https://verifier.example/response".into(),
            kid: "verifier".into(),
            jwk: PublicJwk::from_key(verifier.verifying_key()),
            certificate_trust: None,
            response_encryption: None,
            profile: presentation::Profile::Oid4vpFinal,
        };
        let base = format!("{ISSUER}/types/linked-document");
        let query = |id: &str, vct: &str, field: &str| json!({"id":id,"format":"dc+sd-jwt","meta":{"vct_values":[vct]},"claims":[{"path":[field]}]});
        let request = |queries: Value| {
            let signed = issuance::sign_jwt(&verifier, json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"verifier"}), json!({"iss":"verifier","aud":"https://self-issued.me/v2","client_id":"verifier","response_type":"vp_token","response_mode":"direct_post","response_uri":registry.response_uri,"nonce":"N".repeat(43),"state":"S".repeat(43),"iat":now,"exp":now+60,"dcql_query":{"credentials":queries}})).unwrap();
            presentation::inventory::verify_request(
                &signed,
                std::slice::from_ref(&registry),
                &base,
                now,
            )
            .unwrap()
        };
        let mixed = request(json!([
            query("linked", &base, "name"),
            query("passport", &vct(ISSUER), "name_mrz")
        ]));
        let selected = mixed.select(&inventory, now).unwrap();
        assert_eq!(selected.selected().len(), 2);
        assert_eq!(
            selected.selected()[0].values(now).unwrap(),
            json!({"name":"Fixture"})
        );
        assert_eq!(
            selected.selected()[1].values(now).unwrap(),
            json!({"name_mrz":"ERIKSSON ANNA MARIA"})
        );
        assert!(mixed.select(&inventory[..1], now).is_err());
        assert!(mixed.select(&inventory[1..], now).is_err());
        let wrong_type = request(json!([query("wrong", &base, "name_mrz")]));
        assert!(wrong_type.select(&inventory, now).is_err());
    }
}
