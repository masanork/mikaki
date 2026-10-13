use serde::Deserialize;
use serde_json::json;
use std::io::Read;
#[derive(Deserialize)]
struct Case {
    name: String,
    evidence: mikaki_identity::evidence::Evidence,
    trust: Vec<mikaki_identity::evidence::TrustedKey>,
    now: u64,
}
fn main() {
    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).unwrap();
    let cases: Vec<Case> = serde_json::from_str(&raw).unwrap();
    let mut results = vec![];
    for case in cases {
        let key_json = serde_json::to_string(&case.trust).unwrap();
        let trust = civ_kenmen::TrustSet::empty()
            .with_operator_json(&key_json)
            .unwrap();
        let evidence = &case.evidence;
        let input = civ_kenmen::KenmenInput {
            ef0002: &evidence.attributes,
            ef0003: Some(&evidence.signature),
            ef0004: None,
            auth: civ_kenmen::Auth::Pin,
        };
        let civ = civ_kenmen::verify(&input, &trust, case.now, civ_kenmen::Verifier::Consumer);
        let mikaki = mikaki_identity::evidence::verify(evidence, &case.trust, case.now);
        let (mikaki_status, age_available) = match mikaki {
            Ok(doc) => (
                "verified".to_string(),
                Some(
                    mikaki_identity::claim_profile::age_over(
                        &doc.attributes.birth_date,
                        case.now,
                        18,
                    )
                    .is_some(),
                ),
            ),
            Err(e) => (format!("{e:?}"), None),
        };
        results.push(json!({"case":case.name,"civ":civ.result,"mikaki":mikaki_status,"age_available":age_available}));
    }
    println!("{}", json!(results));
}
