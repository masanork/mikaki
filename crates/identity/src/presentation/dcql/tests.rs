use super::select_available;
use crate::presentation::Dcql;
use serde_json::{Value, json};

const VCT: &str = "urn:example:linked-document";

fn dcql(credentials: usize, sets: Option<Value>) -> Dcql {
    let credentials: Vec<_> = (0..credentials)
        .map(|index| {
            json!({
                "id": format!("q{index}"),
                "format": "dc+sd-jwt",
                "meta": {"vct_values": [VCT]},
                "claims": [{"path": ["name"]}]
            })
        })
        .collect();
    let mut value = json!({"credentials": credentials});
    if let Some(sets) = sets {
        value["credential_sets"] = sets;
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn every_availability_mask_selects_the_first_complete_option_in_signed_order() {
    let query = dcql(
        8,
        Some(json!([
            {"options": [["q7", "q1"], ["q6", "q4"], ["q0", "q2", "q3", "q5"]]},
            {"options": [["q4"]], "required": false}
        ])),
    );
    for mask in 0u16..256 {
        let available: Vec<_> = (0..8).map(|index| mask & (1 << index) != 0).collect();
        // Independent bit masks describe the three whole credential combinations.
        let expected = if mask & 0b1000_0010 == 0b1000_0010 {
            Ok(vec![7, 1])
        } else if mask & 0b0101_0000 == 0b0101_0000 {
            Ok(vec![6, 4])
        } else if mask & 0b0010_1101 == 0b0010_1101 {
            Ok(vec![0, 2, 3, 5])
        } else {
            Err("credential_query_unsatisfied")
        };
        assert_eq!(
            select_available(&query, VCT, Some(&available)),
            expected,
            "availability {mask:08b}"
        );
    }
}

#[test]
fn required_sets_keep_first_seen_order_without_duplicates_or_optional_disclosure() {
    let query = dcql(
        8,
        Some(json!([
            {"options": [["q5", "q2"], ["q0"]]},
            {"options": [["q2", "q7"], ["q6"]]},
            {"options": [["q1"]], "required": false}
        ])),
    );
    assert_eq!(select_available(&query, VCT, None), Ok(vec![5, 2, 7]));
    let mut available = [true; 8];
    available[2] = false;
    assert_eq!(
        select_available(&query, VCT, Some(&available)),
        Ok(vec![0, 6])
    );
    available[6] = false;
    assert_eq!(
        select_available(&query, VCT, Some(&available)),
        Err("credential_query_unsatisfied")
    );
}

#[test]
fn optional_only_queries_retain_the_existing_first_complete_option_fallback() {
    let query = dcql(
        3,
        Some(json!([
            {"options": [["q1", "q2"], ["q0"]], "required": false},
            {"options": [["q2"]], "required": false}
        ])),
    );
    assert_eq!(select_available(&query, VCT, None), Ok(vec![1, 2]));
    assert_eq!(
        select_available(&query, VCT, Some(&[true, false, true])),
        Ok(vec![0])
    );
    assert_eq!(
        select_available(&query, VCT, Some(&[false, false, true])),
        Ok(vec![2])
    );
    assert_eq!(
        select_available(&query, VCT, Some(&[false; 3])),
        Err("credential_query_unsatisfied")
    );
}

#[test]
fn invalid_unselected_queries_and_options_precede_unsatisfied_credential_errors() {
    let mut value = serde_json::to_value(dcql(
        2,
        Some(json!([
            {"options": [["q0"]]},
            {"options": [["q1"]], "required": false}
        ])),
    ))
    .unwrap();
    value["credentials"][1]["meta"] = json!({"vct_values": ["urn:unavailable"]});
    value["credentials"][1]["claims"] = json!([{"path": ["unknown"]}]);
    let valid: Dcql = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        select_available(&valid, VCT, Some(&[false; 2])),
        Err("credential_query_unsatisfied")
    );
    for (field, replacement, error) in [
        ("id", json!("q0"), "unsupported_query"),
        ("format", json!("unsupported"), "unsupported_query"),
        ("meta", json!({"vct_values": []}), "unsupported_query"),
        ("meta", json!({"vct_values": [VCT]}), "unsupported_query"),
        ("claims", json!([{"path": []}]), "unsupported_query"),
        (
            "claims",
            json!([{"path": ["unknown"]}, {"path": ["unknown"]}]),
            "unsupported_query",
        ),
        ("trusted_authorities", json!([]), "invalid_authority_query"),
    ] {
        let mut invalid = value.clone();
        invalid["credentials"][1][field] = replacement;
        let query = serde_json::from_value(invalid).unwrap();
        assert_eq!(
            select_available(&query, VCT, Some(&[false; 2])),
            Err(error),
            "invalid unselected {field}"
        );
    }
    for options in [json!([["unknown"]]), json!([["q1", "q1"]]), json!([[]])] {
        let mut invalid = value.clone();
        invalid["credential_sets"][1]["options"] = options;
        let query = serde_json::from_value(invalid).unwrap();
        assert_eq!(
            select_available(&query, VCT, Some(&[false; 2])),
            Err("unsupported_query")
        );
    }
}

#[test]
fn bounded_query_graph_accepts_its_limits_and_rejects_mismatched_availability() {
    let names: Vec<_> = (0..8).map(|index| format!("q{index}")).collect();
    let options = vec![names; 8];
    let sets = vec![json!({"options": options}); 8];
    let query = dcql(8, Some(json!(sets)));
    assert_eq!(select_available(&query, VCT, None), Ok((0..8).collect()));
    for length in [0, 7, 9] {
        assert_eq!(
            select_available(&query, VCT, Some(&vec![true; length])),
            Err("unsupported_query")
        );
    }
    for count in [0, 9] {
        assert_eq!(
            select_available(&dcql(count, None), VCT, None),
            Err("unsupported_query")
        );
    }
    let all = dcql(2, None);
    assert_eq!(select_available(&all, VCT, None), Ok(vec![0, 1]));
    assert_eq!(
        select_available(&all, VCT, Some(&[true, false])),
        Err("credential_query_unsatisfied")
    );
}
