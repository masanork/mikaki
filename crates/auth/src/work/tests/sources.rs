use super::*;
use serde_json::{Value, json};
fn source() -> Value {
    json!({"source_id":"personal","source_revision":1,"role":"personal","label":"Personal context","repo_name":"personal-repo",
 "commit":"a".repeat(40),"tree":"b".repeat(40),"files":[{"path":"writing.md","blob":"c".repeat(40),"mode":"100644","bytes":22,
 "sha256":Digest::from_bytes(Sha256::digest("結論から書く。\n".as_bytes()).into())}],"code":null})
}
fn read() -> SourceReadInput {
    serde_json::from_value(json!({"format_version":1,"source_id":"personal","source_revision":1,"access_revision":1,"paths":["writing.md"]})).unwrap()
}
fn reply() -> Value {
    json!({"format_version":1,"source_id":"personal","source_revision":1,"commit":"a".repeat(40),"tree":"b".repeat(40),
 "files":[{"path":"writing.md","blob":"c".repeat(40),"content":"結論から書く。\n"}]})
}
fn registered(v: Value) -> Result<RegisteredSource, Denied> {
    RegisteredSource::from_verified_git(serde_json::from_value(v).unwrap())
}
#[test]
fn opaque_copy_selection_requires_both_sha256_content_and_actual_git_blob_identity() {
    let s = registered(source()).unwrap();
    assert!(s.verify_reply(&read(), &reply().to_string()).is_ok());
    denied(
        s.verify_selection(&read(), &reply().to_string()),
        Denied::BindingMismatch,
    );
    let mut v = source();
    v["files"][0]["blob"] = json!("34b417333d03571a5b9bfeabfdd89a472817191d");
    let mut r = reply();
    r["files"][0]["blob"] = v["files"][0]["blob"].clone();
    let s = registered(v).unwrap();
    assert!(s.verify_selection(&read(), &r.to_string()).is_ok());
    r["files"][0]["content"] = json!("別の内容。\n");
    denied(
        s.verify_selection(&read(), &r.to_string()),
        Denied::BindingMismatch,
    );
}
#[test]
fn source_receipt_is_closed_bounded_metadata_without_owner_or_plaintext() {
    let s = registered(source()).unwrap();
    let body = s.authority_record().unwrap();
    assert!(!body.contains("結論から"));
    assert!(!body.contains("owner"));
    assert_eq!(
        RegisteredSource::restore_authority_record(&body)
            .unwrap()
            .authority_record()
            .unwrap(),
        body
    );
    for path in ["../wallet", ".git/config", "a//b", "a\\b", ""] {
        let mut v = source();
        v["files"][0]["path"] = json!(path);
        denied(registered(v), Denied::InvalidInput);
    }
    let mut v = source();
    v["files"][0]["mode"] = json!("120000");
    denied(registered(v), Denied::InvalidInput);
    let mut v = source();
    v["files"][0]["bytes"] = json!(16385);
    denied(registered(v), Denied::InvalidInput);
    let mut v = source();
    v["role"] = json!("code");
    denied(registered(v), Denied::InvalidInput);
    let mut v = source();
    v["owner"] = json!("foreign");
    assert!(serde_json::from_value::<SourceInput>(v).is_err());
    let mut v = json!({"format_version":1,"source_id":"personal","source_revision":1,"access_revision":1,"paths":["writing.md"]});
    v["repo_name"] = json!("other");
    assert!(serde_json::from_value::<SourceReadInput>(v).is_err());
}
#[test]
fn registered_selection_cannot_request_unregistered_paths_versions_or_code_blobs() {
    let s = registered(source()).unwrap();
    let i = read();
    let wire: Value = serde_json::from_str(&s.service_request(&i).unwrap()).unwrap();
    assert_eq!(wire["repo_name"], "personal-repo");
    assert!(wire.get("access_revision").is_none());
    let mut i = read();
    i.paths = vec!["unselected.md".into()];
    denied(s.service_request(&i), Denied::BindingMismatch);
    let mut i = read();
    i.paths = vec!["writing.md".into(); 2];
    denied(s.service_request(&i), Denied::InvalidInput);
    let mut i = read();
    i.source_revision = 2;
    denied(s.service_request(&i), Denied::InvalidInput);
    let mut i = read();
    i.access_revision = 0;
    denied(s.service_request(&i), Denied::InvalidInput);
    let mut v = source();
    v["role"] = json!("code");
    v["files"] = json!([]);
    v["code"] = json!({"commits":2,"history_digest":"d".repeat(64),"objects":6,"object_bytes":500,"head_files":1});
    denied(
        registered(v).unwrap().service_request(&read()),
        Denied::InvalidInput,
    );
}
#[test]
fn source_payload_is_rehashed_and_cannot_substitute_content_identity_or_schema() {
    let s = registered(source()).unwrap();
    let i = read();
    assert_eq!(
        s.verify_reply(&i, &reply().to_string()).unwrap()["files"][0]["content"],
        "結論から書く。\n"
    );
    for (key, value) in [
        ("commit", json!("f".repeat(40))),
        ("tree", json!("f".repeat(40))),
        ("source_id", json!("other")),
        ("source_revision", json!(2)),
    ] {
        let mut r = reply();
        r[key] = value;
        denied(s.verify_reply(&i, &r.to_string()), Denied::BindingMismatch);
    }
    for (key, value) in [
        ("content", "違う文章です。\n"),
        ("path", "other.md"),
        ("blob", &"f".repeat(40)),
    ] {
        let mut r = reply();
        r["files"][0][key] = json!(value);
        denied(s.verify_reply(&i, &r.to_string()), Denied::BindingMismatch);
    }
    let mut r = reply();
    r["allow"] = json!(true);
    denied(s.verify_reply(&i, &r.to_string()), Denied::InvalidInput);
    denied(
        s.verify_reply(&i, &"x".repeat(393217)),
        Denied::InvalidInput,
    );
}
