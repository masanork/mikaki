use super::*;
use serde_json::{Value, json};

fn git_input() -> Value {
    json!({"code":{"repository":"repo:source","commit":"a".repeat(40),"tree":"b".repeat(40),"commits":["a".repeat(40)],"objects":3,"object_bytes":512,"head_files":1},
        "contexts":[{"repository":"personal-context","commit":"c".repeat(40),"tree":"d".repeat(40),"files":[{"path":"writing.md","blob":"e".repeat(40),"mode":"100644","content":"Use clear words.\n"}]}],
        "snapshot":{"repository":"snapshot-1","commit":"f".repeat(40),"tree":"1".repeat(40),"parents":[]}})
}
fn resolve(f: &Fixture, input: Value) -> Result<ResolvedDisclosure, Denied> {
    ResolvedDisclosure::from_verified_git(
        serde_json::from_value(input).unwrap(),
        "launcher-client",
        "managed-agent",
        &f.session,
        &f.env(100),
        700,
    )
}
fn registered_inputs() -> (Value, Value) {
    let input = git_input();
    let history =
        Digest::from_bytes(Sha256::digest(format!("{}\n", "a".repeat(40)).as_bytes()).into());
    let code = json!({"source_id":"repo:source","source_revision":1,"role":"code","label":"Code","repo_name":"code-repo",
        "commit":input["code"]["commit"],"tree":input["code"]["tree"],"files":[],
        "code":{"commits":1,"history_digest":history,"objects":3,"object_bytes":512,"head_files":1}});
    let sha = Digest::from_bytes(Sha256::digest(b"Use clear words.\n").into());
    let context = json!({"source_id":"personal-context","source_revision":1,"role":"personal","label":"Context","repo_name":"personal-repo",
        "commit":input["contexts"][0]["commit"],"tree":input["contexts"][0]["tree"],"code":null,
        "files":[{"path":"writing.md","blob":"e".repeat(40),"mode":"100644","bytes":17,"sha256":sha}]});
    (code, context)
}
fn registered(value: Value) -> RegisteredSource {
    RegisteredSource::from_verified_git(serde_json::from_value(value).unwrap()).unwrap()
}
fn preparation_fixture(f: &Fixture, id: &str) -> Preparation {
    let (c, x) = registered_inputs();
    let c = registered(c);
    let x = registered(x);
    let d = resolve(f, git_input())
        .unwrap()
        .bind_registered_sources(&[(&c, 1), (&x, 1)], Digest::from_bytes([7; 32]))
        .unwrap();
    Preparation::from_registered_disclosure(
        &d,
        id,
        "repo:task",
        "qualification-code",
        "qualification-context",
    )
    .unwrap()
}

#[test]
fn candidate_payload_commits_exact_history_provenance_and_bounded_opaque_bytes() {
    let f = Fixture::new();
    let p = preparation_fixture(&f, "payload-preparation");
    let mut input = input();
    input.disclosure_digest = p.disclosure_digest().to_hex();
    let request = input.validate(&f.session, &f.env(100)).unwrap();
    let task =
        TaskRepository::from_authority("owner-1", "repo:task", 1, p.disclosure_digest()).unwrap();
    let grant = Grant::approve(
        "grant-1",
        &request,
        request.digest(),
        &f.session,
        &task,
        &f.env(100),
    )
    .unwrap();
    let run = Run::register(&f.actor, &grant, &request, &task, 500, &f.env(100)).unwrap();
    let guard = || {
        run.authorize_submission(SUBMIT, &grant, &request, &f.actor, &task, &f.env(110))
            .unwrap()
    };
    let c = guard()
        .prepare_candidate(candidate_input())
        .unwrap()
        .confirm(guard())
        .unwrap();
    let facts = || CandidateGitFacts {
        commit: c.commit().into(),
        tree: c.tree().into(),
        base_commit: request.input().base_commit.clone(),
        objects: 3,
        object_bytes: 512,
        inventory_digest: Digest::from_bytes([1; 32]),
        bundle_digest: Digest::from_bytes(Sha256::digest(b"opaque-synthetic-bundle").into()),
        bundle_bytes: 23,
    };
    let mut good = facts();
    good.bundle_bytes = b"opaque-synthetic-bundle".len() as u64;
    let payload =
        CandidatePayload::from_verified_git(&c, &request, &p, "actual-task", good).unwrap();
    let body = payload.authority_record().unwrap();
    assert_eq!(
        CandidatePayload::restore_authority_record(&body, &c, &request, &p, "actual-task")
            .unwrap()
            .digest(),
        payload.digest()
    );
    payload
        .verify_bundle_bytes(b"opaque-synthetic-bundle")
        .unwrap();
    assert!(payload.verify_bundle_bytes(b"substituted").is_err());
    assert!(
        CandidatePayload::restore_authority_record(&body, &c, &request, &p, "foreign-task")
            .is_err()
    );
    for (field, value) in [
        ("candidate", json!("1".repeat(64))),
        ("base_commit", json!("f".repeat(40))),
        ("bundle_bytes", json!(MAX_CANDIDATE_BUNDLE_BYTES + 1)),
        ("format", json!("git-bundle-v3")),
        ("unknown", json!(true)),
    ] {
        let mut changed: Value = serde_json::from_str(&body).unwrap();
        changed["data"]["data"][field] = value;
        assert!(
            CandidatePayload::restore_authority_record(
                &changed.to_string(),
                &c,
                &request,
                &p,
                "actual-task"
            )
            .is_err()
        );
    }
    let mut bad = facts();
    bad.object_bytes = 67108865;
    assert!(CandidatePayload::from_verified_git(&c, &request, &p, "actual-task", bad).is_err());
}

#[test]
fn credential_attempt_is_frozen_to_dispatched_preparation_and_expected_repository() {
    let f = Fixture::new();
    let mut p = preparation_fixture(&f, "custody");
    assert!(
        CredentialAttempt::from_preparation(
            &p,
            "attempt",
            CredentialRole::Task,
            CredentialPurpose::Initial,
            None
        )
        .is_err()
    );
    p.dispatch(&f.env(100)).unwrap();
    assert!(
        CredentialAttempt::from_preparation(
            &p,
            "attempt",
            CredentialRole::Task,
            CredentialPurpose::Upload,
            None
        )
        .is_err()
    );
    let a = CredentialAttempt::from_preparation(
        &p,
        "attempt",
        CredentialRole::Task,
        CredentialPurpose::Upload,
        Some("actual-repo"),
    )
    .unwrap();
    let body = a.authority_record().unwrap();
    assert_eq!(
        CredentialAttempt::restore_authority_record(&body, &p)
            .unwrap()
            .digest(),
        a.digest()
    );
    let other = preparation_fixture(&f, "other-custody");
    assert!(CredentialAttempt::restore_authority_record(&body, &other).is_err());
    assert!(
        CredentialObservation::from_observed(
            &a,
            "other-repo",
            "token",
            CredentialScope::Write,
            None
        )
        .is_err()
    );
    for (field, value) in [
        ("namespace", json!("foreign")),
        ("deadline", json!(699)),
        ("purpose", json!("readback")),
        ("unknown", json!(true)),
    ] {
        let mut changed: Value = serde_json::from_str(&body).unwrap();
        changed["data"]["plan"][field] = value;
        assert!(CredentialAttempt::restore_authority_record(&changed.to_string(), &p).is_err());
    }
}

#[test]
fn credential_envelope_authenticates_attempt_observation_key_and_ciphertext() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let f = Fixture::new();
    let mut p = preparation_fixture(&f, "encrypted-custody");
    p.dispatch(&f.env(100)).unwrap();
    let a = CredentialAttempt::from_preparation(
        &p,
        "attempt",
        CredentialRole::Task,
        CredentialPurpose::Initial,
        None,
    )
    .unwrap();
    let secret = CredentialSecret::from_service_bytes(b"synthetic-secret").unwrap();
    let key = WrappingKey::from_service_secret(1, &URL_SAFE_NO_PAD.encode([7; 32])).unwrap();
    let o = CredentialObservation::from_observed(
        &a,
        "actual",
        "token",
        CredentialScope::Write,
        Some(600),
    )
    .unwrap();
    let body = key.seal(&a, &o, &secret, [9; 12]).unwrap();
    assert!(key.open(&a, &o, &body).unwrap().matches(&secret));
    assert!(!body.contains("synthetic-secret"));
    let other = CredentialAttempt::from_preparation(
        &p,
        "other",
        CredentialRole::Task,
        CredentialPurpose::Initial,
        None,
    )
    .unwrap();
    assert!(key.open(&other, &o, &body).is_err());
    for (repo, token, scope, expiry) in [
        ("foreign", "token", CredentialScope::Write, Some(600)),
        ("actual", "foreign", CredentialScope::Write, Some(600)),
        ("actual", "token", CredentialScope::Read, Some(600)),
        ("actual", "token", CredentialScope::Write, None),
    ] {
        let changed = CredentialObservation::from_observed(&a, repo, token, scope, expiry).unwrap();
        assert!(key.open(&a, &changed, &body).is_err());
    }
    for other in [
        WrappingKey::from_service_secret(2, &URL_SAFE_NO_PAD.encode([7; 32])).unwrap(),
        WrappingKey::from_service_secret(1, &URL_SAFE_NO_PAD.encode([8; 32])).unwrap(),
    ] {
        assert!(other.open(&a, &o, &body).is_err());
    }
    for (field, value) in [
        ("nonce", json!(URL_SAFE_NO_PAD.encode([8; 12]))),
        ("ciphertext", json!(URL_SAFE_NO_PAD.encode([1; 32]))),
        ("key_version", json!(2)),
        ("version", json!(2)),
        ("unknown", json!(true)),
    ] {
        let mut changed: Value = serde_json::from_str(&body).unwrap();
        changed["data"][field] = value;
        assert!(key.open(&a, &o, &changed.to_string()).is_err());
    }
}

#[test]
fn credential_secrets_and_wrapping_keys_enforce_bounded_canonical_service_input() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    for bytes in [b"".as_slice(), b"with space", b"line\nbreak", &[127], &[0]] {
        assert!(CredentialSecret::from_service_bytes(bytes).is_err());
    }
    assert!(CredentialSecret::from_service_bytes(&vec![b'a'; 4096]).is_ok());
    assert!(CredentialSecret::from_service_bytes(&vec![b'a'; 4097]).is_err());
    for key in [
        URL_SAFE_NO_PAD.encode([0; 31]),
        URL_SAFE_NO_PAD.encode([0; 33]),
        format!("{}=", URL_SAFE_NO_PAD.encode([0; 32])),
    ] {
        assert!(WrappingKey::from_service_secret(1, &key).is_err());
    }
    assert!(WrappingKey::from_service_secret(0, &URL_SAFE_NO_PAD.encode([0; 32])).is_err());
}
#[test]
fn preparation_review_commits_destinations_and_excludes_private_receipts() {
    let f = Fixture::new();
    let mut p = preparation_fixture(&f, "review-copy");
    let reserved = p.review(None).unwrap();
    assert!(reserved["destination_digest"].is_null());
    assert!(reserved["task"]["repository_id"].is_null());
    let e = VerifiedPreparation::from_independently_verified(
        &p,
        "remote-code",
        "remote-context",
        Digest::from_bytes([1; 32]),
        Digest::from_bytes([2; 32]),
    )
    .unwrap();
    denied(p.review(Some(&e)), Denied::BindingMismatch);
    p.dispatch(&f.env(101)).unwrap();
    p.verify(&e).unwrap();
    denied(p.review(None), Denied::BindingMismatch);
    let v = p.review(Some(&e)).unwrap();
    assert_eq!(v["task"]["repository_id"], "remote-code");
    assert_eq!(v["snapshot"]["repository_id"], "remote-context");
    assert_eq!(v["destination_digest"].as_str().unwrap().len(), 64);
    for private in [
        "payload_receipt",
        "credential_receipt",
        "evidence",
        "owner",
        "token",
    ] {
        assert!(!v.to_string().contains(private));
    }
    let other = preparation_fixture(&f, "other-copy");
    denied(other.review(Some(&e)), Denied::BindingMismatch);
    p.require_cleanup();
    let cleaned = p.review(Some(&e)).unwrap();
    assert_eq!(cleaned["destination_digest"], v["destination_digest"]);
    assert_eq!(cleaned["state"], "cleanup_pending");
    p.confirm_cleaned().unwrap();
    assert_eq!(
        p.review(Some(&e)).unwrap()["destination_digest"],
        v["destination_digest"]
    );
}
#[test]
fn prepared_task_gates_production_and_retains_history_after_cleanup() {
    let f = Fixture::new();
    let (c, x) = registered_inputs();
    let c = registered(c);
    let x = registered(x);
    let d = resolve(&f, git_input())
        .unwrap()
        .bind_registered_sources(&[(&c, 1), (&x, 1)], Digest::from_bytes([7; 32]))
        .unwrap();
    let body = d.authority_record().unwrap();
    let disclosure = || ResolvedDisclosure::restore_authority_record(&body).unwrap();
    let mut i = input();
    i.disclosure_digest = d.digest().to_hex();
    let request = i.clone().validate(&f.session, &f.env(100)).unwrap();
    let mut p = preparation_fixture(&f, "task-proof");
    let e = VerifiedPreparation::from_independently_verified(
        &p,
        "remote-code",
        "remote-context",
        Digest::from_bytes([1; 32]),
        Digest::from_bytes([2; 32]),
    )
    .unwrap();
    for state in [
        PreparationState::Reserved,
        PreparationState::Dispatched,
        PreparationState::CleanupPending,
        PreparationState::Cleaned,
    ] {
        let retained =
            Preparation::restore_authority_record(&p.authority_record().unwrap(), state).unwrap();
        let task = retained.task_authority(&e, disclosure(), 1, true).unwrap();
        denied(
            Grant::approve(
                "new",
                &request,
                request.digest(),
                &f.session,
                &task,
                &f.env(101),
            ),
            Denied::StaleAuthority,
        );
    }
    p.dispatch(&f.env(101)).unwrap();
    p.verify(&e).unwrap();
    let task = p.task_authority(&e, disclosure(), 1, true).unwrap();
    let grant = Grant::approve(
        "grant-1",
        &request,
        request.digest(),
        &f.session,
        &task,
        &f.env(101),
    )
    .unwrap();
    let run = Run::register(&f.actor, &grant, &request, &task, 500, &f.env(101)).unwrap();
    i.recipient = "other-client".into();
    let wrong = i.validate(&f.session, &f.env(100)).unwrap();
    denied(task.check_request(&wrong), Denied::BindingMismatch);
    let stale = p.task_authority(&e, disclosure(), 1, false).unwrap();
    denied(stale.check_request(&request), Denied::StaleAuthority);
    let fenced = p.task_authority(&e, disclosure(), 2, true).unwrap();
    denied(fenced.check_request(&request), Denied::StaleAuthority);
    let other = preparation_fixture(&f, "other-task-proof");
    denied(
        other.task_authority(&e, disclosure(), 1, true),
        Denied::BindingMismatch,
    );
    p.require_cleanup();
    let retained = p.task_authority(&e, disclosure(), 1, true).unwrap();
    denied(
        Run::register(&f.actor, &grant, &request, &retained, 500, &f.env(101)),
        Denied::StaleAuthority,
    );
    denied(
        run.authorize_submission(SUBMIT, &grant, &request, &f.actor, &retained, &f.env(101)),
        Denied::StaleAuthority,
    );
    denied(
        TaskRepository::from_authority("owner-1", "repo:task", 1, d.digest())
            .unwrap()
            .retain_only()
            .check_request(&request),
        Denied::StaleAuthority,
    );
}
#[test]
fn preparation_commits_mapping_and_preserves_unknown_effect_identity() {
    let f = Fixture::new();
    let mut p = preparation_fixture(&f, "attempt-1");
    let body = p.authority_record().unwrap();
    let restored =
        Preparation::restore_authority_record(&body, PreparationState::Reserved).unwrap();
    assert_eq!(restored.digest(), p.digest());
    assert_eq!(restored.authority_record().unwrap(), body);
    assert_eq!(p.reserved_bytes(), 529);
    assert!(!body.contains("Use clear words"));
    assert!(!body.contains("token"));
    p.dispatch(&f.env(101)).unwrap();
    assert_eq!(p.state(), PreparationState::Dispatched);
    assert_eq!(p.authority_record().unwrap(), body);
    denied(p.dispatch(&f.env(102)), Denied::InvalidTransition);
    let other = preparation_fixture(&f, "attempt-2");
    let evidence = VerifiedPreparation::from_independently_verified(
        &other,
        "task-id",
        "snapshot-id",
        Digest::from_bytes([1; 32]),
        Digest::from_bytes([2; 32]),
    )
    .unwrap();
    denied(p.verify(&evidence), Denied::BindingMismatch);
    let evidence = VerifiedPreparation::from_independently_verified(
        &p,
        "task-id",
        "snapshot-id",
        Digest::from_bytes([1; 32]),
        Digest::from_bytes([2; 32]),
    )
    .unwrap();
    p.verify(&evidence).unwrap();
    p.require_cleanup();
    assert_eq!(p.state(), PreparationState::CleanupPending);
    denied(p.verify(&evidence), Denied::InvalidTransition);
    p.confirm_cleaned().unwrap();
    assert_eq!(p.state(), PreparationState::Cleaned);
    assert_eq!(p.authority_record().unwrap(), body);
    for pointer in [
        "/data/plan/task_namespace",
        "/data/plan/binding/disclosure",
        "/data/plan/task_name",
    ] {
        let mut changed: Value = serde_json::from_str(&body).unwrap();
        *changed.pointer_mut(pointer).unwrap() = json!("other");
        assert!(
            Preparation::restore_authority_record(&changed.to_string(), PreparationState::Reserved)
                .is_err()
        );
    }
}
#[test]
fn preparation_requires_v2_separate_destinations_and_current_owner_at_dispatch() {
    let f = Fixture::new();
    denied(
        Preparation::from_registered_disclosure(
            &resolve(&f, git_input()).unwrap(),
            "op",
            "task",
            "code",
            "context",
        ),
        Denied::BindingMismatch,
    );
    let p = preparation_fixture(&f, "op");
    let body = p.authority_record().unwrap();
    for task in ["snapshot-1", "repo:source", "personal-context"] {
        let mut changed: Value = serde_json::from_str(&body).unwrap();
        changed["data"]["plan"]["task_repository"] = json!(task);
        denied(
            Preparation::restore_authority_record(&changed.to_string(), PreparationState::Reserved),
            Denied::BindingMismatch,
        );
    }
    denied(
        preparation_fixture(&f, "expired").dispatch(&f.env(700)),
        Denied::Expired,
    );
    let stale = OwnerState::from_authority("owner-1", 8, true).unwrap();
    denied(
        preparation_fixture(&f, "stale").dispatch(&Environment {
            owner: &stale,
            policy_revision: 11,
            now: 101,
        }),
        Denied::StaleAuthority,
    );
    let mut undispatched = preparation_fixture(&f, "cancelled");
    undispatched.require_cleanup();
    assert_eq!(undispatched.state(), PreparationState::Cleaned);
    denied(
        undispatched.dispatch(&f.env(102)),
        Denied::InvalidTransition,
    );
    denied(
        VerifiedPreparation::from_independently_verified(
            &p,
            "same-id",
            "same-id",
            Digest::from_bytes([1; 32]),
            Digest::from_bytes([2; 32]),
        ),
        Denied::BindingMismatch,
    );
}
#[test]
fn registered_disclosure_versions_access_digest_and_legacy_restoration() {
    let f = Fixture::new();
    let legacy = resolve(&f, git_input()).unwrap();
    let body = legacy.authority_record().unwrap();
    assert_eq!(
        ResolvedDisclosure::restore_authority_record(&body)
            .unwrap()
            .authority_record()
            .unwrap(),
        body
    );
    denied(legacy.require_registered_sources(), Denied::BindingMismatch);
    let (code, context) = registered_inputs();
    let c = registered(code.clone());
    let x = registered(context.clone());
    let d = legacy
        .bind_registered_sources(&[(&c, 1), (&x, 1)], Digest::from_bytes([7; 32]))
        .unwrap();
    d.require_registered_sources().unwrap();
    let body = d.authority_record().unwrap();
    let saved: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(saved["version"], 1); // stable storage envelope; disclosure domain v2
    assert_eq!(saved["data"]["data"]["format_version"], 2);
    assert_eq!(
        ResolvedDisclosure::restore_authority_record(&body)
            .unwrap()
            .digest(),
        d.digest()
    );
    for access in [2, MAX_STORED_INTEGER] {
        let changed = resolve(&f, git_input())
            .unwrap()
            .bind_registered_sources(&[(&c, 1), (&x, access)], Digest::from_bytes([7; 32]))
            .unwrap();
        assert_ne!(changed.digest(), d.digest());
    }
    let mut next = context;
    next["source_revision"] = json!(2);
    let next = registered(next);
    assert_ne!(
        resolve(&f, git_input())
            .unwrap()
            .bind_registered_sources(&[(&c, 1), (&next, 1)], Digest::from_bytes([7; 32]))
            .unwrap()
            .digest(),
        d.digest()
    );
    let mut changed = saved.clone();
    changed["data"]["data"]["policy_projection"] = json!("8".repeat(64));
    denied(
        ResolvedDisclosure::restore_authority_record(&changed.to_string()),
        Denied::ReviewMismatch,
    );
    assert_ne!(
        resolve(&f, git_input())
            .unwrap()
            .bind_registered_sources(&[(&c, 1), (&x, 1)], Digest::from_bytes([8; 32]))
            .unwrap()
            .digest(),
        d.digest()
    );
    let mut changed = saved.clone();
    changed["data"]["data"]["registered_sources"][1]["access_revision"] = json!(2);
    denied(
        ResolvedDisclosure::restore_authority_record(&changed.to_string()),
        Denied::ReviewMismatch,
    );
    let mut changed = saved;
    changed["data"]["data"]["format_version"] = json!(3);
    denied(
        ResolvedDisclosure::restore_authority_record(&changed.to_string()),
        Denied::InvalidInput,
    );
    assert!(!body.contains("Use clear words"));
    assert!(!body.contains("repo_name"));
}
#[test]
fn registered_disclosure_rejects_substituted_receipts_membership_and_history() {
    let f = Fixture::new();
    let (code, context) = registered_inputs();
    let c = registered(code.clone());
    let x = registered(context.clone());
    for facts in [
        vec![(&x, 1), (&c, 1)],
        vec![(&c, 1)],
        vec![(&c, 1), (&x, 0)],
    ] {
        assert!(
            resolve(&f, git_input())
                .unwrap()
                .bind_registered_sources(&facts, Digest::from_bytes([7; 32]))
                .is_err()
        );
    }
    for (pointer, value) in [
        ("/commit", json!("2".repeat(40))),
        ("/tree", json!("2".repeat(40))),
        ("/repo_name", json!("code-repo")),
        ("/source_id", json!("other")),
        ("/files/0/path", json!("other.md")),
        ("/files/0/blob", json!("2".repeat(40))),
        ("/files/0/mode", json!("100755")),
        ("/files/0/bytes", json!(18)),
        ("/files/0/sha256", json!("0".repeat(64))),
    ] {
        let mut changed = context.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed = registered(changed);
        denied(
            resolve(&f, git_input())
                .unwrap()
                .bind_registered_sources(&[(&c, 1), (&changed, 1)], Digest::from_bytes([7; 32])),
            Denied::BindingMismatch,
        );
    }
    for (pointer, value) in [
        ("/code/commits", json!(2)),
        ("/code/history_digest", json!("0".repeat(64))),
        ("/code/objects", json!(4)),
        ("/code/object_bytes", json!(513)),
        ("/code/head_files", json!(2)),
    ] {
        let mut changed = code.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed = registered(changed);
        denied(
            resolve(&f, git_input())
                .unwrap()
                .bind_registered_sources(&[(&changed, 1), (&x, 1)], Digest::from_bytes([7; 32])),
            Denied::BindingMismatch,
        );
    }
}
#[test]
fn disclosure_binds_actual_content_versions_recipient_and_owner_review() {
    let f = Fixture::new();
    let d = resolve(&f, git_input()).unwrap();
    let mut i = input();
    i.disclosure_digest = d.digest().to_hex();
    let request = i.clone().validate(&f.session, &f.env(100)).unwrap();
    d.check_request(&request, &f.env(101)).unwrap();
    assert_eq!(d.selected_bytes(), 17);
    for (field, value) in [
        ("content", "Different words.\n"),
        ("path", "other.md"),
        ("blob", &"2".repeat(40)),
    ] {
        let mut changed = git_input();
        changed["contexts"][0]["files"][0][field] = json!(value);
        assert_ne!(resolve(&f, changed).unwrap().digest(), d.digest());
    }
    i.recipient = "other-client".into();
    let wrong = i.validate(&f.session, &f.env(100)).unwrap();
    denied(
        d.check_request(&wrong, &f.env(100)),
        Denied::BindingMismatch,
    );
    denied(d.check_request(&request, &f.env(700)), Denied::Expired);
    denied(
        d.check_request(
            &request,
            &Environment {
                owner: &f.owner,
                policy_revision: 12,
                now: 101,
            },
        ),
        Denied::StalePolicy,
    );
}
#[test]
fn disclosure_rejects_ambiguous_paths_modes_history_and_size() {
    let f = Fixture::new();
    for invalid in [
        "../secret",
        "a/../secret",
        "/secret",
        "a//secret",
        "a/.git/config",
        ".gitmodules",
        "a\\secret",
        "a\nsecret",
        "",
    ] {
        let mut i = git_input();
        i["contexts"][0]["files"][0]["path"] = json!(invalid);
        denied(resolve(&f, i), Denied::InvalidInput);
    }
    for (key, value) in [
        ("mode", json!("120000")),
        ("content", json!("x".repeat(16385))),
        ("content", json!("\0")),
        (
            "content",
            json!("version https://git-lfs.github.com/spec/v1\n"),
        ),
    ] {
        let mut i = git_input();
        i["contexts"][0]["files"][0][key] = value;
        denied(resolve(&f, i), Denied::InvalidInput);
    }
    let mut i = git_input();
    i["snapshot"]["parents"] = json!(["a".repeat(40)]);
    denied(resolve(&f, i), Denied::InvalidInput);
    let mut i = git_input();
    i["code"]["commits"] = json!(["a".repeat(40), "a".repeat(40)]);
    denied(resolve(&f, i), Denied::InvalidInput);
    let mut i = git_input();
    i["contexts"][0]["files"] = json!(vec![i["contexts"][0]["files"][0].clone(); 33]);
    denied(resolve(&f, i), Denied::InvalidInput);
}
#[test]
fn disclosure_codec_recomputes_digest_and_drops_content() {
    let f = Fixture::new();
    let d = resolve(&f, git_input()).unwrap();
    let body = d.authority_record().unwrap();
    assert!(!body.contains("Use clear words"));
    assert_eq!(
        ResolvedDisclosure::restore_authority_record(&body)
            .unwrap()
            .digest(),
        d.digest()
    );
    let mut changed: Value = serde_json::from_str(&body).unwrap();
    changed["data"]["data"]["snapshot"]["commit"] = json!("3".repeat(40));
    denied(
        ResolvedDisclosure::restore_authority_record(&changed.to_string()),
        Denied::ReviewMismatch,
    );
    let mut i = git_input();
    i["owner"] = json!("foreign");
    assert!(serde_json::from_value::<GitDisclosureInput>(i).is_err());
}
