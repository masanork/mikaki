use super::*;

#[test]
fn request_and_candidate_match_independent_length_prefixed_sha256_vectors() {
    // Python hashlib/struct encoder of the field order in workload-profile-v1.md.
    let f = Fixture::new();
    assert_eq!(
        f.request.digest().to_hex(),
        "2b218465b4c8883f33833ce03560f754aec2af0b6edef212a3ec6b904e1a5367"
    );
    assert_eq!(
        f.candidate().digest().to_hex(),
        "331f70773aac5dc74debf53b780885bc1071da3169de4f0b9218f3e718571280"
    );
}

#[test]
fn identifiers_digests_hash_formats_and_zero_revisions_fail_closed() {
    let f = Fixture::new();
    for digest in ["", "short", &"C".repeat(64), &"g".repeat(64)] {
        denied(Digest::parse_hex(digest), Denied::InvalidInput);
    }
    for field in [
        "request_id",
        "code_repository",
        "recipient",
        "workload",
        "task_repository",
        "adoption_repository",
    ] {
        let mut value = serde_json::to_value(input()).unwrap();
        value[field] = serde_json::json!("unresolved/id");
        let raw: RequestInput = serde_json::from_value(value).unwrap();
        denied(raw.validate(&f.session, &f.env(100)), Denied::InvalidInput);
    }
    let mut raw = input();
    raw.revision = 0;
    denied(raw.validate(&f.session, &f.env(100)), Denied::InvalidInput);
    let mut raw = input();
    raw.expected_head = "a".repeat(64);
    denied(raw.validate(&f.session, &f.env(100)), Denied::InvalidInput);
    assert!(OwnerState::from_authority("owner-1", 0, true).is_ok());
    denied(
        OwnerState::from_authority("owner-1", MAX_STORED_INTEGER + 1, true),
        Denied::InvalidInput,
    );
    denied(
        TaskRepository::from_authority("owner-1", "repo:task", 0, Digest::from_bytes([0; 32])),
        Denied::InvalidInput,
    );
    let env = Environment {
        owner: &f.owner,
        policy_revision: 0,
        now: 100,
    };
    denied(input().validate(&f.session, &env), Denied::InvalidInput);
}

#[test]
fn request_digest_binds_every_reviewed_field_owner_epoch_and_policy() {
    let f = Fixture::new();
    let base = serde_json::to_value(input()).unwrap();
    for (field, value) in [
        ("request_id", serde_json::json!("request-2")),
        ("revision", serde_json::json!(2)),
        ("goal", serde_json::json!("Different goal")),
        ("acceptance", serde_json::json!("Different criteria")),
        ("code_repository", serde_json::json!("repo:other")),
        ("base_commit", serde_json::json!("b".repeat(40))),
        ("disclosure_digest", serde_json::json!("f".repeat(64))),
        ("recipient", serde_json::json!("other-client")),
        ("workload", serde_json::json!("other-agent")),
        ("task_repository", serde_json::json!("repo:other-task")),
        (
            "adoption_repository",
            serde_json::json!("repo:other-target"),
        ),
        ("adoption_ref", serde_json::json!("refs/heads/other")),
        ("expected_head", serde_json::json!("b".repeat(40))),
        ("deadline", serde_json::json!(601)),
    ] {
        let mut changed = base.clone();
        changed[field] = value;
        let request: RequestInput = serde_json::from_value(changed).unwrap();
        assert_ne!(
            request.validate(&f.session, &f.env(100)).unwrap().digest(),
            f.request.digest(),
            "{field}"
        );
    }
    for (owner, epoch, policy) in [
        ("other-owner", 7, 11),
        ("owner-1", 8, 11),
        ("owner-1", 7, 12),
    ] {
        let state = OwnerState::from_authority(owner, epoch, true).unwrap();
        let session = OwnerSession::from_verified_session(owner, epoch, 1000).unwrap();
        let env = Environment {
            owner: &state,
            policy_revision: policy,
            now: 100,
        };
        assert_ne!(
            input().validate(&session, &env).unwrap().digest(),
            f.request.digest()
        );
    }
    assert_eq!(
        input().validate(&f.session, &f.env(101)).unwrap().digest(),
        f.request.digest()
    );
}

#[test]
fn input_is_closed_bounded_and_does_not_accept_authority_claims() {
    let f = Fixture::new();
    for field in [
        "owner",
        "owner_epoch",
        "assurance",
        "policy_revision",
        "approved",
    ] {
        let mut value = serde_json::to_value(input()).unwrap();
        value[field] = serde_json::json!("owner-2");
        assert!(
            serde_json::from_value::<RequestInput>(value).is_err(),
            "{field}"
        );
    }
    for reference in [
        "refs/tags/v1",
        "refs/heads/",
        "refs/heads/a..b",
        "refs/heads/.hidden",
        "refs/heads/main.lock",
        "refs/heads/a@{b",
        "refs/heads/a b",
        "refs/heads/a\\b",
    ] {
        let mut request = input();
        request.adoption_ref = reference.into();
        denied(
            request.validate(&f.session, &f.env(100)),
            Denied::InvalidInput,
        );
    }
    for value in ["", " ", "x\0y"] {
        let mut request = input();
        request.goal = value.into();
        denied(
            request.validate(&f.session, &f.env(100)),
            Denied::InvalidInput,
        );
    }
    let mut request = input();
    request.acceptance = "x".repeat(8193);
    denied(
        request.validate(&f.session, &f.env(100)),
        Denied::InvalidInput,
    );
    let mut request = input();
    request.task_repository = request.adoption_repository.clone();
    denied(
        request.validate(&f.session, &f.env(100)),
        Denied::BindingMismatch,
    );
    for (expires, expected) in [
        (100, Denied::Expired),
        (3701, Denied::Expired),
        (u64::MAX, Denied::InvalidInput),
    ] {
        let mut request = input();
        request.deadline = expires;
        denied(request.validate(&f.session, &f.env(100)), expected);
    }
    for operations in [
        vec![],
        vec![SUBMIT.into(), SUBMIT.into()],
        vec!["repo.git-token.issue".into()],
    ] {
        let mut request = input();
        request.operations = operations;
        denied(
            request.validate(&f.session, &f.env(100)),
            Denied::UnsupportedAction,
        );
    }
    let mut request = input();
    request.profile = "unknown-profile".into();
    denied(
        request.validate(&f.session, &f.env(100)),
        Denied::UnsupportedAction,
    );
}
