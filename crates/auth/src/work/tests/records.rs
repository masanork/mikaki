use super::*;

#[test]
fn immutable_storage_roundtrip_preserves_review_and_revoked_producer_tombstones() {
    let f = Fixture::new();
    let request =
        WorkRequest::restore_authority_record(&f.request.authority_record().unwrap()).unwrap();
    assert_eq!(request.digest(), f.request.digest());
    let grant =
        Grant::restore_authority_record(&f.grant.authority_record().unwrap(), 2, true).unwrap();
    let run = Run::restore_authority_record(&f.run.authority_record().unwrap(), 2, true).unwrap();
    assert!(grant.is_revoked());
    assert!(run.is_revoked());
    let candidate = f.candidate();
    let candidate = Candidate::restore_authority_record(
        &candidate.authority_record().unwrap(),
        &request,
        &grant,
        &run,
    )
    .unwrap();
    assert_eq!(candidate.digest(), f.candidate().digest());
    let environment = f.env(610);
    let context = AdoptionContext {
        candidate: &candidate,
        grant: &grant,
        run: &run,
        target: &f.target,
        environment: &environment,
    };
    let fresh =
        CodeApproval::approve("fresh", candidate.digest(), &f.session, &context, 700).unwrap();
    let fresh =
        CodeApproval::restore_authority_record(&fresh.authority_record().unwrap(), 1, false)
            .unwrap();
    let mut operation = fresh
        .prepare_operation(ADOPT_CODE, "op-1", &context)
        .unwrap();
    fresh.dispatch(&mut operation, &context).unwrap();
    let mut restored = ExternalOperation::restore_authority_record(
        &operation.authority_record().unwrap(),
        OperationState::OutcomeUnknown,
        None,
    )
    .unwrap();
    restored.confirm_applied("receipt-1").unwrap();
    assert_eq!(restored.state(), OperationState::Applied);
}

#[test]
fn storage_codecs_reject_changed_digests_bindings_unknown_fields_and_versions() {
    let f = Fixture::new();
    let original: serde_json::Value =
        serde_json::from_str(&f.request.authority_record().unwrap()).unwrap();
    let mut changed = original.clone();
    changed["data"]["input"]["goal"] = "Changed after review".into();
    denied(
        WorkRequest::restore_authority_record(&changed.to_string()),
        Denied::ReviewMismatch,
    );
    for field in ["version", "kind", "unknown"] {
        let mut changed = original.clone();
        changed[field] = serde_json::json!(2);
        denied(
            WorkRequest::restore_authority_record(&changed.to_string()),
            Denied::InvalidInput,
        );
    }
    let candidate = f.candidate();
    let mut changed: serde_json::Value =
        serde_json::from_str(&candidate.authority_record().unwrap()).unwrap();
    changed["data"]["provenance"]["adoption_repository"] = "repo:substituted".into();
    denied(
        Candidate::restore_authority_record(&changed.to_string(), &f.request, &f.grant, &f.run),
        Denied::BindingMismatch,
    );
    let mut changed: serde_json::Value =
        serde_json::from_str(&candidate.authority_record().unwrap()).unwrap();
    changed["data"]["commit"] = "f".repeat(40).into();
    denied(
        Candidate::restore_authority_record(&changed.to_string(), &f.request, &f.grant, &f.run),
        Denied::ReviewMismatch,
    );
    denied(
        WorkRequest::restore_authority_record(&"x".repeat(32769)),
        Denied::InvalidInput,
    );
}

#[test]
fn mutable_authority_state_cannot_be_reactivated_or_read_from_immutable_json() {
    let f = Fixture::new();
    let body = f.grant.authority_record().unwrap();
    for (revision, revoked) in [
        (0, false),
        (2, false),
        (1, true),
        (3, true),
        (MAX_STORED_INTEGER + 1, false),
    ] {
        denied(
            Grant::restore_authority_record(&body, revision, revoked),
            Denied::InvalidInput,
        );
    }
    let mut changed: serde_json::Value = serde_json::from_str(&body).unwrap();
    changed["data"]["revoked"] = false.into();
    denied(
        Grant::restore_authority_record(&changed.to_string(), 2, true),
        Denied::InvalidInput,
    );
    let candidate = f.candidate();
    let approval = f.approval(&candidate);
    let operation = approval
        .prepare_operation(ADOPT_CODE, "op-1", &f.context(&candidate, &f.env(130)))
        .unwrap();
    let body = operation.authority_record().unwrap();
    denied(
        ExternalOperation::restore_authority_record(&body, OperationState::Applied, None),
        Denied::InvalidInput,
    );
    denied(
        ExternalOperation::restore_authority_record(
            &body,
            OperationState::Prepared,
            Some("receipt-1"),
        ),
        Denied::InvalidInput,
    );
}
