use super::*;

#[test]
fn approval_is_exact_short_lived_and_code_only() {
    let f = Fixture::new();
    let candidate = f.candidate();
    let env = f.env(130);
    let context = f.context(&candidate, &env);
    denied(
        CodeApproval::approve(
            "approval-1",
            Digest::from_bytes([0; 32]),
            &f.session,
            &context,
            400,
        ),
        Denied::ReviewMismatch,
    );
    for (expiry, expected) in [
        (130, Denied::Expired),
        (431, Denied::Expired),
        (u64::MAX, Denied::InvalidInput),
    ] {
        denied(
            CodeApproval::approve(
                "approval-1",
                candidate.digest(),
                &f.session,
                &context,
                expiry,
            ),
            expected,
        );
    }
    let short_session = OwnerSession::from_verified_session("owner-1", 7, 200).unwrap();
    denied(
        CodeApproval::approve(
            "approval-1",
            candidate.digest(),
            &short_session,
            &context,
            400,
        ),
        Denied::Expired,
    );
    let approval = f.approval(&candidate);
    denied(
        approval.prepare_operation("context.decision.adopt", "op-1", &context),
        Denied::UnsupportedAction,
    );
    let op = approval
        .prepare_operation(ADOPT_CODE, "op-1", &context)
        .unwrap();
    assert_eq!(op.repository(), "repo:field");
    assert_eq!(op.reference(), "refs/heads/field-trial");
    assert_eq!(op.expected_head(), "a".repeat(40));
    assert_eq!(op.commit(), candidate.commit());
    assert_eq!(op.state(), OperationState::Prepared);
}

#[test]
fn approval_refuses_changed_candidate_target_authority_or_policy_at_dispatch() {
    let f = Fixture::new();
    let candidate = f.candidate();
    let approval = f.approval(&candidate);
    for (owner, repository, reference, head, revision, writable) in [
        (
            "owner-1",
            "repo:field",
            "refs/heads/field-trial",
            "b",
            3,
            true,
        ),
        (
            "owner-1",
            "repo:other",
            "refs/heads/field-trial",
            "a",
            3,
            true,
        ),
        ("owner-1", "repo:field", "refs/heads/other", "a", 3, true),
        (
            "owner-1",
            "repo:field",
            "refs/heads/field-trial",
            "a",
            4,
            true,
        ),
        (
            "owner-1",
            "repo:field",
            "refs/heads/field-trial",
            "a",
            3,
            false,
        ),
    ] {
        let target = CodeTarget::from_authority(
            owner,
            repository,
            reference,
            &head.repeat(40),
            revision,
            writable,
        )
        .unwrap();
        let env = f.env(140);
        let mut context = f.context(&candidate, &env);
        context.target = &target;
        denied(
            approval.prepare_operation(ADOPT_CODE, "op-1", &context),
            Denied::StaleTarget,
        );
    }
    let mut other_input = candidate_input();
    other_input.commit = "f".repeat(40);
    let other = f
        .guard(110)
        .unwrap()
        .prepare_candidate(other_input)
        .unwrap()
        .confirm(f.guard(120).unwrap())
        .unwrap();
    denied(
        approval.prepare_operation(ADOPT_CODE, "op-1", &f.context(&other, &f.env(140))),
        Denied::ReviewMismatch,
    );
    for (epoch, active, policy, now, expected) in [
        (8, true, 11, 140, Denied::StaleAuthority),
        (7, false, 11, 140, Denied::InactiveOwner),
        (7, true, 12, 140, Denied::StalePolicy),
        (7, true, 11, 400, Denied::Expired),
    ] {
        let state = OwnerState::from_authority("owner-1", epoch, active).unwrap();
        let env = Environment {
            owner: &state,
            policy_revision: policy,
            now,
        };
        let mut operation = approval
            .prepare_operation(ADOPT_CODE, "op-1", &f.context(&candidate, &f.env(130)))
            .unwrap();
        denied(
            approval.dispatch(&mut operation, &f.context(&candidate, &env)),
            expected,
        );
        assert_eq!(operation.state(), OperationState::Prepared);
    }
}

#[test]
fn revocation_invalidates_old_approval_but_fresh_owner_can_adopt_retained_candidate() {
    let mut f = Fixture::new();
    let candidate = f.candidate();
    let old = f.approval(&candidate);
    let mut operation = old
        .prepare_operation(ADOPT_CODE, "op-old", &f.context(&candidate, &f.env(130)))
        .unwrap();
    f.grant.revoke().unwrap();
    f.run.revoke().unwrap();
    denied(
        old.dispatch(&mut operation, &f.context(&candidate, &f.env(140))),
        Denied::StaleAuthority,
    );
    let env = f.env(610);
    let context = f.context(&candidate, &env);
    let fresh = CodeApproval::approve(
        "approval-fresh",
        candidate.digest(),
        &f.session,
        &context,
        700,
    )
    .unwrap();
    let mut operation = fresh
        .prepare_operation(ADOPT_CODE, "op-fresh", &context)
        .unwrap();
    fresh.dispatch(&mut operation, &context).unwrap();
    assert_eq!(operation.state(), OperationState::Dispatched);
    assert!(f.grant.is_revoked());
    assert!(f.run.is_revoked());
}

#[test]
fn revoked_approval_cannot_dispatch_and_other_approval_cannot_take_over_operation() {
    let f = Fixture::new();
    let candidate = f.candidate();
    let env = f.env(130);
    let context = f.context(&candidate, &env);
    let mut approval = f.approval(&candidate);
    let mut operation = approval
        .prepare_operation(ADOPT_CODE, "op-1", &context)
        .unwrap();
    let other = CodeApproval::approve(
        "other-approval",
        candidate.digest(),
        &f.session,
        &context,
        400,
    )
    .unwrap();
    denied(other.dispatch(&mut operation, &context), Denied::Conflict);
    approval.revoke().unwrap();
    denied(approval.dispatch(&mut operation, &context), Denied::Revoked);
    assert_eq!(operation.state(), OperationState::Prepared);
}

#[test]
fn dispatched_unknown_effect_is_reconciled_after_revocation_without_redispatch() {
    let mut f = Fixture::new();
    let candidate = f.candidate();
    let mut approval = f.approval(&candidate);
    let mut operation = approval
        .prepare_operation(ADOPT_CODE, "op-1", &f.context(&candidate, &f.env(130)))
        .unwrap();
    denied(
        operation.confirm_applied("receipt-1"),
        Denied::InvalidTransition,
    );
    denied(operation.mark_outcome_unknown(), Denied::InvalidTransition);
    approval
        .dispatch(&mut operation, &f.context(&candidate, &f.env(140)))
        .unwrap();
    operation.mark_outcome_unknown().unwrap();
    operation.mark_outcome_unknown().unwrap();
    assert_eq!(operation.state(), OperationState::OutcomeUnknown);
    denied(
        approval.dispatch(&mut operation, &f.context(&candidate, &f.env(150))),
        Denied::InvalidTransition,
    );
    denied(operation.cancel_undispatched(), Denied::InvalidTransition);
    approval.revoke().unwrap();
    f.grant.revoke().unwrap();
    f.run.revoke().unwrap();
    operation.confirm_applied("receipt-1").unwrap();
    operation.confirm_applied("receipt-1").unwrap();
    assert_eq!(operation.state(), OperationState::Applied);
    assert_eq!(operation.receipt(), Some("receipt-1"));
    denied(
        operation.confirm_applied("different-receipt"),
        Denied::Conflict,
    );
    denied(operation.confirm_rejected("receipt-1"), Denied::Conflict);
}

#[test]
fn cancellation_and_confirmed_rejection_have_distinct_terminal_outcomes() {
    let f = Fixture::new();
    let candidate = f.candidate();
    let approval = f.approval(&candidate);
    let env = f.env(130);
    let context = f.context(&candidate, &env);
    let mut cancelled = approval
        .prepare_operation(ADOPT_CODE, "op-cancel", &context)
        .unwrap();
    cancelled.cancel_undispatched().unwrap();
    cancelled.cancel_undispatched().unwrap();
    assert_eq!(cancelled.state(), OperationState::Cancelled);
    denied(
        approval.dispatch(&mut cancelled, &context),
        Denied::InvalidTransition,
    );
    denied(
        cancelled.confirm_applied("receipt-1"),
        Denied::InvalidTransition,
    );
    let mut rejected = approval
        .prepare_operation(ADOPT_CODE, "op-reject", &context)
        .unwrap();
    approval.dispatch(&mut rejected, &context).unwrap();
    rejected.confirm_rejected("ref-conflict-1").unwrap();
    rejected.confirm_rejected("ref-conflict-1").unwrap();
    assert_eq!(rejected.state(), OperationState::Rejected);
    denied(rejected.confirm_applied("receipt-1"), Denied::Conflict);
}
