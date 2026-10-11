use super::*;

#[test]
fn grant_requires_current_owner_exact_review_and_authoritative_task_disclosure() {
    let f = Fixture::new();
    denied(
        Grant::approve(
            "grant-2",
            &f.request,
            Digest::from_bytes([0; 32]),
            &f.session,
            &f.task,
            &f.env(100),
        ),
        Denied::ReviewMismatch,
    );
    for (owner, id, disclosure) in [
        ("other-owner", "repo:task", "c"),
        ("owner-1", "repo:other", "c"),
        ("owner-1", "repo:task", "d"),
    ] {
        let task = TaskRepository::from_authority(
            owner,
            id,
            1,
            Digest::parse_hex(&disclosure.repeat(64)).unwrap(),
        )
        .unwrap();
        denied(
            Grant::approve(
                "grant-2",
                &f.request,
                f.request.digest(),
                &f.session,
                &task,
                &f.env(100),
            ),
            Denied::BindingMismatch,
        );
    }
    let other = OwnerSession::from_verified_session("owner-2", 7, 1000).unwrap();
    denied(
        Grant::approve(
            "grant-2",
            &f.request,
            f.request.digest(),
            &other,
            &f.task,
            &f.env(100),
        ),
        Denied::OwnerMismatch,
    );
    denied(
        Grant::approve(
            "grant-2",
            &f.request,
            f.request.digest(),
            &f.session,
            &f.task,
            &f.env(1000),
        ),
        Denied::Expired,
    );
}

#[test]
fn workload_default_denies_non_submission_actions_and_actor_substitution() {
    let f = Fixture::new();
    assert!(f.guard(120).is_ok());
    for action in [
        "",
        "unknown",
        "repo.git-token.issue",
        "workload.token.exchange",
        "context.snapshot.release",
        ADOPT_CODE,
        "context.decision.adopt",
    ] {
        denied(
            f.run.authorize_submission(
                action,
                &f.grant,
                &f.request,
                &f.actor,
                &f.task,
                &f.env(120),
            ),
            Denied::UnsupportedAction,
        );
    }
    for field in [
        "issuer",
        "issuer_revision",
        "client",
        "workload",
        "run",
        "grant",
        "proof_key",
    ] {
        let mut facts = actor();
        match field {
            "issuer" => facts.issuer = "untrusted-launcher",
            "issuer_revision" => facts.issuer_revision = 2,
            "client" => facts.client = "other-client",
            "workload" => facts.workload = "other-workload",
            "run" => facts.run = "other-run",
            "grant" => facts.grant = "other-grant",
            "proof_key" => facts.proof_key = Digest::from_bytes([5; 32]),
            _ => unreachable!(),
        }
        let changed = ManagedActor::from_verified_request(facts).unwrap();
        denied(
            f.run.authorize_submission(
                SUBMIT,
                &f.grant,
                &f.request,
                &changed,
                &f.task,
                &f.env(120),
            ),
            Denied::BindingMismatch,
        );
    }
    let mut facts = actor();
    facts.issuer = "";
    denied(
        ManagedActor::from_verified_request(facts),
        Denied::InvalidInput,
    );
    let mut facts = actor();
    facts.issuer_revision = 0;
    denied(
        ManagedActor::from_verified_request(facts),
        Denied::InvalidInput,
    );
}

#[test]
fn revocation_and_all_live_expiry_boundaries_stop_new_work() {
    let mut f = Fixture::new();
    assert!(f.guard(199).is_ok());
    denied(f.guard(200), Denied::Expired);
    let mut facts = actor();
    facts.expires_at = 900;
    let refreshed = ManagedActor::from_verified_request(facts).unwrap();
    denied(
        f.run.authorize_submission(
            SUBMIT,
            &f.grant,
            &f.request,
            &refreshed,
            &f.task,
            &f.env(500),
        ),
        Denied::Expired,
    );
    denied(
        Run::register(&refreshed, &f.grant, &f.request, &f.task, 601, &f.env(120)),
        Denied::Expired,
    );
    f.grant.revoke().unwrap();
    let revision = f.grant.revision();
    f.grant.revoke().unwrap();
    assert_eq!(f.grant.revision(), revision);
    denied(f.guard(120), Denied::Revoked);
    denied(
        Run::register(&f.actor, &f.grant, &f.request, &f.task, 500, &f.env(120)),
        Denied::Revoked,
    );
    let mut f = Fixture::new();
    f.run.revoke().unwrap();
    denied(f.guard(120), Denied::Revoked);
    assert!(!f.grant.is_revoked());
    for (epoch, active, expected) in [
        (8, true, Denied::StaleAuthority),
        (7, false, Denied::InactiveOwner),
    ] {
        let state = OwnerState::from_authority("owner-1", epoch, active).unwrap();
        let env = Environment {
            owner: &state,
            policy_revision: 11,
            now: 120,
        };
        denied(
            f.run
                .authorize_submission(SUBMIT, &f.grant, &f.request, &f.actor, &f.task, &env),
            expected,
        );
    }
}

#[test]
fn edited_request_policy_and_resource_revision_cannot_reuse_grant() {
    let f = Fixture::new();
    let mut edited = input();
    edited.revision = 2;
    edited.goal.push_str(" and publish");
    let edited = edited.validate(&f.session, &f.env(120)).unwrap();
    denied(
        f.run
            .authorize_submission(SUBMIT, &f.grant, &edited, &f.actor, &f.task, &f.env(120)),
        Denied::StaleRequest,
    );
    let env = Environment {
        owner: &f.owner,
        policy_revision: 12,
        now: 120,
    };
    denied(
        f.run
            .authorize_submission(SUBMIT, &f.grant, &f.request, &f.actor, &f.task, &env),
        Denied::StalePolicy,
    );
    let task = TaskRepository::from_authority(
        "owner-1",
        "repo:task",
        2,
        Digest::parse_hex(&"c".repeat(64)).unwrap(),
    )
    .unwrap();
    denied(
        f.run
            .authorize_submission(SUBMIT, &f.grant, &f.request, &f.actor, &task, &f.env(120)),
        Denied::StaleTarget,
    );
}

#[test]
fn prepared_candidate_requires_same_fresh_read_set_and_exact_git_objects() {
    let f = Fixture::new();
    let prepared = f
        .guard(110)
        .unwrap()
        .prepare_candidate(candidate_input())
        .unwrap();
    let mut facts = actor();
    facts.expires_at = 201;
    let actor = ManagedActor::from_verified_request(facts).unwrap();
    let changed = f
        .run
        .authorize_submission(SUBMIT, &f.grant, &f.request, &actor, &f.task, &f.env(120))
        .unwrap();
    denied(prepared.confirm(changed), Denied::StaleAuthority);
    let first = f.candidate();
    let mut other = candidate_input();
    other.tree = "f".repeat(40);
    let second = f
        .guard(110)
        .unwrap()
        .prepare_candidate(other)
        .unwrap()
        .confirm(f.guard(120).unwrap())
        .unwrap();
    assert_ne!(first.digest(), second.digest());
    assert_eq!(first.commit(), "d".repeat(40));
    assert_eq!(first.tree(), "e".repeat(40));
    for commit in ["short".into(), "D".repeat(40), "d".repeat(64)] {
        let mut value = candidate_input();
        value.commit = commit;
        denied(
            f.guard(110).unwrap().prepare_candidate(value),
            Denied::InvalidInput,
        );
    }
}
