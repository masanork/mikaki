use super::*;

fn denied<T>(result: Result<T, Denied>, expected: Denied) {
    assert_eq!(result.err(), Some(expected));
}

fn input() -> RequestInput {
    RequestInput {
        profile: PROFILE.into(),
        request_id: "request-1".into(),
        revision: 1,
        goal: "Fix the documented flow".into(),
        acceptance: "Docs checks pass".into(),
        code_repository: "repo:source".into(),
        base_commit: "a".repeat(40),
        disclosure_digest: "c".repeat(64),
        recipient: "launcher-client".into(),
        workload: "managed-agent".into(),
        task_repository: "repo:task".into(),
        adoption_repository: "repo:field".into(),
        adoption_ref: "refs/heads/field-trial".into(),
        expected_head: "a".repeat(40),
        operations: vec![SUBMIT.into()],
        deadline: 600,
    }
}

fn actor() -> ManagedActorFacts<'static> {
    ManagedActorFacts {
        issuer: "launcher-1",
        issuer_revision: 1,
        client: "launcher-client",
        workload: "managed-agent",
        run: "run-1",
        grant: "grant-1",
        proof_key: Digest::from_bytes([4; 32]),
        expires_at: 200,
    }
}

fn candidate_input() -> CandidateInput {
    CandidateInput {
        commit: "d".repeat(40),
        tree: "e".repeat(40),
        evidence: Digest::from_bytes([6; 32]),
    }
}

struct Fixture {
    owner: OwnerState,
    session: OwnerSession,
    request: WorkRequest,
    task: TaskRepository,
    actor: ManagedActor,
    grant: Grant,
    run: Run,
    target: CodeTarget,
}

impl Fixture {
    fn new() -> Self {
        let owner = OwnerState::from_authority("owner-1", 7, true).unwrap();
        let session = OwnerSession::from_verified_session("owner-1", 7, 1000).unwrap();
        let environment = Environment {
            owner: &owner,
            policy_revision: 11,
            now: 100,
        };
        let request = input().validate(&session, &environment).unwrap();
        let task = TaskRepository::from_authority(
            "owner-1",
            "repo:task",
            1,
            Digest::parse_hex(&"c".repeat(64)).unwrap(),
        )
        .unwrap();
        let grant = Grant::approve(
            "grant-1",
            &request,
            request.digest(),
            &session,
            &task,
            &environment,
        )
        .unwrap();
        let actor = ManagedActor::from_verified_request(actor()).unwrap();
        let run = Run::register(&actor, &grant, &request, &task, 500, &environment).unwrap();
        let target = CodeTarget::from_authority(
            "owner-1",
            "repo:field",
            "refs/heads/field-trial",
            &"a".repeat(40),
            3,
            true,
        )
        .unwrap();
        Self {
            owner,
            session,
            request,
            task,
            actor,
            grant,
            run,
            target,
        }
    }
    fn env(&self, now: u64) -> Environment<'_> {
        Environment {
            owner: &self.owner,
            policy_revision: 11,
            now,
        }
    }
    fn guard(&self, now: u64) -> Result<SubmissionGuard, Denied> {
        self.run.authorize_submission(
            SUBMIT,
            &self.grant,
            &self.request,
            &self.actor,
            &self.task,
            &self.env(now),
        )
    }
    fn candidate(&self) -> Candidate {
        self.guard(110)
            .unwrap()
            .prepare_candidate(candidate_input())
            .unwrap()
            .confirm(self.guard(120).unwrap())
            .unwrap()
    }
    fn context<'a>(
        &'a self,
        candidate: &'a Candidate,
        environment: &'a Environment<'a>,
    ) -> AdoptionContext<'a> {
        AdoptionContext {
            candidate,
            grant: &self.grant,
            run: &self.run,
            target: &self.target,
            environment,
        }
    }
    fn approval(&self, candidate: &Candidate) -> CodeApproval {
        CodeApproval::approve(
            "approval-1",
            candidate.digest(),
            &self.session,
            &self.context(candidate, &self.env(130)),
            400,
        )
        .unwrap()
    }
}

mod adoption;
mod delegation;
mod disclosure;
mod records;
mod request;
mod sources;
