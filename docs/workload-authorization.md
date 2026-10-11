# Workload authorization with AuthZEN and ABAC

**Status:** Proposal and applicability review, 2026-10-06, supporting [ADR 0016](adr/0016-personal-context-and-workload-delegation.md). No new PDP, policy engine or workload endpoint is implemented here.

The first [domain contract](workload-profile-v1.md) implements typed rules for bounded proposal submission and exact human code adoption. Current main integration qualifies the portable Rust rules. OP-owned D1 conditional transitions, atomic approval consumption, audit rollback and concurrent dispatch were exercised in the retained pre-main Worker fixture and must be requalified against main's fresh schema under the [integration plan](work-delegation-implementation.md). AuthZEN HTTP, cryptographic actor verification, product ingress and the remaining actions are separate integration gates.

## Recommendation and existing fit

Use an attribute-based decision model inside the authoritative Mikaki operation handlers first. Use AuthZEN's information model for a common internal decision contract, and introduce its HTTP interface when independent enforcement services need shared policy decisions. A separate remote policy engine is not necessary for the initial owner/run/grant checks.

The existing [Rust owner evaluator](../crates/worker/src/vault_authzen.rs) already uses subject, action and resource structures and permits an authenticated owner for an explicit set of Vault operations. It is an owner matcher, not a general workload ABAC engine or an externally interoperable PDP. The [OpenID/OAuth priorities](oidc-standards-priorities.md) recommend internal decision vectors before external PDP adoption. This proposal follows that sequence and preserves [ADR 0012](adr/0012-vault-protocol-boundaries.md) and [ADR 0015](adr/0015-service-data-ownership.md).

## What the standards contribute

[AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html), published 2026-01-11 as OpenID Final, exchanges decision queries between enforcement and decision services. Requests contain subject, action and resource, with optional context; responses carry a boolean decision and optional context. It also specifies batch evaluation, search and metadata facilities. Policy language and state management are outside its scope. Response-context meanings, including reasons or obligations, require an implementation profile.

[NIST SP 800-162](https://csrc.nist.gov/pubs/sp/800/162/upd2/final) defines ABAC as evaluating subject, object, operation and environmental attributes against policy. [SP 800-205](https://csrc.nist.gov/pubs/sp/800/205/final) addresses attribute considerations and authoritative attribute management. ABAC is a decision method, not a credential format or a transport protocol.

The rest of this document proposes Mikaki-specific semantics; it is not part of those standards.

| Mechanism | Responsibility in this proposal |
| --- | --- |
| Wallet/Passkey or workload credential | Authenticate a principal or verify requested identity evidence under its own trust model. |
| Owner consent and authoritative grant | Establish bounded, revocable permission and selected disclosure. |
| OAuth/RAR | Describe requested rights and issue resource-bound delegated tokens under the selected profile. |
| ABAC rules | Decide whether current verified attributes satisfy this operation's constraints. |
| AuthZEN-shaped interface | Carry the decision query/result between qualified enforcement and evaluation components. |
| Domain transaction and external dispatcher | Commit the authorized effect/audit intent with current guards, then reconcile any external operation. |
| Encryption/key custody | Determine whether approved ciphertext can actually be decrypted or proof material used. |

## Logical roles and ownership

- **PEP:** The service receiving a supported operation: Token Exchange, task-repository provisioning, context release, proposal submission, adoption or credential-use adapter. It authenticates the caller and constructs the decision input from verified records. The frontend is a preview client, not an enforcement authority.
- **PDP:** A local evaluator initially, potentially a qualified shared service later. It evaluates a documented action and attribute profile without creating consent, changing grants or committing the operation.
- **Attribute sources:** Existing authentication, grant, run, repository, snapshot and approval authorities. They expose bounded verified facts; a policy service does not receive generic database access.
- **Policy administration:** An authorized operation selects immutable policy revisions and records their adoption. Agent-editable policy files are proposals until adopted by that authority. There is no second independently editable grant/ACL ledger in the PDP.

Changing evaluation placement does not transfer mutation authority. Keep the current local Vault checks where they belong; do not require unrelated owner operations to depend on a new remote PDP. The same decision vectors should exercise any future evaluator/adapters before migration.

## Attributes and provenance

For a workload-originated operation, the subject is the acting instance, mapped from validated actor identity and run registration. The owner is a separately verified delegation principal; do not use token `sub` alone as though the person directly performed the workload's request. Owner adoption has a human subject. Any service executing the approved effect is separately authenticated and recorded as executor.

| Attribute group | Examples | Authoritative source and freshness |
| --- | --- | --- |
| Actor and instance | Logical workload ID, run ID/revision, registered proof key, launcher issuer and assurance mode | Accepted workload credential, validated proof and current run registry. Owner enrollment and platform attestation remain distinct modes. |
| Owner and delegation | Owner reference, account state/epoch, grant ID/revision, operations, expiry, target/destination | Current owner/grant authority. Signed token claims are bound to these records and cannot replace their revocation checks. |
| Resource | Internal repository ID, owner/project, task versus upstream role, immutable snapshot/commit, expected head | Authorized internal destination mapping and resource authority. Labels copied from an agent's request or a modified repo file are not authoritative. |
| Disclosure | Approved input snapshot, allowed recipients/destinations, actual reachable files/history | Adopted selection manifest and current disclosure/grant association. No body or credential presentation is sent just to evaluate access. |
| Approval | Reviewed candidate digest, expected upstream state, allowed effect, approval revision/expiry | Exact owner-approved operation. A successful policy evaluation cannot set these fields to approved. |
| Environment | Server time, active policy revision, runtime/credential-use limits | Service clock, selected policy authority and qualified runtime counters. Limits must be reserved atomically when consumed. |
| Optional identity evidence | Minimal required qualification, issuer and verified freshness/status | Qualified Wallet/verifier result only when a named resource requires it. Ordinary repo work does not require legal name, address or a government-document presentation. |

Each security-relevant attribute needs an issuer/source, authenticated subject/resource binding, type, validity interval or revision, and missing/stale-value rule. The PEP/PDP trust contract determines which component may assert each fact. Treat request hints as candidates to resolve, not facts; reject conflict with verified state. A cryptographically valid self-entered label does not gain issuer assurance.

The owner-to-run-to-target relationships remain references to authoritative grant and registration records. ABAC can evaluate them alongside attributes; it does not require duplicating them into another relationship database. Fixed grant limits remain an upper bound even if a broad role or attribute policy would otherwise permit more.

## Proposed evaluation shape

This synthetic query illustrates the information model. Its type/action/property names are proposed Mikaki vocabulary. It is constructed by an authenticated PEP; it is not an API accepting self-asserted identity or grant properties from an agent.

```json
{
  "subject": {
    "type": "mikaki-workload-instance",
    "id": "run:example-42",
    "properties": {
      "logical_workload_id": "workload:example-agent",
      "proof_key_thumbprint": "example-public-key-thumbprint",
      "assurance_mode": "managed-launcher"
    }
  },
  "action": {
    "name": "repo.proposal.submit"
  },
  "resource": {
    "type": "mikaki-task-repository",
    "id": "task-repo:example-42",
    "properties": {
      "owner_ref": "owner:example",
      "role": "task"
    }
  },
  "context": {
    "profile": "mikaki_workload_authorization_v1",
    "owner_ref": "owner:example",
    "grant_id": "grant:example-42",
    "grant_revision": 3,
    "run_revision": 1,
    "policy_revision": 2,
    "input_snapshot": "snapshot:example-42",
    "candidate_commit": "example-candidate-commit",
    "request_digest": "example-operation-digest",
    "now": "2026-10-06T12:00:00Z"
  }
}
```

The evaluator resolves or validates these references against the trusted snapshot/attribute inputs. An illustrative response is `{"decision": false, "context": {"reason_code": "grant_expired"}}`. The reason code is a Mikaki extension, not an AuthZEN-defined value. It is safe to expose only when the caller is entitled to know the grant. A decision response is not a portable access credential.

## Rules for the first workload slice

Default to deny for unknown actions, incomplete bindings, required attributes that are missing/stale, untrusted issuers or unsupported profile versions. For workload-originated operations, an allow is the intersection of current owner authority, approved grant scope, this run's authority, the exact resource/operation, disclosure restrictions and active policy. None of these inputs can broaden another's permission.

| Operation candidate | Required predicates in addition to authentication |
| --- | --- |
| `workload.token.exchange` | Enrolled actor and permitted OAuth requester/exchange; owner/grant/run live; requested audience and operations within the grant; proof-key binding accepted. |
| `context.snapshot.release` | Exact selected snapshot and recipient/destination approved; disclosure grant still live; no unselected reachable history exposed. |
| `repo.task.provision` | Approved destination mapping and bounded task repository; quota reserved; any source fork readable under the disclosure grant. |
| `repo.git-token.issue` | Task repo is authorized; requested repo-wide read/write matches the full reachable contents and permitted operations; credential expiry/cleanup profile qualified. |
| `repo.proposal.submit` | Candidate belongs to the approved task destination; grant/run and input snapshot associations match; no upstream effect is implied. |
| `repo.change.adopt` | Exact owner adoption exists; candidate/expected upstream/request digest unchanged; current upstream write authority and approval remain valid. |
| `context.decision.adopt` | Owner selected this exact value and personal/project destination; context base revision unchanged; a code approval alone is insufficient. |

These actions are design candidates, not implemented API names. Checking a snapshot ID proves selection/association, not that the agent actually consulted every document or used no other information. Purpose descriptions explain consent; they are not cryptographic controls on reasoning.

Human adoption is a separate owner operation. Revocation of the producing run/grant stops its new operations, but need not prevent the owner from reviewing retained results and granting fresh exact adoption with current owner, target, policy and approval authority. Record the producer's provenance and revocation state without requiring its authority to become live again. An invalidated pending approval cannot be reused.

A general ABAC rule may restrict a workload by assurance mode or target classification, but cannot make a task-token path enforce a finer permission than the backend supports. Direct Artifacts Git remains repo-scoped bearer access. If a grant permits only broker-mediated proposal operations or narrower path/ref access, do not issue a direct write token that can perform additional repo-wide operations. Use a supported broker path or deny that provisioning mode.

## Decision freshness and operation commitment

An allow is valid only for its evaluated input and policy snapshot. Bind the decision internally to the principal, proof key, action, target/revision, grant/run/account/policy revisions and request digest. A remote PDP must satisfy the same freshness/provenance contract; an unqualified boolean from an arbitrary endpoint is insufficient. The AuthZEN wire shape does not supply a cross-service transaction or automatic freshness fencing.

The domain authority conditionally commits the operation or dispatch intent with the same live predicates and revisions. If a relevant revision changes, reevaluate or reject; do not continue using a cached allow. Audit and any quota reservation commit with that transition. Necessary transactional guards implement this operation contract, not a second independently editable policy ledger.

External dispatch and the Mikaki transaction have separate failure boundaries. Revocation rejects work that has not crossed the defined boundary; already dispatched/accepted effects may finish. Use the [ADR 0016 credential lifecycle](adr/0016-personal-context-and-workload-delegation.md#artifacts-authorization-boundary) for direct Git cleanup and measured revocation delay. A PDP cannot revoke a previously released bearer token or erase a delivered clone.

In the initial profile, do not reuse positive decisions across operations. Immutable metadata caching may be qualified separately, but cannot supply live grant/account/run/policy authorization. Do not reuse preview or search results as execution permission.

## Responses, UI and failure behavior

Expose safe reasons and next steps for the owner's work request, while preventing cross-owner resource existence leaks. A permission refusal, expired grant, missing approval and unavailable decision service should remain distinguishable to an authorized owner. Invalid identity/proof is an authentication failure; it is not converted into a policy allow or a weaker fallback.

Candidate owner-facing messages are "This permission expired — review and grant again", "This request has no permission for this repository — choose an authorized destination", "Your approval is required — review the exact change", and "Permission could not be checked right now — retry". Expose them only when that owner may know the referenced request/resource; other callers receive the visibility-safe response.

An optional response-context field must not be interpreted as executable instructions. For the first profile, represent unmet owner approval or required step-up as deny plus a profiled reason; perform a separate verified action and reevaluate. Do not return allow with an unenforced "obtain approval later" obligation. Unknown mandatory enforcement conditions fail closed.

When HTTP AuthZEN is introduced, authenticate and authorize each PEP, protect its transport and restrict its attribute-assertion/query powers. A timeout, malformed response, unavailable attribute source, profile mismatch or decision-service error produces no protected read or mutation. The user can see a retryable service error without presenting it as a permanent permission refusal. Do not expose a general PDP endpoint to agents merely to let them assert or enumerate other owners' subjects/resources.

Batch evaluation can reduce overhead for multiple independent checks, but does not make a multi-resource mutation atomic. Treat missing/errored entries as no authorization. Resource browsing must authorize each disclosed result and metadata field under the chosen visibility policy; pagination/counts/reasons must not reveal inaccessible resources. Defer AuthZEN search endpoints until a concrete browse workflow and privacy tests justify them.

## Qualification vectors and rollout

These are required design vectors, not tests reported as passing:

| Input or transition | Expected outcome |
| --- | --- |
| Valid registered run, live grant, exact task target and supported operation | Allow the bounded operation under the matching revisions. |
| Request supplies another owner, actor, grant or destination | Reject; use no caller-supplied ownership or trust facts. |
| Candidate, target head, selected snapshot or relevant policy changes after preview/evaluation | Reevaluate or reject before committing/dispatching. |
| Grant/account/run revoked or expired while token remains cryptographically valid | No new exchange or broker effect; reconcile outstanding direct credentials. |
| Workload key differs from DPoP confirmation or run registration | Authentication/binding failure, no policy fallback. |
| Required issuer, assurance or attribute provenance absent | Deny operations requiring that evidence; do not relabel owner enrollment as platform attestation. |
| Code adoption approved but saving a decision was not | Code effect only; no silent personal/project-context write. |
| Producer grant revoked; owner submits a new exact adoption after reviewing retained results | Evaluate current owner/target/approval authority independently; do not reactivate the producer or reuse invalidated approval. |
| Grant narrower than repo-wide Git token capabilities | Deny direct token issuance; use a qualified bounded broker mode if available. |
| PDP timeout/malformed response, missing batch result or policy-revision mismatch | No protected effect, with a safe service error for authorized callers. |
| Revocation after an external effect crossed dispatch boundary | Record/reconcile the actual outcome; no claim of recalled effect or data. |
| Agent modifies policy/labels in its task repo | Treat changes as proposals; effective policy and resource classification remain authoritative. |

First freeze the vocabulary, attribute sources, revision rules and side-effect boundary and exercise vectors in the existing local operation authority. Then use them in a real work request from ADR 0016. Add authenticated HTTP AuthZEN only for named independent PEPs, with an independent PDP/client interoperability probe and the same failure/race vectors. Evaluate policy engines against those contracts; no Rego, Cedar or XACML engine is selected here.

## Remaining decisions

- Which operation handlers need the same policy, and when does service separation justify a network PDP?
- Which minimal attribute/assurance vocabulary supports real external agents without requiring unnecessary identity evidence?
- How are policy revisions adopted, enforced during concurrent changes and recovered without restoring revoked authority?
- What exact client-authentication, issuer trust and attribute-assertion contract does a remote PDP support?
- Which browsing/search, batch evaluation and cache behavior improves the actual frontend without leaking data or weakening live authorization?

Applicability conclusion: AuthZEN fits the decision boundary and ABAC fits the run/grant/resource constraints. Their useful first application is a shared internal authorization contract grounded in existing authorities; external PDP interoperability is a later, separately qualified capability.
