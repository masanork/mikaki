# Workload delegation design review

**Date:** 2026-10-06. Review of [ADR 0016](adr/0016-personal-context-and-workload-delegation.md) and the supporting [AuthZEN/ABAC proposal](workload-authorization.md).

## Scope and method

The designer and technical reviewer agents independently reviewed the initial ADR without changing files. The author incorporated their findings while researching AuthZEN and ABAC, then requested a targeted second review of both documents. This is a documentation review, not a security certification, implementation test or interoperability result.

## Findings and dispositions

| Review | Priority | Finding | Disposition in the revised design |
| --- | --- | --- | --- |
| Designer | High | A person's continuing context could become dependent on a destination project/task repository. | Separate personal, project and request context. Keep the personal source under owner control and independent of the destination; a private context repo remains a valid native source. |
| Designer | High | Consent did not sufficiently describe actual recipients/history or what revocation stops. | Show actual disclosed versions, reachable history, recipients/operators and operations. Distinguish revoked authority, pending credential cleanup, dispatched effects and already delivered copies. |
| Designer | Medium | Code adoption and saving decisions could be confused. | Make them separately selected, approved effects, each bound to its reviewed target/value. |
| Designer | Medium | Handoff could silently preserve suggestions or reuse secrets. | Select prior results explicitly, include adopted decisions and open questions, keep proposals labelled, and obtain fresh run authority without transferring old secrets. |
| Designer | Medium | External agents could be excluded or misrepresented by one attestation model. | Distinguish owner-enrolled and platform-verified assurance. Qualify the managed-run path first; define allowed operations for a later owner-enrolled path independently. |
| Designer | Medium | Accepted product direction and protocol proposals were hard to distinguish. | Split accepted principles from proposed architecture and protocol selection. |
| Technical reviewer | Medium | OAuth requester/client authentication could be conflated with actor verification. | Require a profile for client authentication, accepted actor tokens and issuer/audience/subject/key/run checks, plus permitted-exchange policy. Do not implicitly extend existing public-client Agent OAuth. |
| Technical reviewer | Medium | Lost initial Artifacts credentials might not be recoverable or safely revocable. | Probe recoverable token IDs/metadata and revocation latency. Stop provisioning when untracked credentials cannot be managed; cleanup/recreation is limited to untouched, unreleased disposable task repositories. |
| Technical reviewer | Low | An SVID could be treated as inherently identifying a Mikaki run. | Authenticate the SPIFFE ID, then separately map logical workload and run/key/grant associations. |
| Technical reviewer | Low | JWT actor and proof-binding notation could be mistaken for a complete profile. | Explain nested `act` representation and access-token `cnf.jkt`; keep the table conceptual rather than a wire schema. |
| Technical reviewer, second pass | Medium | Applying live producer grant/run checks to every operation could prevent fresh owner adoption after stopping an agent. | Limit the delegation intersection to workload-originated operations. Evaluate fresh owner adoption using current owner/target/policy/approval authority, record producer provenance, and never reactivate the producer or reuse invalidated approval. |

The author's placement decision retains repo-native ordinary context, as requested. Independence from a destination project does not require moving personal context back into Vault or creating a proprietary context database.

## AuthZEN and ABAC applicability

AuthZEN fits the authorization decision interface; ABAC fits instance, grant, target and current-state predicates. Adopt a shared internal vocabulary and decision vectors first. Introduce authenticated HTTP PDP access only when named independent enforcement services need shared decisions. The existing local Vault owner matcher is relevant implementation evidence, but does not establish workload ABAC or external AuthZEN interoperability.

The proposal preserves one authoritative grant/policy lifecycle, verified attribute provenance, current-state checks at operation commitment and separate external credential reconciliation. A decision result neither records owner consent nor supplies decryption keys, transaction atomicity or finer Git permissions than Artifacts supports.

## Targeted second review

The designer confirmed that the initial high-priority findings were addressed and found no product/UX defect that blocks the proposal. Two low-priority suggestions were incorporated: expandable disclosure summaries and safe owner-facing refusal/service-error wording tied to next steps.

The technical reviewer confirmed that the initial technical findings and standards/trust-boundary concerns were addressed. Its remaining medium-priority finding was the owner-adoption boundary above. After that separation was incorporated, the reviewer checked both documents again and confirmed that the ambiguity was resolved, with no additional findings.

This review cycle is complete. The documents can serve as the basis for selecting and qualifying the first implementation profile; the open implementation decisions and acceptance gates remain in force.

## Validation and remaining work

Documentation link/heading checks, whitespace checks, Mermaid parsing and JSON-example parsing passed for the revised documents. The qualification vectors in the authorization proposal are future acceptance requirements; they have not been exercised against a workload implementation.

Implementation still needs concrete client/actor profiles, transition ownership, attribute and policy revision contracts, launcher and credential custody, external dispatch boundaries and Artifacts token-lifecycle evidence. Canonical repository migration and external PDP adoption remain separately qualified proposals.
