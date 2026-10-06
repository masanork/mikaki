import assert from 'node:assert/strict';
import { test } from 'node:test';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import {
  OwnerNoteProposals,
  OwnerNoteProposalError,
} from '../../crates/worker/ui/vault-owner-note-proposals.ts';
import { encodeOwnerNote, newOwnerNote } from '../../crates/worker/ui/vault-note.ts';
import { encodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';
import type { OwnerVaultController } from '../../crates/worker/ui/vault-owner-controller.ts';

const opaque = () => encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
const context = {
  origin: 'https://mikaki.test',
  ownerId: 'owner',
  vaultId: 'vault',
  keyGeneration: 1,
};
const authority = { key_generation: 1, owner_key_revision: 1 };
const target = {
  storage_version: 2,
  origin: context.origin,
  owner_id: 'owner',
  vault_id: 'vault',
  collection_id: 'personal',
  record_id: 'owner_note',
  kind: 'owner_note',
  revision: 0,
  ciphertext_sha256: null,
  deleted: false,
};

async function fixture(
  options: {
    unknownField?: boolean;
    decisionStatus?: number;
    revokedHistory?: boolean;
    existingPrepared?: boolean;
  } = {},
) {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const keyId = await agentKeyId(publicJwk);
  const grantId = opaque(),
    proposalId = opaque(),
    requestHash = opaque(),
    expires = Math.floor(Date.now() / 1000) + 600;
  const payload = new TextDecoder().decode(
    encodeOwnerNote(newOwnerNote('Suggestion', 'Untrusted proposal text')),
  );
  const existingOperation = options.existingPrepared ? opaque() : null;
  const existingCandidate = options.existingPrepared
    ? JSON.stringify({
        format_version: 2,
        vault_id: context.vaultId,
        key_generation: 1,
        owner_key_revision: 1,
        kind: 'owner_note',
        revision: 1,
        ciphertext: opaque(),
        key_envelope: opaque(),
      })
    : null;
  const proposal: Record<string, unknown> = {
    proposal_id: proposalId,
    grant_id: grantId,
    grant_revision: 1,
    request_hash: requestHash,
    attribute_id: 'owner_note',
    base_revision: 0,
    payload,
    expires_at: expires,
    created_at: expires - 60,
    state: options.existingPrepared ? 'approved' : 'pending',
    storage_version: 2,
    target_origin: target.origin,
    target_vault_id: target.vault_id,
    target_collection_id: target.collection_id,
    target_record_id: target.record_id,
    target_kind: target.kind,
    target_ciphertext_sha256: null,
    target_deleted: 0,
    target_key_generation: 1,
    target_owner_key_revision: 1,
    delegate: 'writer',
    provider: 'test-provider',
    operation_id: existingOperation,
    candidate: existingCandidate,
    result_revision: null,
    target,
    authority,
    destination: 'owner-vault-record',
    untrusted_content: true,
  };
  if (options.unknownField) proposal.surprise = true;
  const grant = {
    grant_id: grantId,
    account_id: 'owner',
    delegate: 'writer',
    provider: 'test-provider',
    resource: 'https://agent.test/mcp',
    source_revision: 1,
    operations: '["read","propose","execute"]',
    document_ids: '["name"]',
    created_at: expires - 600,
    expires_at: expires + 3600,
    revoked: 0,
    revision: 1,
    recipient_key_id: keyId,
    storage_version: 2,
    source_origin: context.origin,
    source_vault_id: context.vaultId,
    source_collection_id: 'personal',
    source_record_id: 'name',
    source_kind: 'name',
    source_ciphertext_sha256: opaque(),
    source_key_generation: 1,
    source_owner_key_revision: 1,
    active: 1,
  };
  const historyGrant = {
    ...grant,
    grant_id: opaque(),
    revoked: 1,
    active: 0,
    expires_at: expires - 1,
  };
  let decisionCalls = 0;
  const bodies: string[] = [];
  const paths: string[] = [];
  let statusValue: Record<string, unknown> = {
    grants: options.revokedHistory ? [grant, historyGrant] : [grant],
    audit: [],
    proposals: [],
    drafts: [],
    storage_version: 2,
    record_proposals: [proposal],
    recipient: { public_jwk: publicJwk, key_id: keyId, resource: grant.resource, enabled: true },
  };
  let generation = 0;
  const scope = {
    identity: { account_id: 'owner', credential_id: opaque() },
    signal: new AbortController().signal,
    request: async (path: string, init?: RequestInit) => {
      paths.push(path);
      if (path === '/vault/records/personal/owner_note')
        return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 });
      if (path === '/vault/agents/record-status') return new Response(JSON.stringify(statusValue));
      if (path === '/vault/agents/record-decide') {
        const body = String(init?.body ?? '');
        bodies.push(body);
        decisionCalls++;
        if (options.decisionStatus)
          return new Response(JSON.stringify({ error: 'stale_proposal' }), {
            status: options.decisionStatus,
          });
        if (decisionCalls === 1)
          return new Response(JSON.stringify({ error: 'temporary' }), { status: 503 });
        const input = JSON.parse(body) as { approve: boolean };
        proposal.state = input.approve ? 'approved' : 'rejected';
        if (!input.approve) proposal.payload = null;
        statusValue = { ...statusValue, record_proposals: [proposal] };
        return new Response(
          JSON.stringify({
            proposal_id: proposalId,
            request_hash: requestHash,
            state: proposal.state,
            target,
            authority,
            expires_at: expires,
            destination: 'owner-vault-record',
            untrusted_content: true,
          }),
        );
      }
      if (path === '/vault/records/personal/owner_note/approved')
        return new Response(JSON.stringify({ error: 'revision_conflict' }), { status: 409 });
      throw new Error(`unexpected ${path}`);
    },
    assert: () => {},
    verify: async () => {},
    ensure: async () => {},
    end: () => {
      generation++;
    },
  };
  const owner = {
    scope,
    checkpoint: () => generation,
    assertCurrent: (value: number) => {
      if (value !== generation) throw new DOMException('stale', 'AbortError');
    },
    verifyAuthority: async () => {},
    lease: () => ({
      stored: { context, revision: 1 },
      session: { open: async () => new TextEncoder().encode(payload) },
    }),
  } as unknown as OwnerVaultController;
  return {
    helper: new OwnerNoteProposals(owner),
    proposalId,
    bodies,
    paths,
    get status() {
      return statusValue;
    },
    owner,
    setStatus(value: Record<string, unknown>) {
      statusValue = value;
    },
  };
}

test('loads the exact owner-note target and refuses unknown proposal fields', async () => {
  const f = await fixture();
  const snapshot = await f.helper.load();
  assert.equal(snapshot.head.revision, 0);
  assert.equal(snapshot.head.value, null);
  assert.equal(snapshot.proposals.length, 1);
  assert.equal(snapshot.proposals[0]!.value?.text, 'Untrusted proposal text');
  assert.equal(snapshot.proposals[0]!.targetCurrent, true);
  const bad = await fixture({ unknownField: true });
  await assert.rejects(
    bad.helper.load(),
    (error: unknown) => error instanceof OwnerNoteProposalError && error.code === 'invalid_status',
  );
});

test('keeps revoked v2 grant history visible without treating it as active authority', async () => {
  const f = await fixture({ revokedHistory: true });
  const snapshot = await f.helper.load();
  assert.equal(snapshot.grants.length, 2);
  assert.equal(snapshot.grants[0]!.active, true);
  assert.equal(snapshot.grants[1]!.active, false);
  assert.equal(snapshot.proposals[0]!.matchingGrantActive, true);
});

test('an uncertain decision retries the identical operation body and reconciles with fresh status', async () => {
  const f = await fixture();
  const snapshot = await f.helper.load();
  const operation = await f.helper.prepareDecision(snapshot, f.proposalId, true);
  await assert.rejects(
    f.helper.decide(operation),
    (error: unknown) => error instanceof OwnerNoteProposalError && !error.definitelyRejected,
  );
  const result = await f.helper.decide(operation);
  assert.equal(f.bodies.length, 2);
  assert.equal(f.bodies[0], f.bodies[1]);
  assert.equal(result.proposals[0]!.state, 'approved');
});

test('a definite decision rejection is identified without changing the pending proposal', async () => {
  const f = await fixture({ decisionStatus: 409 });
  const snapshot = await f.helper.load();
  const operation = await f.helper.prepareDecision(snapshot, f.proposalId, false);
  await assert.rejects(
    f.helper.decide(operation),
    (error: unknown) =>
      error instanceof OwnerNoteProposalError &&
      error.code === 'stale_proposal' &&
      error.definitelyRejected,
  );
});

test('recovery reuses a prepared candidate and skips the grant-fenced prepare endpoint', async () => {
  const f = await fixture({ existingPrepared: true });
  const snapshot = await f.helper.load();
  const operation = await f.helper.recoverCommit(snapshot, f.proposalId);
  assert.equal(
    operation.operationId,
    (snapshot.proposals[0] as { operation_id: string }).operation_id,
  );
  await assert.rejects(
    f.helper.commit(operation),
    (error: unknown) => error instanceof OwnerNoteProposalError && error.definitelyRejected,
  );
  assert.ok(!f.paths.includes('/vault/agents/record-prepare'));
  assert.equal(f.paths.at(-1), '/vault/records/personal/owner_note/approved');
});
