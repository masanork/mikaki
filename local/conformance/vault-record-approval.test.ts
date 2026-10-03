import assert from 'node:assert/strict';
import { createDecipheriv, createHash, privateDecrypt, constants } from 'node:crypto';
import { test } from 'node:test';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import {
  approvedRecordProofBinding,
  openApprovedRecordProof,
  sealApprovedRecordProof,
  type ApprovedRecordProofBinding,
} from '../../crates/worker/ui/agent-record-proof.ts';
import { parseApprovedRecordNote } from '../../crates/worker/ui/vault-record-approval.ts';
import {
  createOwnerKey,
  openOwnerRecord,
  sealApprovedOwnerRecord,
} from '../../crates/worker/ui/vault-owner-crypto.ts';
import {
  parseVaultRecordSource,
  vaultCiphertextDigest,
} from '../../crates/worker/ui/vault-record-source.ts';
import { OwnerKeySession } from '../../crates/worker/ui/vault-owner-session.ts';
import { VaultScope } from '../../crates/worker/ui/vault-lifecycle.ts';
import { encodeOwnerNote, newOwnerNote } from '../../crates/worker/ui/vault-note.ts';

const hash = (s: string) => createHash('sha256').update(s).digest('base64url');
const context = {
  origin: 'https://mikaki.example',
  ownerId: 'owner',
  vaultId: 'vault',
  keyGeneration: 1,
};
const authority = { key_generation: 1, owner_key_revision: 3 };
const payload = new TextDecoder().decode(
  encodeOwnerNote(newOwnerNote('Exact title', 'Exact approved note')),
);
const target = {
  storage_version: 2 as const,
  origin: context.origin,
  owner_id: 'owner',
  vault_id: 'vault',
  collection_id: 'personal' as const,
  record_id: 'owner_note' as const,
  kind: 'owner_note' as const,
  revision: 0,
  ciphertext_sha256: null,
  deleted: false,
};
const proposal = {
  proposal_id: hash('proposal'),
  request_hash: hash('request'),
  grant_id: hash('grant'),
  payload,
  expires_at: 1_900_000_000,
  target,
  authority,
};
const pairPromise = crypto.subtle.generateKey(
  {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  },
  true,
  ['encrypt', 'decrypt'],
);
async function receiver() {
  const pair = await pairPromise,
    public_jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return {
    pair,
    recipient: {
      public_jwk,
      key_id: await agentKeyId(public_jwk),
      resource: 'https://agent.example/mcp',
    },
  };
}
async function binding(): Promise<ApprovedRecordProofBinding> {
  const { recipient } = await receiver();
  return approvedRecordProofBinding({
    owner: 'owner',
    grant_id: proposal.grant_id,
    key_id: recipient.key_id,
    resource: recipient.resource,
    expires_at: proposal.expires_at,
    proposal_id: proposal.proposal_id,
    request_hash: proposal.request_hash,
    operation_id: hash('operation'),
    candidate_sha256: hash('candidate'),
    target,
    authority,
    candidate_source: parseVaultRecordSource({
      storage_version: 2,
      origin: target.origin,
      owner_id: target.owner_id,
      vault_id: target.vault_id,
      collection_id: target.collection_id,
      record_id: target.record_id,
      kind: target.kind,
      revision: 1,
      ciphertext_sha256: hash('ciphertext'),
    }),
  });
}
// Independent receiver uses Node RSA and GCM, without either product proof opener.
async function referenceOpen(
  proof: { wrapped_key: string; nonce: string; ciphertext: string },
  b: ApprovedRecordProofBinding,
) {
  const { pair } = await receiver();
  const der = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  const label = Buffer.from(JSON.stringify(['mikaki-approved-record-proof', 2, b]));
  const raw = privateDecrypt(
    {
      key: Buffer.from(der),
      format: 'der',
      type: 'pkcs8',
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
      oaepLabel: label,
    },
    Buffer.from(proof.wrapped_key, 'base64url'),
  );
  try {
    const data = Buffer.from(proof.ciphertext, 'base64url');
    const cipher = createDecipheriv('aes-256-gcm', raw, Buffer.from(proof.nonce, 'base64url'));
    cipher.setAAD(label);
    cipher.setAuthTag(data.subarray(-16));
    return Buffer.concat([cipher.update(data.subarray(0, -16)), cipher.final()]);
  } finally {
    raw.fill(0);
  }
}

async function selectedBinding() {
  const b = await binding();
  return b;
}

test('approved record producer emits only new candidate-key proof and independent receiver opens the exact canonical note', async () => {
  const { key } = await createOwnerKey(
    context,
    new Uint8Array([1]),
    new Uint8Array(32),
    new Uint8Array(32),
  );
  const { recipient, pair } = await receiver();
  const prepared = await sealApprovedOwnerRecord(
    proposal,
    hash('operation'),
    recipient,
    key,
    context,
  );
  const candidate = JSON.parse(prepared.candidate);
  assert.deepEqual(Object.keys(prepared), [
    'proposal_id',
    'request_hash',
    'operation_id',
    'candidate',
    'candidate_sha256',
    'proof',
  ]);
  assert.equal(hash(prepared.candidate), prepared.candidate_sha256);
  const source = parseVaultRecordSource({
    storage_version: 2,
    origin: target.origin,
    owner_id: target.owner_id,
    vault_id: target.vault_id,
    collection_id: target.collection_id,
    record_id: target.record_id,
    kind: target.kind,
    revision: 1,
    ciphertext_sha256: await vaultCiphertextDigest(candidate.ciphertext),
  });
  const b = approvedRecordProofBinding({
    ...(await selectedBinding()),
    candidate_sha256: prepared.candidate_sha256,
    candidate_source: source,
  });
  const contentKey = await referenceOpen(prepared.proof, b);
  const productKey = await openApprovedRecordProof(prepared.proof, pair.privateKey, b);
  try {
    assert.equal(contentKey.length, 32);
    assert.deepEqual(contentKey, Buffer.from(productKey));
    const lp = (...parts: string[]) =>
      Buffer.concat(
        parts.flatMap((part) => {
          const body = Buffer.from(part),
            n = Buffer.alloc(2);
          n.writeUInt16BE(body.length);
          return [n, body];
        }),
      );
    const body = Buffer.from(candidate.ciphertext, 'base64url');
    const cipher = createDecipheriv('aes-256-gcm', contentKey, body.subarray(1, 13));
    cipher.setAAD(
      lp(
        'mikaki-vault-record-content',
        '2',
        context.origin,
        'owner',
        'vault',
        'personal',
        'owner_note',
        'owner_note',
        '1',
      ),
    );
    cipher.setAuthTag(body.subarray(-16));
    const plaintext = Buffer.concat([cipher.update(body.subarray(13, -16)), cipher.final()]);
    try {
      assert.equal(plaintext.toString(), payload);
    } finally {
      plaintext.fill(0);
    }
    const reopened = await openOwnerRecord(
      { format_version: 2, ciphertext: candidate.ciphertext, key_envelope: candidate.key_envelope },
      key,
      context,
      { collectionId: 'personal', recordId: 'owner_note', kind: 'owner_note', revision: 1 },
    );
    try {
      assert.equal(new TextDecoder().decode(reopened), payload);
    } finally {
      reopened.fill(0);
    }
  } finally {
    contentKey.fill(0);
    productKey.fill(0);
  }
});

test('approved proof binds all authorization fields and cannot be relabeled as a snapshot', async () => {
  const { recipient, pair } = await receiver(),
    b = await selectedBinding(),
    raw = new Uint8Array(32).fill(9);
  const proof = await sealApprovedRecordProof(raw, recipient, b);
  for (const [field, value] of Object.entries({
    owner: 'other',
    grant_id: hash('other'),
    key_id: hash('other'),
    resource: 'https://other.example/mcp',
    expires_at: b.expires_at + 1,
    proposal_id: hash('other'),
    request_hash: hash('other'),
    operation_id: hash('other'),
    candidate_sha256: hash('other'),
    authority: { ...authority, owner_key_revision: 4 },
    target: { ...target, revision: 1, ciphertext_sha256: hash('old') },
    candidate_source: { ...b.candidate_source, ciphertext_sha256: hash('other') },
  })) {
    await assert.rejects(
      openApprovedRecordProof(proof, pair.privateKey, {
        ...b,
        [field]: value,
      } as ApprovedRecordProofBinding),
      field,
    );
  }
  await assert.rejects(
    openApprovedRecordProof({ ...proof, version: 1 } as never, pair.privateKey, b),
  );
  await assert.rejects(referenceOpen(proof, { ...b, request_hash: hash('other') }));
  assert.deepEqual(raw, new Uint8Array(32).fill(9));
});

test('proof producer snapshots caller key, recipient, and binding before asynchronous work', async () => {
  const { recipient: original, pair } = await receiver(),
    b = structuredClone(await selectedBinding());
  const recipient = structuredClone(original),
    raw = new Uint8Array(32).fill(7),
    expected = structuredClone(b);
  const pending = sealApprovedRecordProof(raw, recipient, b);
  raw.fill(0);
  recipient.resource = 'https://other.example/mcp';
  recipient.public_jwk.n = 'invalid';
  Object.assign(b.authority, { owner_key_revision: 999 });
  Object.assign(b.target, { revision: 99 });
  const proof = await pending,
    opened = await openApprovedRecordProof(proof, pair.privateKey, expected);
  try {
    assert.deepEqual(opened, new Uint8Array(32).fill(7));
  } finally {
    opened.fill(0);
  }
});

test('record approval retains exact owner-note schema and explicit tombstone semantics', () => {
  for (const changed of [
    { ...proposal, payload: payload + '\n' },
    { ...proposal, payload: '\uFEFF' + payload },
    { ...proposal, payload: payload.replace('"version":1', '"version":2') },
    { ...proposal, target: { ...target, revision: 0, deleted: true } },
    { ...proposal, target: { ...target, revision: 2, deleted: false } },
    { ...proposal, target: { ...target, collection_id: 'threads' } },
    { ...proposal, unknown: true },
  ])
    assert.throws(() => parseApprovedRecordNote(changed as typeof proposal));
  assert.equal(
    parseApprovedRecordNote({ ...proposal, target: { ...target, revision: 2, deleted: true } })
      .target.revision,
    2,
  );
});

test('owner operation clears temporary decryption material and fences a late approved result', async (t) => {
  const { recipient } = await receiver();
  const identity = { account_id: 'owner', credential_id: 'AQ', session_tag: 's'.repeat(43) };
  const scope = new VaultScope(
    () => {},
    undefined,
    undefined,
    async () => Response.json(identity),
  );
  scope.observe(identity);
  const session = new OwnerKeySession(scope, context);
  await session.initialize(async () => ({
    credentialId: new Uint8Array([1]),
    output: new Uint8Array(32),
  }));
  const decrypted: ArrayBuffer[] = [],
    decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  t.mock.method(crypto.subtle, 'decrypt', async (...args: Parameters<typeof decrypt>) => {
    const buffer = await decrypt(...args);
    decrypted.push(buffer);
    return buffer;
  });
  const pending = session.sealApprovedNote(proposal, hash('operation'), recipient);
  session.suspend();
  await assert.rejects(pending, /unavailable|stale/);
  assert.ok(decrypted.length >= 3);
  assert.ok(decrypted.every((buffer) => new Uint8Array(buffer).every((byte) => byte === 0)));
  for (const method of ['getKey', 'withKey', 'exportRoot', 'exportContentKey'])
    assert.equal(method in session, false);
  session.dispose();
});
