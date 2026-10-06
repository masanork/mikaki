import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import type { OwnerVaultController } from '../../crates/worker/ui/vault-owner-controller.ts';
import { OwnerNameSharing } from '../../crates/worker/ui/vault-owner-name-sharing.ts';

const origin = 'https://mikaki.test';
const ownerId = 'owner';
const vaultId = 'vault';
const keyGeneration = 1;
const rootRevision = 4;
const now = Math.floor(Date.now() / 1000);
const recordBytes = randomBytes(48);
const ciphertext = recordBytes.toString('base64url');
const publicKey = randomBytes(1184);
const recipientKeyId = createHash('sha256').update(publicKey).digest('base64url');

function recipient() {
  return {
    service_id: 'userinfo',
    algorithm: 'ML-KEM-768',
    envelope_suite: 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-record-v2',
    key_id: recipientKeyId,
    public_key: publicKey.toString('base64url'),
    generation: 3,
    revision: 7,
  };
}

function response(value: unknown, status = 200, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', ...Object.fromEntries(new Headers(headers)) },
  });
}

function releaseClient(overrides: Record<string, unknown> = {}) {
  return {
    client_id: 'rp-one',
    sector_identifier: 'https://rp.example',
    client_revision: 2,
    connection_grant_version: 5,
    release_version: null,
    release_status: null,
    expires_at: null,
    source_storage_version: null,
    source_origin: null,
    source_vault_id: null,
    source_collection_id: null,
    source_record_id: null,
    source_kind: null,
    attribute_revision: null,
    source_ciphertext_sha256: null,
    source_key_generation: null,
    source_owner_key_revision: null,
    system_grant_version: null,
    authority_current: 0,
    ...overrides,
  };
}

function fixture() {
  let name = '保存済みの名前';
  let recordRevision = 9;
  let shareActive = true;
  let shareVersion = 6;
  let corruptGrantSource = false;
  let shareActiveAfterCommit: boolean | null = null;
  let releasesEnabled = true;
  let currentClients = [releaseClient()];
  let keyDirectoryAvailable = true;
  let staleOnPostDecryptCheck = false;
  let postDecryptChecks = 0;
  let openedPlaintext: Uint8Array<ArrayBuffer> | null = null;
  const requests: { path: string; method: string; headers: Headers; body: string }[] = [];
  let encryptions = 0;
  const digest = createHash('sha256').update(recordBytes).digest('base64url');
  const grant = () =>
    shareActive
      ? {
          storage_version: 2,
          owner_id: ownerId,
          vault_id: vaultId,
          origin,
          collection_id: 'personal',
          record_id: corruptGrantSource ? 'note' : 'name',
          kind: corruptGrantSource ? 'note' : 'name',
          record_revision: recordRevision,
          ciphertext_sha256: digest,
          key_generation: keyGeneration,
          owner_key_revision: rootRevision,
          version: shareVersion,
          status: 'active',
          expires_at: now + 3600,
          authority_current: 1,
          recipient_key_id: recipientKeyId,
          recipient_generation: 3,
          directory_revision: 7,
          policy_revision: 2,
        }
      : null;
  const scope = {
    request: async (path: string, init: RequestInit = {}) => {
      const method = init.method ?? 'GET';
      const headers = new Headers(init.headers);
      const body = typeof init.body === 'string' ? init.body : '';
      requests.push({ path, method, headers, body });
      if (path === '/vault/records/personal/name') {
        return response(
          {
            owner_id: ownerId,
            origin,
            vault_id: vaultId,
            key_generation: keyGeneration,
            owner_key_revision: rootRevision,
            format_version: 2,
            collection_id: 'personal',
            record_id: 'name',
            kind: 'name',
            revision: recordRevision,
            ciphertext,
            key_envelope: 'opaque-encrypted-record-key',
          },
          200,
          { ETag: `"${recordRevision}"` },
        );
      }
      if (path === '/vault/records/personal/name/sharing' && method === 'GET')
        return response({
          enabled: true,
          policy_revision: 2,
          grant_ttl_seconds: 604800,
          grant: grant(),
        });
      if (path === '/vault/records/personal/name/releases' && method === 'GET')
        return response({
          enabled: releasesEnabled,
          policy_revision: 4,
          ttl_seconds: 86400,
          clients: currentClients,
        });
      if (path === '/vault/records/personal/name/sharing' && method === 'POST') {
        shareActive = shareActiveAfterCommit ?? true;
        shareVersion++;
        return response({
          grant_version: shareVersion,
          record_revision: recordRevision,
          acknowledged: true,
        });
      }
      if (path === '/vault/records/personal/name/sharing' && method === 'DELETE') {
        shareActive = false;
        shareVersion++;
        return response({
          grant_version: shareVersion,
          record_revision: recordRevision,
          acknowledged: true,
        });
      }
      if (path === '/vault/records/personal/name/releases' && method === 'POST') {
        const input = JSON.parse(body) as { client_id: string; expected_release_version: number };
        const version = (input.expected_release_version || 0) + 1;
        currentClients = currentClients.map((client) =>
          client.client_id === input.client_id
            ? releaseClient({
                ...client,
                release_version: version,
                release_status: 'active',
                expires_at: now + 900,
                source_storage_version: 2,
                source_origin: origin,
                source_vault_id: vaultId,
                source_collection_id: 'personal',
                source_record_id: 'name',
                source_kind: 'name',
                attribute_revision: recordRevision,
                source_ciphertext_sha256: digest,
                source_key_generation: keyGeneration,
                source_owner_key_revision: rootRevision,
                system_grant_version: shareVersion,
                authority_current: 1,
              })
            : client,
        );
        return response({
          client_id: input.client_id,
          release_version: version,
          acknowledged: true,
        });
      }
      if (path === '/vault/records/personal/name/releases' && method === 'DELETE') {
        const input = JSON.parse(body) as { client_id: string };
        const existing = currentClients.find((client) => client.client_id === input.client_id)!;
        const version = Number(existing.release_version) + 1;
        currentClients = currentClients.map((client) =>
          client.client_id === input.client_id
            ? releaseClient({ ...client, release_version: version, release_status: 'revoked' })
            : client,
        );
        return response({
          client_id: input.client_id,
          release_version: version,
          acknowledged: true,
        });
      }
      return response({ error: 'not_found' }, 404);
    },
  };
  const stored = {
    context: { origin, ownerId, vaultId, keyGeneration },
    revision: rootRevision,
    envelope: { credential_id: 'AQ' },
  };
  const owner = {
    origin,
    scope,
    checkpoint: () => 1,
    assertCurrent: () => {
      if (staleOnPostDecryptCheck && openedPlaintext) {
        postDecryptChecks++;
        if (postDecryptChecks === 2) throw new DOMException('Stale Vault operation', 'AbortError');
      }
    },
    verifyAuthority: async () => {},
    lease: () => ({
      stored,
      session: {
        open: async () => {
          openedPlaintext = new TextEncoder().encode(name);
          return openedPlaintext;
        },
        sealUserInfoRecipient: async () => {
          encryptions++;
          return new Uint8Array([0x21, 0x22, 0x23]);
        },
      },
    }),
  } as unknown as OwnerVaultController;
  const sharing = new OwnerNameSharing(owner, {
    getItem: () => null,
    setItem: () => {},
  });
  return {
    sharing,
    requests,
    scope,
    get name() {
      return name;
    },
    set name(value: string) {
      name = value;
    },
    get recordRevision() {
      return recordRevision;
    },
    set recordRevision(value: number) {
      recordRevision = value;
    },
    get encryptions() {
      return encryptions;
    },
    set shareActive(value: boolean) {
      shareActive = value;
    },
    set corruptGrantSource(value: boolean) {
      corruptGrantSource = value;
    },
    set shareActiveAfterCommit(value: boolean | null) {
      shareActiveAfterCommit = value;
    },
    set releasesEnabled(value: boolean) {
      releasesEnabled = value;
    },
    set currentClients(value: ReturnType<typeof releaseClient>[]) {
      currentClients = value;
    },
    set keyDirectoryAvailable(value: boolean) {
      keyDirectoryAvailable = value;
    },
    set staleOnPostDecryptCheck(value: boolean) {
      staleOnPostDecryptCheck = value;
    },
    get openedPlaintext() {
      return openedPlaintext;
    },
    get keyDirectoryAvailable() {
      return keyDirectoryAvailable;
    },
  };
}

async function withRecipient<T>(run: () => Promise<T>) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    const current = activeFixture?.keyDirectoryAvailable;
    if (current === false) throw new TypeError('directory unavailable');
    return response(recipient());
  };
  try {
    return await run();
  } finally {
    globalThis.fetch = original;
    activeFixture = null;
  }
}

let activeFixture: ReturnType<typeof fixture> | null = null;
function usingFixture() {
  activeFixture = fixture();
  return activeFixture;
}

test('loads the saved encrypted name and reconciles a historical share receipt from fresh status', async () => {
  await withRecipient(async () => {
    const f = usingFixture();
    f.shareActiveAfterCommit = false;
    const initial = await f.sharing.load();
    assert.equal(initial.name, '保存済みの名前');
    assert.equal(initial.source.storage_version, 2);
    assert.equal(initial.source.record_id, 'name');
    assert.equal(initial.sharing.authorityCurrent, true);
    assert.equal(initial.releases.clients[0]!.eligible, true);
    assert.equal(initial.releases.clients[0]!.current, false);
    const operation = await f.sharing.prepareShare(initial);
    assert.equal(operation.action, 'share');
    const refreshed = await f.sharing.commit(operation);
    assert.equal(refreshed.sharing.grant, null);
    assert.equal(refreshed.sharing.authorityCurrent, false);
    const post = f.requests.find((request) => request.method === 'POST')!;
    assert.equal(post.headers.get('if-match'), '"9"');
    assert.equal(post.headers.get('x-operation-id'), operation.operationId);
    assert.equal(post.headers.get('content-type'), 'application/json');
    const sent = JSON.parse(post.body) as Record<string, unknown>;
    assert.equal(
      sent['source'] && (sent['source'] as Record<string, unknown>)['record_id'],
      'name',
    );
    assert.equal(sent['frame'], 'ISIj');
    assert.ok(!post.body.includes('保存済みの名前'));
    assert.ok(!post.body.includes('opaque-encrypted-record-key'));
    assert.equal(f.encryptions, 1);
  });
});

test('rejects a substituted source snapshot before encryption or mutation', async () => {
  await withRecipient(async () => {
    const f = usingFixture();
    const snapshot = await f.sharing.load();
    f.name = '別の名前';
    f.recordRevision++;
    const before = f.requests.filter((request) => request.method !== 'GET').length;
    await assert.rejects(
      f.sharing.prepareShare(snapshot),
      (error: unknown) => (error as { code?: string }).code === 'stale_snapshot',
    );
    assert.equal(f.encryptions, 0);
    assert.equal(f.requests.filter((request) => request.method !== 'GET').length, before);
  });
});

test('zeros decrypted name bytes if the owner session becomes stale before returning the snapshot', async () => {
  await withRecipient(async () => {
    const f = usingFixture();
    f.staleOnPostDecryptCheck = true;
    await assert.rejects(f.sharing.load(), { name: 'AbortError' });
    assert.ok(f.openedPlaintext);
    assert.ok(f.openedPlaintext!.every((byte) => byte === 0));
    assert.equal(
      f.requests.some((request) => request.method !== 'GET'),
      false,
    );
  });
});

test('keeps exact operation ID, body and fence after an unknown response, then reloads status', async () => {
  await withRecipient(async () => {
    const f = usingFixture();
    const snapshot = await f.sharing.load();
    const operation = await f.sharing.prepareShare(snapshot);
    const originalRequest = f.scope.request;
    let failOnce = true;
    const attempts: {
      path: string;
      method: string;
      operation: string | null;
      match: string | null;
      body: string;
    }[] = [];
    f.scope.request = async (path: string, init: RequestInit = {}) => {
      if (path === '/vault/records/personal/name/sharing' && init.method === 'POST') {
        const headers = new Headers(init.headers);
        attempts.push({
          path,
          method: init.method,
          operation: headers.get('x-operation-id'),
          match: headers.get('if-match'),
          body: String(init.body),
        });
        if (failOnce) {
          failOnce = false;
          throw new TypeError('response lost');
        }
      }
      return originalRequest(path, init);
    };
    await assert.rejects(f.sharing.commit(operation));
    const after = await f.sharing.commit(operation);
    assert.equal(after.sharing.grant?.status, 'active');
    const sent = f.requests.filter((entry) => entry.method === 'POST');
    assert.equal(sent.length, 1); // The first transport loss occurred before the Worker response.
    assert.deepEqual(attempts[0], attempts[1]);
    assert.equal(attempts[0]!.operation, operation.operationId);
    assert.equal(attempts[0]!.match, '"9"');
  });
});

test('pins the system-grant version for RP consent and the RP release version for withdrawal', async () => {
  await withRecipient(async () => {
    const f = usingFixture();
    const snapshot = await f.sharing.load();
    const grant = await f.sharing.prepareRelease(snapshot, 'rp-one');
    const afterGrant = await f.sharing.commit(grant);
    const releasePost = f.requests.find((request) => request.method === 'POST')!;
    assert.equal(releasePost.headers.get('if-match'), '"6"');
    assert.equal(JSON.parse(releasePost.body).expected_release_version, 0);
    assert.equal(afterGrant.releases.clients[0]!.release_version, 1);
    assert.equal(afterGrant.releases.clients[0]!.current, true);
    const revoke = await f.sharing.prepareRevokeRelease(afterGrant, 'rp-one');
    const afterRevoke = await f.sharing.commit(revoke);
    const releaseDelete = f.requests.find((request) => request.method === 'DELETE')!;
    assert.equal(releaseDelete.headers.get('if-match'), '"1"');
    assert.deepEqual(JSON.parse(releaseDelete.body), { client_id: 'rp-one' });
    assert.equal(afterRevoke.releases.clients[0]!.release_status, 'revoked');
  });
});

test('a definitive 4xx rejection retires the operation; a 5xx stays exact-retryable', async () => {
  await withRecipient(async () => {
    const f = usingFixture();
    const snapshot = await f.sharing.load();
    const rejected = await f.sharing.prepareShare(snapshot);
    const original = f.scope.request;
    f.scope.request = async (path, init) =>
      path === '/vault/records/personal/name/sharing' && init?.method === 'POST'
        ? response({ error: 'stale_source' }, 409)
        : original(path, init);
    await assert.rejects(
      f.sharing.commit(rejected),
      (error: unknown) => (error as { definitelyRejected?: boolean }).definitelyRejected === true,
    );
    await assert.rejects(
      f.sharing.commit(rejected),
      (error: unknown) => (error as { code?: string }).code === 'invalid_operation',
    );

    const retryable = await f.sharing.prepareShare(await f.sharing.load());
    let failOnce = true;
    f.scope.request = async (path, init) =>
      path === '/vault/records/personal/name/sharing' && init?.method === 'POST' && failOnce
        ? ((failOnce = false), response({ error: 'temporarily_unavailable' }, 503))
        : original(path, init);
    await assert.rejects(
      f.sharing.commit(retryable),
      (error: unknown) => (error as { definitelyRejected?: boolean }).definitelyRejected === false,
    );
    assert.equal((await f.sharing.commit(retryable)).sharing.grant?.status, 'active');
  });
});

test('accepts the full registered sector-identifier length', async () => {
  await withRecipient(async () => {
    const f = usingFixture();
    f.currentClients = [
      releaseClient({ sector_identifier: `https://${'a'.repeat(2032)}.example` }),
    ];
    const snapshot = await f.sharing.load();
    assert.equal(snapshot.releases.clients[0]!.sector_identifier.length, 2048);
    assert.equal(snapshot.releases.clients[0]!.eligible, true);
  });
});

test('does not mark an RP release current when its root authority tuple is stale', async () => {
  await withRecipient(async () => {
    const f = usingFixture();
    f.currentClients = [
      releaseClient({
        release_version: 3,
        release_status: 'active',
        expires_at: now + 600,
        source_storage_version: 2,
        source_origin: origin,
        source_vault_id: vaultId,
        source_collection_id: 'personal',
        source_record_id: 'name',
        source_kind: 'name',
        attribute_revision: 9,
        source_ciphertext_sha256: createHash('sha256').update(recordBytes).digest('base64url'),
        source_key_generation: keyGeneration,
        source_owner_key_revision: rootRevision + 1,
        system_grant_version: 6,
        authority_current: 1,
      }),
    ];
    const snapshot = await f.sharing.load();
    assert.equal(snapshot.releases.clients[0]!.eligible, true);
    assert.equal(snapshot.releases.clients[0]!.current, false);
  });
});

test('rejects a share grant whose returned source is not exactly the name record', async () => {
  await withRecipient(async () => {
    const f = usingFixture();
    f.corruptGrantSource = true;
    await assert.rejects(f.sharing.load());
    assert.equal(
      f.requests.some((request) => request.method !== 'GET'),
      false,
    );
  });
});

test('directory outage keeps revoke available but cannot authorize new RP release', async () => {
  await withRecipient(async () => {
    const f = usingFixture();
    f.keyDirectoryAvailable = false;
    const snapshot = await f.sharing.load();
    assert.equal(snapshot.recipient, null);
    assert.equal(snapshot.sharing.authorityCurrent, false);
    await assert.rejects(
      f.sharing.prepareRelease(snapshot, 'rp-one'),
      (error: unknown) => (error as { code?: string }).code === 'share_not_eligible',
    );
    const revoke = await f.sharing.prepareRevokeShare(snapshot);
    assert.equal(revoke.action, 'revoke-share');
  });
});
