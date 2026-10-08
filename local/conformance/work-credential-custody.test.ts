import assert from 'node:assert/strict';
import { createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { preparationFixture } from './support/work-preparation-fixture.ts';
import { gitFixture } from '../../scripts/work-git-fixture.ts';
import { prepareGitDisclosure } from '../../scripts/work-git-disclosure.ts';

const receipt = '3'.repeat(64);
type Role = 'task' | 'snapshot';
type Purpose = 'initial' | 'upload' | 'readback';
type AttemptRow = {
  body: string;
  observation: string;
  envelope: string | null;
  key_version: number | null;
  nonce: string | null;
  state: string;
  revision: number;
};

async function fixture(throughMigration?: string) {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-custody-'));
  const keys = [randomBytes(32), randomBytes(32), randomBytes(32)];
  const bindings = {
    WORK_CREDENTIAL_KEY_FLOOR: '1',
    ...Object.fromEntries(
      keys.map((k, i) => [`WORK_CREDENTIAL_KEY_V${i + 1}`, k.toString('base64url')]),
    ),
  };
  let op = await preparationFixture(directory, bindings);
  try {
    const code = await gitFixture(directory, 'code', { 'README.md': 'Synthetic code\n' });
    const selected = await prepareGitDisclosure(
      { repository: 'code', gitDir: code.dir, commit: code.commit },
      [],
      directory,
      'snapshot',
    );
    const p = await op.initialize(selected.input, throughMigration);
    await op.call({ action: 'dispatch-preparation', id: p.id });
    if (!throughMigration) await op.call({ action: 'activate-credential-key' });
    const call: typeof op.call = (...args) => op.call(...args);
    async function row(id: string) {
      return (await op.DB.prepare(
        'SELECT body,observation,envelope,key_version,nonce,state,revision FROM work_credential_attempt WHERE attempt_id=?',
      )
        .bind(id)
        .first<AttemptRow>())!;
    }
    async function count(table: string) {
      return Number(await op.DB.prepare(`SELECT count(*) AS n FROM ${table}`).first('n'));
    }
    const reserve = (
      role: Role = 'task',
      purpose: Purpose = 'initial',
      status = 200,
      key_version = 1,
    ) =>
      call(
        {
          action: 'reserve-credential',
          key_version,
          credential: { preparation_id: p.id, role, purpose },
        },
        status,
      );
    const dispatch = (id: string, status = 200, key_version = 1) =>
      call({ action: 'dispatch-credential', id, key_version }, status);
    const capture = (
      id: string,
      role: Role = 'task',
      purpose: Purpose = 'initial',
      status = 200,
      extra: Record<string, unknown> = {},
      key_version = 1,
    ) =>
      call(
        {
          action: 'capture-credential',
          id,
          key_version,
          credential: {
            repo_id: `actual-${role}`,
            token_id: `token-${role}-${purpose}`,
            scope: purpose === 'readback' ? 'read' : 'write',
            expires_at: Math.floor(Date.now() / 1000) + 120,
            plaintext: `synthetic-secret-${role}-${purpose}`,
            ...extra,
          },
        },
        status,
      );
    const close = (id: string, confirmation = 'refused', status = 200) =>
      call({ action: 'credential-close', id, credential: { confirmation }, receipt }, status);
    return {
      p,
      keys,
      directory,
      call,
      row,
      count,
      reserve,
      dispatch,
      capture,
      close,
      get DB() {
        return op.DB;
      },
      get ownerRead() {
        return op.ownerRead;
      },
      async restart(overrides: Record<string, string> = {}) {
        await op.close();
        op = await preparationFixture(directory, { ...bindings, ...overrides });
      },
      async dispose() {
        await op.close();
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await op.close();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
function digestFields(domain: string, fields: (string | Buffer)[]) {
  const h = createHash('sha256');
  for (const value of [domain, ...fields]) {
    const bytes = typeof value === 'string' ? Buffer.from(value) : value;
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    h.update(length).update(bytes);
  }
  return h.digest();
}
function numberField(n: number) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

test('credential reservation and dispatch admit one winner; unknown result retains its slot and cleanup charge', async () => {
  const f = await fixture();
  try {
    const slots = await Promise.all(Array.from({ length: 6 }, () => f.reserve()));
    assert.equal(new Set(slots.map((s) => s.id)).size, 1);
    const id = slots[0]!.id;
    const dispatches = await Promise.all(Array.from({ length: 6 }, () => f.dispatch(id)));
    assert.equal(dispatches.filter((d) => d.started).length, 1);
    await f.restart();
    assert.equal((await f.reserve()).id, id);
    assert.equal((await f.dispatch(id)).started, false);
    assert.equal(await f.count('work_credential_attempt'), 1);
    assert.equal(
      await f.DB.prepare(
        "SELECT sum(reserved_bytes) FROM work_credential_attempt WHERE state!='closed'",
      ).first('sum(reserved_bytes)'),
      8192,
    );
    assert.equal(
      await f.DB.prepare(
        "SELECT count(*) FROM work_audit WHERE action='credential.dispatch'",
      ).first('count(*)'),
      1,
    );
    await f.reserve('task', 'upload', 409);
    await f.call({ action: 'credential-custody-receipt', id: f.p.id }, 409);
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    await f.call({ action: 'cleaned-preparation', id: f.p.id, receipt }, 409);
    assert.equal((await f.row(id)).state, 'revocation_pending');
    await f.close(id, 'refused', 409);
    // Local fixture stands in for independently established non-issuance.
    await f.close(id, 'not_issued');
    assert.equal((await f.reserve()).state, 'closed');
    assert.equal((await f.dispatch(id)).started, false);
    await f.call({ action: 'cleaned-preparation', id: f.p.id, receipt });
  } finally {
    await f.dispose();
  }
});

test('native AES-GCM envelope matches independent Node decryption and survives OP restart without owner unlock', async () => {
  const f = await fixture();
  try {
    const a = await f.reserve();
    await f.dispatch(a.id);
    await f.capture(a.id);
    const stored = await f.row(a.id),
      e = JSON.parse(stored.envelope!).data;
    const digest = JSON.parse(stored.body).data.digest as string;
    const aad = digestFields('mikaki.work-credential-envelope.v1', [
      Buffer.from(digest, 'hex'),
      stored.observation,
      numberField(1),
      numberField(1),
    ]);
    const cipher = Buffer.from(e.ciphertext, 'base64url');
    const decrypt = createDecipheriv('aes-256-gcm', f.keys[0]!, Buffer.from(e.nonce, 'base64url'));
    decrypt.setAAD(aad);
    decrypt.setAuthTag(cipher.subarray(-16));
    assert.equal(
      Buffer.concat([decrypt.update(cipher.subarray(0, -16)), decrypt.final()]).toString(),
      'synthetic-secret-task-initial',
    );
    await f.call({ action: 'credential-cleanup-recovery', id: a.id }, 409);
    const review = await f.ownerRead(`/work/preparations/${f.p.id}`);
    const privateRows = await f.DB.prepare('SELECT * FROM work_credential_attempt').all();
    const audits = await f.DB.prepare('SELECT * FROM work_audit').all();
    assert.doesNotMatch(JSON.stringify([privateRows, audits, review.body]), /synthetic-secret/);
    assert.doesNotMatch(
      JSON.stringify(review.body),
      /token-task|ciphertext|credential_observation|key_version/,
    );
    await f.call({ action: 'credential-revoke', id: a.id });
    await f.DB.prepare('UPDATE account_security SET active=0').run();
    await f.restart();
    const recovered = await f.call({ action: 'credential-cleanup-recovery', id: a.id });
    assert.equal(
      recovered.digest,
      createHash('sha256').update('synthetic-secret-task-initial').digest('hex'),
    );
    await f.close(a.id);
    const closed = await f.row(a.id);
    assert.equal(closed.envelope, null);
    assert.equal(closed.nonce, stored.nonce);
    assert.equal(closed.key_version, 1);
    await f.restart();
    await f.call({ action: 'credential-cleanup-recovery', id: a.id }, 409);
    await f.capture(a.id, 'task', 'initial', 409);
    assert.equal(
      await f.DB.prepare(
        "SELECT coalesce(sum(reserved_bytes),0) FROM work_credential_attempt WHERE state!='closed'",
      ).first('coalesce(sum(reserved_bytes),0)'),
      0,
    );
  } finally {
    await f.dispose();
  }
});

test('cleanup and authority loss fence new dispatch but preserve late returned credential under missing creation policy', async () => {
  const f = await fixture();
  try {
    const task = await f.reserve(),
      snapshot = await f.reserve('snapshot');
    await f.dispatch(task.id);
    await f.DB.prepare("UPDATE work_source_head SET active=0 WHERE source_id='code'").run();
    await f.dispatch(snapshot.id, 409);
    assert.equal((await f.capture(task.id)).state, 'revocation_pending');
    await f.DB.prepare('UPDATE account_security SET epoch=epoch+1,active=0').run();
    await f.DB.prepare('UPDATE sso_session SET revoked=1').run();
    await f.DB.prepare('DELETE FROM work_credential_policy').run();
    await f.DB.prepare('DELETE FROM work_preparation_policy').run();
    await f.DB.prepare('DELETE FROM work_resource_policy').run();
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    assert.equal((await f.row(snapshot.id)).state, 'revocation_pending');
    await f.call({ action: 'credential-cleanup-recovery', id: task.id });
    await f.call({ action: 'cleaned-preparation', id: f.p.id, receipt }, 409);
    await f.close(task.id);
    await f.close(snapshot.id, 'not_issued');
    await f.call({ action: 'cleaned-preparation', id: f.p.id, receipt });
    assert.equal((await f.ownerRead(`/work/preparations/${f.p.id}`)).status, 401);
  } finally {
    await f.dispose();
  }
});

test('late capture after cleanup records revocation obligation and rejects destination substitutions', async () => {
  const f = await fixture();
  try {
    const task = await f.reserve(),
      snapshot = await f.reserve('snapshot');
    await f.dispatch(task.id);
    await f.dispatch(snapshot.id);
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    assert.equal((await f.capture(task.id)).state, 'revocation_pending');
    await f.capture(snapshot.id, 'snapshot', 'initial', 500, { repo_id: 'actual-task' });
    assert.equal((await f.row(snapshot.id)).observation, null);
    await f.capture(snapshot.id, 'snapshot', 'initial', 200, { plaintext: null });
    assert.equal((await f.row(snapshot.id)).envelope, null);
    await f.capture(task.id, 'task', 'initial', 409, { repo_id: 'substituted' });
    await f.capture(task.id, 'task', 'initial', 409, { plaintext: 'different-secret' });
    await f.close(task.id, 'not_issued', 409);
    await f.close(task.id);
    await f.close(snapshot.id);
    await f.call({ action: 'cleaned-preparation', id: f.p.id, receipt });
  } finally {
    await f.dispose();
  }
});

test('key rotation, retirement, external floor and altered secret fail closed without deleting obligations', async () => {
  const f = await fixture();
  try {
    const a = await f.reserve();
    await f.dispatch(a.id);
    await f.capture(a.id);
    await f.call({ action: 'credential-revoke', id: a.id });
    await f.call({ action: 'activate-credential-key', key_version: 2 });
    assert.equal(
      await f.DB.prepare('SELECT state FROM work_credential_key WHERE version=1').first('state'),
      'decrypt_only',
    );
    await f.call({ action: 'credential-cleanup-recovery', id: a.id });
    await f.reserve('snapshot', 'initial', 409);
    const b = await f.reserve('snapshot', 'initial', 200, 2);
    await f.dispatch(b.id, 409, 1);
    await f.call({ action: 'retire-credential-key', key_version: 1 }, 500);
    await f.restart({ WORK_CREDENTIAL_KEY_V1: randomBytes(32).toString('base64url') });
    await f.call({ action: 'credential-cleanup-recovery', id: a.id }, 409);
    await f.restart({ WORK_CREDENTIAL_KEY_FLOOR: '2' });
    await f.call({ action: 'credential-cleanup-recovery', id: a.id }, 409);
    const obligations = await f.call({ action: 'credential-attempts', id: f.p.id });
    assert.equal(
      obligations.attempts?.find((attempt) => attempt.id === a.id)?.state,
      'revocation_pending',
    );
    const handle = await f.call({ action: 'credential-cleanup-target', id: a.id });
    assert.equal(handle.repo_id, 'actual-task');
    assert.equal(handle.token_id, 'token-task-initial');
    assert.equal((await f.row(a.id)).state, 'revocation_pending');
    // A verified handle-based refusal can still be recorded without decryption.
    await f.close(a.id);
    await f.restart();
    await f.call({ action: 'retire-credential-key', key_version: 1 });
    await f.call({ action: 'activate-credential-key', key_version: 1 }, 409);
    await assert.rejects(
      f.DB.prepare("UPDATE work_credential_key SET state='active' WHERE version=1").run(),
    );
    await assert.rejects(f.DB.prepare('DELETE FROM work_credential_key WHERE version=1').run());
  } finally {
    await f.dispose();
  }
});

test('credential byte and retained-row budgets reject allocation; safety transitions remain atomic under audit failure', async () => {
  const f = await fixture();
  try {
    await f.DB.prepare(
      'UPDATE work_credential_policy SET bytes_per_owner=8192,bytes_total=8192',
    ).run();
    const a = await f.reserve();
    await f.dispatch(a.id);
    await f.reserve('snapshot', 'initial', 409);
    await f.DB.exec(
      "CREATE TRIGGER fail_capture BEFORE INSERT ON work_audit WHEN NEW.action='credential.capture' BEGIN SELECT RAISE(ABORT,'test audit failure'); END;",
    );
    await f.capture(a.id, 'task', 'initial', 500);
    assert.equal(await f.count('work_preparation_repository'), 0);
    assert.equal((await f.row(a.id)).state, 'dispatched');
    await f.DB.exec('DROP TRIGGER fail_capture');
    await f.capture(a.id);
    await f.DB.exec(
      "CREATE TRIGGER fail_cleanup BEFORE INSERT ON work_audit WHEN NEW.action='credential.revoke' BEGIN SELECT RAISE(ABORT,'test audit failure'); END;",
    );
    await f.call({ action: 'cleanup-preparation', id: f.p.id }, 500);
    assert.equal((await f.row(a.id)).state, 'captured');
    assert.equal(
      await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
        .bind(f.p.id)
        .first('state'),
      'dispatched',
    );
    await f.DB.exec('DROP TRIGGER fail_cleanup');
    await f.call({ action: 'credential-revoke', id: a.id });
    await f.DB.exec(
      "CREATE TRIGGER fail_close BEFORE INSERT ON work_audit WHEN NEW.action='credential.closed' BEGIN SELECT RAISE(ABORT,'test audit failure'); END;",
    );
    await f.close(a.id, 'refused', 500);
    assert.ok((await f.row(a.id)).envelope);
    await f.DB.exec('DROP TRIGGER fail_close');
    await f.close(a.id);
    await f.DB.prepare('UPDATE work_credential_policy SET retained_per_owner=1').run();
    await f.reserve('snapshot', 'initial', 409);
    await f.DB.prepare('UPDATE work_credential_policy SET retained_per_owner=96').run();
    await f.reserve('snapshot');
    assert.equal(await f.count('work_transition_guard'), 0);
  } finally {
    await f.dispose();
  }
});

test('all six known credentials must close before independently receipted preparation becomes productive', async () => {
  const f = await fixture();
  try {
    const evidence = {
      for_operation: f.p.id,
      task_repo_id: 'actual-task',
      snapshot_repo_id: 'actual-snapshot',
      payload_receipt: '1'.repeat(64),
      credential_receipt: '2'.repeat(64),
    };
    for (const role of ['task', 'snapshot'] as const) {
      for (const purpose of ['initial', 'upload', 'readback'] as const) {
        const a = await f.reserve(role, purpose);
        await f.dispatch(a.id);
        await f.capture(a.id, role, purpose);
        await f.call(
          { action: 'verify-preparation', id: f.p.id, preparation_evidence: evidence },
          409,
        );
        await f.call({ action: 'credential-revoke', id: a.id });
        await f.close(a.id);
        assert.equal((await f.reserve(role, purpose)).id, a.id);
      }
    }
    const aggregate = await f.call({ action: 'credential-custody-receipt', id: f.p.id });
    await f.call({ action: 'verify-preparation', id: f.p.id, preparation_evidence: evidence }, 409);
    evidence.credential_receipt = aggregate.digest;
    const records = (
      await f.DB.prepare(
        "SELECT body,observation,confirmation,receipt FROM work_credential_attempt WHERE state='closed' ORDER BY role,purpose",
      ).all<{ body: string; observation: string; confirmation: string; receipt: string }>()
    ).results;
    assert.equal(
      aggregate.digest,
      digestFields(
        'mikaki.work-credential-receipt.v1',
        records.flatMap((r) => [r.body, r.observation, r.confirmation, r.receipt]),
      ).toString('hex'),
    );
    assert.equal(
      (await f.call({ action: 'verify-preparation', id: f.p.id, preparation_evidence: evidence }))
        .state,
      'verified',
    );
    await f.call({ action: 'materialize-preparation', id: f.p.id });
    const review = (await f.ownerRead(`/work/preparations/${f.p.id}`)).body;
    assert.equal(
      ((review['record'] as Record<string, unknown>)['preparation'] as Record<string, unknown>)[
        'current_authority'
      ],
      true,
    );
    assert.equal(await f.count('work_prepared_task'), 1);
    await assert.rejects(
      f.DB.prepare(
        "UPDATE work_credential_attempt SET state='dispatched',revision=revision+1 WHERE role='task' AND purpose='initial'",
      ).run(),
    );
    await assert.rejects(f.DB.prepare('DELETE FROM work_credential_attempt').run());
    await assert.rejects(
      f.DB.prepare(
        "UPDATE work_preparation_repository SET repo_id='foreign' WHERE role='task'",
      ).run(),
    );
    await f.call({ action: 'cleanup-preparation', id: f.p.id });
    await f.call({ action: 'cleaned-preparation', id: f.p.id, receipt });
  } finally {
    await f.dispose();
  }
});

test('0007 retains all prior OP rows without credential backfill and rolls key rotation back on audit failure', async () => {
  const f = await fixture('0006');
  try {
    const tables = (
      await f.DB.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name",
      ).all<{ name: string }>()
    ).results.map((r) => r.name);
    const before = await Promise.all(
      tables.map((name) => f.DB.prepare(`SELECT * FROM ${name}`).all()),
    );
    const sql = await readFile(
      new URL(
        '../../crates/worker/work-migrations/0007_work_credential_custody.sql',
        import.meta.url,
      ),
      'utf8',
    );
    await f.DB.batch(splitSqlQuery(sql).map((s) => f.DB.prepare(s)));
    const after = await Promise.all(
      tables.map((name) => f.DB.prepare(`SELECT * FROM ${name}`).all()),
    );
    before.forEach((r, i) => assert.deepEqual(after[i]!.results, r.results, tables[i]));
    assert.equal(await f.count('work_credential_attempt'), 0);
    assert.equal(await f.count('work_credential_key'), 0);
    await f.call({ action: 'activate-credential-key' });
    await f.DB.exec(
      "CREATE TRIGGER fail_rotation BEFORE INSERT ON work_credential_key_audit WHEN NEW.version=2 BEGIN SELECT RAISE(ABORT,'test key audit failure'); END;",
    );
    await f.call({ action: 'activate-credential-key', key_version: 2 }, 500);
    assert.equal(
      await f.DB.prepare('SELECT state FROM work_credential_key WHERE version=1').first('state'),
      'active',
    );
    assert.equal(await f.count('work_credential_key'), 1);
    await f.DB.exec('DROP TRIGGER fail_rotation');
    await Promise.all(
      Array.from({ length: 4 }, () =>
        f.call({ action: 'activate-credential-key', key_version: 2 }),
      ),
    );
    assert.equal(await f.count('work_credential_key'), 2);
    assert.equal(await f.count('work_credential_key_audit'), 3);
  } finally {
    await f.dispose();
  }
});

test('captured dispatch SQL repeats primary authority, policy and exact active-key guards after native preflight', async () => {
  const dispatchSql = await readFile(
    new URL('../../crates/worker/sql/work/credential-dispatch.sql', import.meta.url),
    'utf8',
  );
  for (const fence of ['epoch', 'source', 'policy', 'budget', 'cleanup', 'key'] as const) {
    const f = await fixture();
    try {
      const a = await f.reserve();
      const fingerprint = await f.DB.prepare(
        'SELECT fingerprint FROM work_credential_key WHERE version=1',
      ).first<string>('fingerprint');
      if (fence === 'epoch') await f.DB.prepare('UPDATE account_security SET epoch=epoch+1').run();
      if (fence === 'source')
        await f.DB.prepare('UPDATE work_source_access SET access_revision=access_revision+1').run();
      if (fence === 'policy')
        await f.DB.prepare('UPDATE runtime_policy_active SET generation=generation+1').run();
      if (fence === 'budget') await f.DB.prepare('DELETE FROM work_resource_policy').run();
      if (fence === 'cleanup') await f.call({ action: 'cleanup-preparation', id: f.p.id });
      if (fence === 'key') await f.call({ action: 'activate-credential-key', key_version: 2 });
      const before = await f.row(a.id);
      const auditCount = await f.count('work_audit');
      const result = await f.DB.prepare(dispatchSql)
        .bind(a.id, 1, 1, fingerprint)
        .run()
        .catch(() => null);
      if (result) assert.equal(result.meta.changes, 0, fence);
      assert.deepEqual(await f.row(a.id), before, fence);
      assert.equal(await f.count('work_audit'), auditCount, fence);
    } finally {
      await f.dispose();
    }
  }
});

test('closed credential nonce tombstone prevents same-key reuse by another attempt', async () => {
  const f = await fixture();
  try {
    const a = await f.reserve();
    await f.dispatch(a.id);
    await f.capture(a.id);
    const sealed = await f.row(a.id);
    await f.call({ action: 'credential-revoke', id: a.id });
    await f.close(a.id);
    const b = await f.reserve('snapshot');
    await f.dispatch(b.id);
    const digest = JSON.parse((await f.row(b.id)).body).data.digest;
    const plan = JSON.parse(f.p.body).data.plan;
    const observation = JSON.stringify({
      version: 1,
      kind: 'credential_observation',
      data: {
        attempt_digest: digest,
        repo_id: 'actual-snapshot',
        token_id: 'other-token',
        scope: 'write',
        expires_at: null,
      },
    });
    const sql = await readFile(
      new URL('../../crates/worker/sql/work/credential-capture.sql', import.meta.url),
      'utf8',
    );
    // Use a structurally bound synthetic row to exercise the actual SQL nonce
    // constraint. Native AEAD independently rejects this ciphertext substitution.
    await assert.rejects(
      f.DB.batch([
        f.DB.prepare('INSERT INTO work_preparation_repository VALUES(?,?,?,?,?)').bind(
          f.p.id,
          'snapshot',
          plan.snapshot_namespace,
          plan.snapshot_name,
          'actual-snapshot',
        ),
        f.DB.prepare(sql).bind(b.id, 2, 'captured', observation, 1, sealed.envelope),
      ]),
      /UNIQUE constraint failed: work_credential_attempt.key_version, work_credential_attempt.nonce/,
    );
    assert.equal((await f.row(b.id)).state, 'dispatched');
    assert.equal(await f.count('work_preparation_repository'), 1);
    assert.equal((await f.row(a.id)).nonce, sealed.nonce);
  } finally {
    await f.dispose();
  }
});
