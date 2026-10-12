import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { preparationFixture } from './support/work-preparation-fixture.ts';
import type { FixtureRequestOptions } from './support/work-preparation-fixture.ts';
import { gitFixture } from '../../scripts/work-git-fixture.ts';
import { prepareGitDisclosure } from '../../scripts/work-git-disclosure.ts';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';

type Checkpoint = { authority: string; epoch: string; sequence: number; tip: string };
type Permit = { operation: string; previous: Checkpoint; next: Checkpoint };
type State = {
  checkpoint: Checkpoint;
  pending: Permit | null;
  last: Permit | null;
  release_floor: number;
  frozen: boolean;
};
const receipt = '3'.repeat(64);
async function fixture(
  enrolled = true,
  throughMigration?: string,
  sourceRead = false,
  product = false,
  workThroughMigration?: number,
) {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-checkpoint-'));
  const code = await gitFixture(directory, 'code', { 'README.md': 'Synthetic code\n' });
  const personal = sourceRead
    ? await gitFixture(directory, 'personal', { 'writing.md': 'SOURCE_CHECKPOINT_FIXTURE\n' })
    : null;
  const selected = await prepareGitDisclosure(
    { repository: 'code', gitDir: code.dir, commit: code.commit },
    personal
      ? [
          {
            repository: 'personal',
            gitDir: personal.dir,
            commit: personal.commit,
            paths: ['writing.md'],
          },
        ]
      : [],
    directory,
    'snapshot',
  );
  const bindings = {
    WORK_CREDENTIAL_KEY_FLOOR: '1',
    WORK_CREDENTIAL_KEY_V1: randomBytes(32).toString('base64url'),
    WORK_CREDENTIAL_KEY_V2: randomBytes(32).toString('base64url'),
    ...(sourceRead
      ? {
          WORK_SOURCE_API_ENABLED: 'true',
          LOCAL_CHECKPOINT_SOURCE_REPLY: JSON.stringify({
            format_version: 1,
            source_id: 'personal',
            source_revision: 1,
            commit: selected.input.contexts[0]!.commit,
            tree: selected.input.contexts[0]!.tree,
            files: selected.input.contexts[0]!.files.map(({ path, blob, content }) => ({
              path,
              blob,
              content,
            })),
          }),
        }
      : {}),
  };
  let op = await preparationFixture(
    directory,
    bindings,
    enrolled,
    false,
    undefined,
    undefined,
    product,
  );
  let stopped = false;
  try {
    const p = await op.initialize(selected.input, throughMigration, workThroughMigration);
    const plan = JSON.parse(p.body).data.plan;
    const request = {
      profile: 'mikaki-managed-work-v1',
      request_id: 'checkpoint-request',
      revision: 1,
      goal: 'Verify historical authority',
      acceptance: 'Review exact bytes',
      code_repository: 'code',
      base_commit: code.commit,
      disclosure_digest: plan.binding.disclosure,
      recipient: 'launcher-client',
      workload: 'managed-agent',
      task_repository: 'synthetic-task',
      adoption_repository: 'field',
      adoption_ref: 'refs/heads/trial',
      expected_head: code.commit,
      operations: ['repo.proposal.submit'],
      deadline: plan.binding.expires_at - 60,
    };
    async function checkpoint<T>(input: Record<string, unknown>, status = 200): Promise<T> {
      const r = await op.fixtureFetch('/checkpoint-fixture', input);
      assert.equal(r.status, status);
      return JSON.parse((await r.text()) || 'null') as T;
    }
    async function native<T>(input: Record<string, unknown>, status = 200): Promise<T> {
      const r = await op.fixtureFetch('/fixture', input);
      assert.equal(r.status, status);
      return r.json() as Promise<T>;
    }
    const current = () => native<Checkpoint>({ action: 'checkpoint-current' });
    const state = () => checkpoint<State>({ action: 'status', release: 1 });
    async function stop() {
      if (!stopped) {
        await op.close();
        stopped = true;
      }
    }
    async function restart(withCheckpoint = enrolled, pauseSource = false) {
      await stop();
      op = await preparationFixture(
        directory,
        { ...bindings, LOCAL_CHECKPOINT_SOURCE_PAUSE: pauseSource ? 'true' : 'false' },
        withCheckpoint,
        false,
        undefined,
        undefined,
        product,
      );
      stopped = false;
    }
    async function backup() {
      await stop();
      await cp(join(directory, 'op-state/d1'), join(directory, 'd1-backup'), { recursive: true });
      await restart();
    }
    async function restore() {
      await stop();
      await rm(join(directory, 'op-state/d1'), { recursive: true, force: true });
      await cp(join(directory, 'd1-backup'), join(directory, 'op-state/d1'), { recursive: true });
      await restart();
    }
    return {
      p,
      request,
      directory,
      native,
      checkpoint,
      current,
      state,
      stop,
      restart,
      backup,
      restore,
      admin: (input: Record<string, unknown>) => op.fixtureFetch('/authority-fixture', input),
      http: (path: string, options: FixtureRequestOptions = {}) => op.request(path, options),
      get DB() {
        return op.DB;
      },
      get call() {
        return op.call;
      },
      get ownerRead() {
        return op.ownerRead;
      },
      readSource: () =>
        op.fixtureFetch('/work/sources/read', {
          format_version: 1,
          source_id: 'personal',
          source_revision: 1,
          access_revision: 1,
          paths: ['writing.md'],
        }),
      productFetch: (path: string, options: FixtureRequestOptions = {}) =>
        op.productFetch(path, options),
      async close() {
        await stop();
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (e) {
    await op.close();
    await rm(directory, { recursive: true, force: true });
    throw e;
  }
}
async function sql(name: string) {
  return readFile(new URL(`../../crates/worker/sql/work/${name}.sql`, import.meta.url), 'utf8');
}
function step(f: Awaited<ReturnType<typeof fixture>>, p: Permit) {
  return f.DB.prepare(
    'UPDATE work_authority_checkpoint SET sequence=?,tip=? WHERE id=1 AND authority=? AND epoch=? AND sequence=? AND tip=?',
  ).bind(
    p.next.sequence,
    p.next.tip,
    p.previous.authority,
    p.previous.epoch,
    p.previous.sequence,
    p.previous.tip,
  );
}

async function prepareProductLogout(f: Awaited<ReturnType<typeof fixture>>) {
  const before = await f.productFetch('/logout', {
    headers: { Cookie: '__Host-op-sso=synthetic-delivery-session' },
  });
  assert.equal(before.status, 200, 'normal product Worker serves the logout confirmation');
  const html = await before.text();
  const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(csrf, 'logout confirmation includes its CSRF value');
  const cookieHeader = before.headers.get('set-cookie') ?? '';
  const logoutCookie = /__Host-op-logout=([^;,\s]+)/.exec(cookieHeader)?.[1];
  assert.ok(logoutCookie, 'logout confirmation sets its CSRF cookie');
  return () =>
    f.productFetch('/logout', {
      method: 'POST',
      headers: {
        Cookie: `__Host-op-sso=synthetic-delivery-session; __Host-op-logout=${logoutCookie}`,
        Origin: 'https://work.test',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ csrf }).toString(),
    });
}

async function productLogout(f: Awaited<ReturnType<typeof fixture>>) {
  return (await prepareProductLogout(f))();
}

async function seedLogoutClient(f: Awaited<ReturnType<typeof fixture>>) {
  await f.DB.batch([
    f.DB.prepare(
      "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('synthetic-logout-client',1,1,'https://rp.example.test')",
    ),
    f.DB.prepare('INSERT INTO app_connection VALUES(?,?,1,1)').bind(
      'synthetic-delivery-owner',
      'synthetic-logout-client',
    ),
    f.DB.prepare('INSERT INTO client_backchannel_logout_uri VALUES(?,?,1)').bind(
      'synthetic-logout-client',
      'https://rp.example.test/backchannel',
    ),
    f.DB.prepare('INSERT INTO client_session VALUES(?,?,?,?,?,1,0)').bind(
      'synthetic-logout-client',
      'synthetic-logout-sid',
      'delivery-sso',
      'synthetic-delivery-owner',
      'synthetic-logout-subject',
    ),
  ]);
}

async function logoutState(f: Awaited<ReturnType<typeof fixture>>) {
  return {
    revoked: await f.DB.prepare('SELECT revoked FROM sso_session WHERE sso_id=?')
      .bind('delivery-sso')
      .first('revoked'),
    transactions: (await f.DB.prepare('SELECT * FROM logout_transaction ORDER BY csrf_hash').all())
      .results,
    events: (await f.DB.prepare('SELECT * FROM sso_logout_event ORDER BY sso_id').all()).results,
    deliveries: (await f.DB.prepare('SELECT * FROM logout_delivery ORDER BY client_id,sid').all())
      .results,
    clients: (await f.DB.prepare('SELECT * FROM client_session ORDER BY client_id,sid').all())
      .results,
    guards: (await f.DB.prepare('SELECT * FROM atomic_guard ORDER BY operation_id').all()).results,
  };
}

test('private checkpoint follows actual work batches and survives independent OP/DO restart without public exposure', async () => {
  const f = await fixture();
  try {
    const before = await f.current();
    await f.call({ action: 'dispatch-preparation', id: f.p.id });
    const after = await f.current();
    assert.equal(after.sequence, before.sequence + 1);
    assert.notEqual(after.tip, before.tip);
    assert.equal(after.epoch, before.epoch);
    assert.deepEqual((await f.state()).checkpoint, after);
    await f.restart();
    assert.deepEqual(await f.current(), after);
    await f.call({ action: 'dispatch-preparation', id: f.p.id }); // Existing, never a second effect.
    assert.deepEqual(await f.current(), after);
    await f.checkpoint({ action: 'public' }, 404);
    const owner = await f.ownerRead(`/work/preparations/${f.p.id}`);
    assert.equal(owner.status, 200);
    for (const value of [after.epoch, after.tip, after.authority, 'release_floor', 'pending'])
      assert.equal(JSON.stringify(owner.body).includes(value), false);
    await assert.rejects(f.DB.prepare('DELETE FROM work_authority_checkpoint').run());
    await assert.rejects(
      f.DB.prepare('UPDATE work_authority_checkpoint SET sequence=sequence-1').run(),
    );
  } finally {
    await f.close();
  }
});

test('restoring the whole D1 backup cannot redispatch a credential closed after that backup', async () => {
  const f = await fixture();
  try {
    await f.call({ action: 'dispatch-preparation', id: f.p.id });
    await f.call({ action: 'activate-credential-key' });
    const attempt = await f.call({
      action: 'reserve-credential',
      credential: { preparation_id: f.p.id, role: 'task', purpose: 'initial' },
    });
    const old = await f.current();
    await f.backup();
    assert.equal((await f.call({ action: 'dispatch-credential', id: attempt.id })).started, true);
    await f.call({ action: 'credential-revoke', id: attempt.id });
    await f.call({
      action: 'credential-close',
      id: attempt.id,
      credential: { confirmation: 'not_issued' },
      receipt,
    });
    await f.call({ action: 'activate-credential-key', key_version: 2 });
    const retained = await f.current();
    assert.ok(retained.sequence > old.sequence);
    await f.restore();
    assert.equal((await f.call({ action: 'credential-status', id: attempt.id })).state, 'reserved');
    assert.deepEqual((await f.state()).checkpoint, retained);
    await f.native({ action: 'checkpoint-current' }, 409);
    await f.native({ action: 'checkpoint-reconcile' }, 409);
    await f.call({ action: 'dispatch-credential', id: attempt.id }, 409);
    assert.equal((await f.call({ action: 'credential-status', id: attempt.id })).state, 'reserved');
    assert.deepEqual((await f.state()).checkpoint, retained);
  } finally {
    await f.close();
  }
});

test('whole D1 rollback may expose historical active grants but cannot commit fresh producer authority', async () => {
  const f = await fixture();
  try {
    await f.call({ action: 'dispatch-preparation', id: f.p.id });
    await f.call({
      action: 'verify-preparation',
      id: f.p.id,
      preparation_evidence: {
        for_operation: f.p.id,
        task_repo_id: 'remote-code',
        snapshot_repo_id: 'remote-context',
        payload_receipt: '1'.repeat(64),
        credential_receipt: '2'.repeat(64),
      },
    });
    await f.call({ action: 'materialize-preparation', id: f.p.id });
    const request = await f.call({ action: 'prepared-request', request: f.request });
    await f.call({ action: 'grant', id: 'old-grant', digest: request.digest });
    await f.backup();
    await f.call({ action: 'revoke-grant', id: 'old-grant' });
    const sealed = await f.current();
    await f.restore();
    assert.equal(
      await f.DB.prepare("SELECT revoked FROM work_grant WHERE grant_id='old-grant'").first(
        'revoked',
      ),
      0,
    );
    await f.call({ action: 'grant', id: 'fresh-grant', digest: request.digest }, 409);
    await f.call({ action: 'grant', id: 'old-grant', digest: request.digest }, 409);
    assert.equal(
      await f.DB.prepare("SELECT count(*) AS n FROM work_grant WHERE grant_id='fresh-grant'").first(
        'n',
      ),
      0,
    );
    assert.deepEqual((await f.state()).checkpoint, sealed);
  } finally {
    await f.close();
  }
});

test('one durable pending intent blocks competitors and old-marker reconciliation without expiry or inference from absence', async () => {
  const f = await fixture();
  try {
    const expected = await f.current();
    const plans = await Promise.all(
      Array.from({ length: 4 }, () =>
        f.checkpoint<Permit>({ action: 'begin', release: 1, expected, operation: 'lost-intent' }),
      ),
    );
    plans.forEach((p) => assert.deepEqual(p, plans[0]));
    await f.checkpoint({ action: 'begin', release: 1, expected, operation: 'competitor' }, 409);
    await f.native({ action: 'dispatch-preparation', id: f.p.id }, 409);
    await f.restart();
    assert.deepEqual((await f.state()).pending, plans[0]);
    await f.native({ action: 'checkpoint-reconcile' }, 409);
    assert.deepEqual(
      await f.DB.prepare(
        'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint',
      ).first(),
      expected,
    );
    await f.checkpoint({ action: 'commit', release: 1, permit: plans[0], observed: expected }, 409);
    assert.deepEqual((await f.state()).pending, plans[0]);
    // A whole backup restored to this old marker has the same appearance. No
    // automatic abort, rebase, lease expiry or blank advancement is safe here.
    await f.checkpoint(
      {
        action: 'begin',
        release: 1,
        expected: { ...expected, authority: 'foreign' },
        operation: 'wrong-scope',
      },
      409,
    );
    await f.checkpoint({ action: 'status', release: 1, extra: 'unknown' }, 400);
  } finally {
    await f.close();
  }
});

test('a committed next marker reconciles a lost publication without replaying SQL; captured old CAS cannot commit', async () => {
  const f = await fixture();
  try {
    const expected = await f.current();
    const plan = await f.checkpoint<Permit>({
      action: 'begin',
      release: 1,
      expected,
      operation: 'committed-lost-reply',
    });
    const auditBefore = await f.DB.prepare('SELECT count(*) AS n FROM work_audit').first('n');
    await f.DB.batch([
      step(f, plan),
      f.DB.prepare(await sql('guard')).bind('captured-good'),
      f.DB.prepare("DELETE FROM work_transition_guard WHERE guard_id='captured-good'"),
    ]);
    await f.restart();
    assert.deepEqual(await f.native({ action: 'checkpoint-reconcile' }), plan.next);
    assert.deepEqual(await f.current(), plan.next);
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_audit').first('n'),
      auditBefore,
    );
    await assert.rejects(
      f.DB.batch([
        step(f, plan),
        f.DB.prepare(await sql('guard')).bind('captured-stale'),
        f.DB.prepare(
          'INSERT INTO work_audit(audit_id,owner_id,entity_type,entity_id,action,actor,revision) VALUES(?,?,?,?,?,?,?)',
        ).bind(
          'late-replay',
          'synthetic-delivery-owner',
          'preparation',
          f.p.id,
          'late-replay',
          'fixture',
          1,
        ),
      ]),
      /work_guard_passed/,
    );
    assert.equal(
      await f.DB.prepare("SELECT count(*) AS n FROM work_audit WHERE audit_id='late-replay'").first(
        'n',
      ),
      0,
    );
    await f.checkpoint({ action: 'commit', release: 1, permit: plan, observed: plan.next }); // Same current commit retry.
    assert.deepEqual(await f.current(), plan.next);
  } finally {
    await f.close();
  }
});

test('definitive audit abort rolls business state back while settling one empty checkpoint slot', async () => {
  const f = await fixture();
  try {
    const before = await f.current();
    const audits = await f.DB.prepare('SELECT count(*) AS n FROM work_audit').first('n');
    await f.DB.prepare(
      "CREATE TRIGGER fixture_checkpoint_audit_failure BEFORE INSERT ON work_audit BEGIN SELECT RAISE(ABORT,'fixture_checkpoint_audit_failure'); END",
    ).run();
    await f.native({ action: 'dispatch-preparation', id: f.p.id }, 500);
    assert.equal((await f.call({ action: 'get-preparation', id: f.p.id })).state, 'reserved');
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_audit').first('n'), audits);
    const after = await f.current();
    assert.equal(after.sequence, before.sequence + 1);
    assert.equal((await f.state()).pending, null);
    await f.DB.prepare('DROP TRIGGER fixture_checkpoint_audit_failure').run();
    assert.equal((await f.call({ action: 'dispatch-preparation', id: f.p.id })).started, true);
  } finally {
    await f.close();
  }
});

test('release floor, irreversible freeze, absent binding and one-time enrollment cannot silently reopen authority', async () => {
  const f = await fixture();
  try {
    const initial = await f.current();
    const cookie = { Cookie: '__Host-op-sso=synthetic-delivery-session' };
    assert.equal((await f.http('/work/session', { headers: cookie })).status, 200);
    await f.checkpoint(
      { action: 'bootstrap', checkpoint: { ...initial, sequence: 0 }, floor: 1 },
      409,
    );
    await f.restart(false);
    assert.equal((await f.http('/work/session', { headers: cookie })).status, 409);
    await f.call({ action: 'dispatch-preparation', id: f.p.id }, 409);
    await f.restart(true);
    assert.deepEqual(await f.current(), initial);
    await f.checkpoint({ action: 'raise-floor', floor: 2 });
    assert.equal((await f.http('/work/session', { headers: cookie })).status, 409);
    await f.checkpoint({ action: 'raise-floor', floor: 1 }, 409);
    await f.native({ action: 'checkpoint-current' }, 409);
    await f.call({ action: 'dispatch-preparation', id: f.p.id }, 409);
    await f.restart();
    await f.call({ action: 'dispatch-preparation', id: f.p.id }, 409);
    const state = await f.checkpoint<State>({ action: 'status', release: 2 });
    assert.equal(state.release_floor, 2);
    assert.deepEqual(state.checkpoint, initial);
    await f.checkpoint({ action: 'freeze' });
    await f.checkpoint({ action: 'status', release: 2 }, 409);
  } finally {
    await f.close();
  }
});

test('source plaintext release checks independent checkpoint before RPC and again after a pending intent appears during RPC', async () => {
  const f = await fixture(true, undefined, true);
  try {
    await f.DB.prepare(
      'CREATE TABLE fixture_source_reads(id INTEGER PRIMARY KEY,n INTEGER NOT NULL)',
    ).run();
    await f.DB.prepare('INSERT INTO fixture_source_reads VALUES(1,0)').run();
    const healthy = await f.readSource();
    assert.equal(healthy.status, 200);
    assert.ok((await healthy.text()).includes('SOURCE_CHECKPOINT_FIXTURE'));
    await f.restart(true, true);
    const pending = await f.readSource();
    assert.equal(pending.status, 409);
    assert.equal((await pending.text()).includes('SOURCE_CHECKPOINT_FIXTURE'), false);
    assert.equal(await f.DB.prepare('SELECT n FROM fixture_source_reads').first('n'), 2);
    const blocked = await f.readSource();
    assert.equal(blocked.status, 409);
    assert.equal(await f.DB.prepare('SELECT n FROM fixture_source_reads').first('n'), 2);
    assert.equal((await f.state()).pending!.operation, 'fixture-during-source-read');
  } finally {
    await f.close();
  }
});

test('0011 preserves all previous data and supplies no automatic authority enrollment', async () => {
  const f = await fixture(false, '0010');
  try {
    const names = (
      await f.DB.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name",
      ).all<{ name: string }>()
    ).results.map((r) => r.name);
    const before = await f.DB.batch(names.map((name) => f.DB.prepare(`SELECT * FROM ${name}`)));
    const migration = await readFile(
      new URL(
        '../../crates/worker/work-migrations/0011_work_authority_checkpoint.sql',
        import.meta.url,
      ),
      'utf8',
    );
    await f.DB.batch(splitSqlQuery(migration).map((s) => f.DB.prepare(s)));
    const after = await f.DB.batch(names.map((name) => f.DB.prepare(`SELECT * FROM ${name}`)));
    before.forEach((r, i) => assert.deepEqual(after[i]!.results, r.results, names[i]));
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
      0,
    );
    await f.native({ action: 'checkpoint-current' }, 409);
  } finally {
    await f.close();
  }
});

const auditMetadata = {
  actor: 'local-qualified-operator',
  reason: 'Synthetic authority restore qualification',
};
async function admin(
  f: Awaited<ReturnType<typeof fixture>>,
  input: Record<string, unknown>,
  status = 200,
) {
  const response = await f.admin({ ...auditMetadata, ...input });
  assert.equal(response.status, status);
  return response.json() as Promise<Record<string, unknown>>;
}
async function policy(f: Awaited<ReturnType<typeof fixture>>) {
  return f.DB.prepare(
    'SELECT projection_revision,generation FROM runtime_policy_active WHERE id=1',
  ).first<{ projection_revision: string; generation: number }>();
}
async function policyInput() {
  const original = JSON.parse(
    await readFile(new URL('../generated/worker-policy.json', import.meta.url), 'utf8'),
  );
  const { projection_revision: _, ...contents } = original;
  contents.access_token_ttl_seconds = original.access_token_ttl_seconds + 1;
  const canonical = Object.fromEntries(
    Object.entries(contents).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
  return {
    ...contents,
    projection_revision: (await import('node:crypto'))
      .createHash('sha256')
      .update(JSON.stringify(canonical), 'ascii')
      .digest('hex'),
  };
}

test('enrolled security tables reject unframed mutations and a frame cannot persist across transactions', async () => {
  const f = await fixture();
  try {
    const checkpoint = await f.current();
    const mutations = [
      'UPDATE account_security SET epoch=epoch+1',
      'UPDATE credential SET active=0',
      'UPDATE sso_session SET revoked=1',
      "UPDATE sso_context SET secret_hash='unframed'",
      "INSERT INTO passkey_credential VALUES('delivery-credential','synthetic-public-key','synthetic-handle',0,0,0,1)",
      "INSERT INTO account_role VALUES('synthetic-delivery-owner','admin',1)",
      'UPDATE runtime_policy_active SET generation=generation+1',
      "UPDATE runtime_policy_version SET projection_json='{}'",
      "UPDATE runtime_policy_audit SET reason='unframed'",
    ];
    for (const sql of mutations)
      await assert.rejects(f.DB.prepare(sql).run(), /work_checkpoint_guard_failed/);
    await assert.rejects(
      f.DB.prepare('INSERT INTO work_authority_frame VALUES(1,?,?,1)')
        .bind(checkpoint.sequence, checkpoint.tip)
        .run(),
      // workerd may mask deferred-FK failures at the direct D1 RPC boundary.
      // Verify rejection and the persisted state below instead of its message.
    );
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_authority_frame').first('n'),
      0,
    );
    const next = { ...checkpoint, sequence: checkpoint.sequence + 1, tip: 'c'.repeat(64) };
    // Even a correct leading CAS cannot commit if an adapter forgets to close its frame.
    await assert.rejects(
      f.DB.batch([
        step(f, { operation: 'unclosed-frame', previous: checkpoint, next }),
        f.DB.prepare('INSERT INTO work_authority_frame VALUES(1,?,?,1)').bind(
          next.sequence,
          next.tip,
        ),
        f.DB.prepare('UPDATE account_security SET active=0'),
      ]),
      // workerd may mask deferred-FK failures at the direct D1 RPC boundary.
      // Verify rejection and the persisted state below instead of its message.
    );
    assert.deepEqual(await f.current(), checkpoint);
    assert.equal(await f.DB.prepare('SELECT active FROM account_security').first('active'), 1);
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_authority_frame').first('n'),
      0,
    );
    await f.checkpoint({ action: 'public-admin-rpc' }, 404);
    await f.checkpoint({ action: 'named-admin-raw-rpc' }, 404);
  } finally {
    await f.close();
  }
});

test('account epoch and credential disablement advance the independent floor and survive historical D1 restore', async () => {
  for (const change of [
    { action: 'revoke-account', account: 'synthetic-delivery-owner', expected_epoch: 0 },
    {
      action: 'disable-credential',
      account: 'synthetic-delivery-owner',
      credential: 'delivery-credential',
    },
  ]) {
    const f = await fixture(true, undefined, true);
    try {
      const before = await f.current();
      await f.backup();
      await admin(f, change);
      const retained = await f.current();
      assert.equal(retained.sequence, before.sequence + 1);
      assert.equal(
        await f.DB.prepare('SELECT count(*) AS n FROM op_authority_audit').first('n'),
        1,
      );
      await f.restore();
      assert.equal(await f.DB.prepare('SELECT active FROM account_security').first('active'), 1);
      assert.equal(await f.DB.prepare('SELECT active FROM credential').first('active'), 1);
      await f.native({ action: 'checkpoint-current' }, 409);
      await admin(f, change, 409);
      assert.equal((await f.readSource()).status, 409);
      assert.deepEqual((await f.state()).checkpoint, retained);
      assert.equal(
        await f.DB.prepare('SELECT count(*) AS n FROM op_authority_audit').first('n'),
        0,
      );
    } finally {
      await f.close();
    }
  }
});

test('actual product logout frames revocation and cannot succeed again from the pre-logout D1 backup', async () => {
  const f = await fixture(true, undefined, true);
  try {
    const cookie = '__Host-op-sso=synthetic-delivery-session';
    const initial = await f.http('/logout', { headers: { Cookie: cookie } });
    assert.equal(initial.status, 200);
    const html = await initial.text();
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)![1];
    const logoutCookie = /__Host-op-logout=([^; ,]+)/.exec(initial.headers.get('set-cookie')!)![1];
    const confirm = () =>
      f.http('/logout', {
        method: 'POST',
        headers: {
          Cookie: `${cookie}; __Host-op-logout=${logoutCookie}`,
          Origin: 'https://work.test',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ csrf }).toString(),
      });
    const before = await f.current();
    await f.backup();
    assert.equal((await confirm()).status, 200);
    const retained = await f.current();
    assert.equal(retained.sequence, before.sequence + 1);
    assert.equal(await f.DB.prepare('SELECT revoked FROM sso_session').first('revoked'), 1);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM sso_logout_event').first('n'), 1);
    await f.restore();
    assert.equal(await f.DB.prepare('SELECT revoked FROM sso_session').first('revoked'), 0);
    assert.equal((await confirm()).status, 400);
    assert.equal((await f.readSource()).status, 409);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM sso_logout_event').first('n'), 0);
    assert.deepEqual((await f.state()).checkpoint, retained);
  } finally {
    await f.close();
  }
});

test('enrolled policy CLI uses the fixed native admin binding; historical policy cannot reactivate after whole D1 restore', async () => {
  const f = await fixture(true, undefined, true);
  try {
    const original = (await policy(f))!;
    const candidate = await policyInput();
    await assert.rejects(
      activateWorkerPolicy(f.DB, candidate, {
        ...auditMetadata,
        expectedRevision: original.projection_revision,
      }),
      /OP_AUTHORITY_ADMIN/,
    );
    assert.deepEqual(await policy(f), original);
    const before = await f.current();
    await f.backup();
    const result = await activateWorkerPolicy(f.DB, candidate, {
      ...auditMetadata,
      expectedRevision: original.projection_revision,
      administrator: {
        fetch: async (request) => f.admin((await request.json()) as Record<string, unknown>),
      },
    });
    assert.equal(result.generation, original.generation + 1);
    const retained = await f.current();
    assert.equal(retained.sequence, before.sequence + 1);
    const audit = await f.DB.prepare(
      'SELECT previous_revision,projection_revision FROM runtime_policy_audit WHERE generation=?',
    )
      .bind(result.generation)
      .first();
    assert.deepEqual(audit, {
      previous_revision: original.projection_revision,
      projection_revision: candidate.projection_revision,
    });
    await f.restore();
    assert.deepEqual(await policy(f), original);
    await admin(
      f,
      {
        action: 'activate-policy',
        policy: candidate,
        expected_revision: original.projection_revision,
        expected_generation: original.generation,
      },
      409,
    );
    assert.equal((await f.readSource()).status, 409);
    assert.deepEqual((await f.state()).checkpoint, retained);
  } finally {
    await f.close();
  }
});

test('fixed authority operations reject arbitrary fields, malformed policy, stale guards, missing binding and unenrolled state', async () => {
  const f = await fixture();
  try {
    const before = await f.current();
    const change = {
      action: 'revoke-account',
      account: 'synthetic-delivery-owner',
      expected_epoch: 0,
    };
    for (const input of [
      { ...change, sql: 'DELETE FROM credential' },
      { ...change, active: 1 },
      { ...change, expected_epoch: 9007199254740992 },
      {
        action: 'revoke-session',
        session: 'delivery-sso',
        account: 'different-owner',
        expected_epoch: 0,
      },
      { action: 'activate-policy', policy: {}, expected_revision: null, expected_generation: 0 },
    ])
      await admin(f, input, 409);
    for (const body of [
      JSON.stringify({ ...auditMetadata, ...change }).replace(
        '"action":',
        '"action":"revoke-account","action":',
      ),
      ' '.repeat(8193),
    ])
      assert.equal((await f.http('/authority-fixture', { method: 'POST', body })).status, 409);
    const settled = await f.current();
    // Invalid preflight consumes no slot; SQL stale-CAS failure settles one empty slot.
    assert.equal(settled.sequence, before.sequence + 1);
    assert.equal((await f.state()).pending, null);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM op_authority_audit').first('n'), 0);
    await f.restart(false);
    await admin(f, change, 409);
  } finally {
    await f.close();
  }
  const unenrolled = await fixture(false);
  try {
    await admin(
      unenrolled,
      { action: 'revoke-account', account: 'synthetic-delivery-owner', expected_epoch: 0 },
      409,
    );
  } finally {
    await unenrolled.close();
  }
});

test('authority audit abort rolls back the protected change and closes the SQL frame without returning success', async () => {
  const f = await fixture();
  try {
    const before = await f.current();
    await f.DB.prepare(
      "CREATE TRIGGER fixture_authority_abort BEFORE INSERT ON op_authority_audit BEGIN SELECT RAISE(ABORT,'fixture_authority_abort'); END",
    ).run();
    const change = {
      action: 'revoke-session',
      session: 'delivery-sso',
      account: 'synthetic-delivery-owner',
      expected_epoch: 0,
    };
    await admin(f, change, 409);
    assert.equal(await f.DB.prepare('SELECT revoked FROM sso_session').first('revoked'), 0);
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_authority_frame').first('n'),
      0,
    );
    assert.equal((await f.current()).sequence, before.sequence + 1);
    await f.DB.prepare('DROP TRIGGER fixture_authority_abort').run();
    await admin(f, change);
    assert.equal(await f.DB.prepare('SELECT revoked FROM sso_session').first('revoked'), 1);
  } finally {
    await f.close();
  }
});

test('0012 preserves unenrolled 0011 history and does not retroactively certify authority', async () => {
  const f = await fixture(false, '0011');
  try {
    const tables = (
      await f.DB.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY name",
      ).all<{ name: string }>()
    ).results.map((r) => r.name);
    const before = await f.DB.batch(tables.map((t) => f.DB.prepare(`SELECT * FROM ${t}`)));
    const migration = await readFile(
      new URL('../../crates/worker/work-migrations/0012_op_authority_frames.sql', import.meta.url),
      'utf8',
    );
    await f.DB.batch(splitSqlQuery(migration).map((s) => f.DB.prepare(s)));
    const after = await f.DB.batch(tables.map((t) => f.DB.prepare(`SELECT * FROM ${t}`)));
    before.forEach((r, i) => assert.deepEqual(after[i]!.results, r.results, tables[i]));
    assert.equal(
      await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
      0,
    );
    await f.DB.prepare('UPDATE sso_session SET revoked=1').run(); // Existing unenrolled OP contract.
  } finally {
    await f.close();
  }
});

test('normal OP logout keeps the legacy batch path without a checkpoint table or enrollment', async () => {
  for (const absentTable of [false, true]) {
    const f = await fixture(false, undefined, false, true, absentTable ? 10 : undefined);
    try {
      await seedLogoutClient(f);
      const table = await f.DB.prepare(
        "SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='work_authority_checkpoint'",
      ).first('n');
      assert.equal(table, absentTable ? 0 : 1);
      if (!absentTable)
        assert.equal(
          await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
          0,
        );

      const response = await productLogout(f);
      assert.equal(response.status, 200, 'unenrolled legacy logout remains available');
      const state = await logoutState(f);
      assert.equal(state.revoked, 1);
      assert.equal(state.transactions.length, 0);
      assert.equal(state.events.length, 1);
      assert.equal(state.deliveries.length, 1);
      assert.equal(state.clients[0]?.revoked, 1);
      assert.deepEqual(state.guards, []);
      if (!absentTable)
        assert.equal(
          await f.DB.prepare('SELECT count(*) AS n FROM work_authority_checkpoint').first('n'),
          0,
        );
    } finally {
      await f.close();
    }
  }
});

test('normal OP logout fails closed for an enrolled checkpoint without its service binding', async () => {
  const f = await fixture(false, undefined, false, true);
  try {
    await seedLogoutClient(f);
    await f.DB.prepare('INSERT INTO work_authority_checkpoint VALUES(1,?,?,0,?)')
      .bind('synthetic-managed-work', 'a'.repeat(64), 'b'.repeat(64))
      .run();
    const submit = await prepareProductLogout(f);
    const before = await logoutState(f);
    assert.equal(before.revoked, 0);
    assert.equal(before.transactions.length, 1, 'GET prepared a durable CSRF transaction');
    const marker = await f.DB.prepare(
      'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1',
    ).first();

    const response = await submit();
    assert.equal(response.status, 400, 'an enrolled checkpoint cannot fall back to raw D1');
    assert.deepEqual(await logoutState(f), before);
    assert.deepEqual(
      await f.DB.prepare(
        'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1',
      ).first(),
      marker,
    );
  } finally {
    await f.close();
  }
});

test('normal OP logout commits through the bound checkpoint and advances D1 and the Durable Object', async () => {
  const f = await fixture(true, undefined, false, true);
  try {
    await seedLogoutClient(f);
    const before = await f.current();
    assert.deepEqual((await f.state()).checkpoint, before);
    const response = await productLogout(f);
    assert.equal(response.status, 200);
    const after = await f.current();
    assert.equal(after.sequence, before.sequence + 1);
    assert.notEqual(after.tip, before.tip);
    assert.deepEqual((await f.state()).checkpoint, after);
    const state = await logoutState(f);
    assert.equal(state.revoked, 1);
    assert.equal(state.transactions.length, 0);
    assert.equal(state.events.length, 1);
    assert.equal(state.deliveries.length, 1);
    assert.equal(state.deliveries[0]?.client_id, 'synthetic-logout-client');
    assert.equal(state.deliveries[0]?.sid, 'synthetic-logout-sid');
    assert.equal(state.clients[0]?.revoked, 1);
    assert.deepEqual(state.guards, []);
    assert.deepEqual(
      await f.DB.prepare(
        'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1',
      ).first(),
      after,
    );
  } finally {
    await f.close();
  }
});

test('normal OP logout does not mutate D1 when its enrolled checkpoint is frozen, above the release floor, or mismatched', async () => {
  for (const mode of ['frozen', 'release-floor', 'mismatched'] as const) {
    const f = await fixture(true, undefined, false, true);
    try {
      await seedLogoutClient(f);
      if (mode === 'frozen') await f.checkpoint({ action: 'freeze' });
      else if (mode === 'release-floor') await f.checkpoint({ action: 'raise-floor', floor: 2 });
      else {
        await f.DB.prepare('DROP TRIGGER work_authority_checkpoint_monotonic').run();
        await f.DB.prepare('UPDATE work_authority_checkpoint SET tip=? WHERE id=1')
          .bind('c'.repeat(64))
          .run();
      }
      const submit = await prepareProductLogout(f);
      const before = await logoutState(f);
      const marker = await f.DB.prepare(
        'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1',
      ).first();
      const response = await submit();
      assert.equal(response.status, 400, `${mode} checkpoint must refuse logout mutation`);
      assert.deepEqual(await logoutState(f), before);
      assert.deepEqual(
        await f.DB.prepare(
          'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1',
        ).first(),
        marker,
      );
    } finally {
      await f.close();
    }
  }
});
