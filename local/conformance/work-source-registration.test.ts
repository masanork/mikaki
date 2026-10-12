import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSourceFixture } from './support/work-source-fixture.ts';

test('private operator registration commits verified code metadata through the enrolled product authority', async (t) => {
  const f = await createSourceFixture(undefined, true, 'product', true, 3600, true);
  const source = {
    source_id: 'registered-code',
    source_revision: 1,
    role: 'code',
    label: 'Code snapshot; original history excluded',
    ...f.codeSource,
    files: [],
  };
  const register = (patch: Record<string, unknown> = {}) =>
    f.fixture.fetch('https://work.test/authority-fixture', {
      method: 'POST',
      body: JSON.stringify({
        action: 'register-source',
        source,
        account: f.first.account,
        expected_epoch: 0,
        actor: 'trusted-local-git',
        reason: 'verified source',
        ...patch,
      }),
    });
  const count = async () =>
    Number(
      await f.DB.prepare(
        "SELECT count(*) AS n FROM work_audit WHERE entity_type='source' AND action='source.register'",
      ).first('n'),
    );
  try {
    await t.test(
      'source, owner access and both audit streams commit together; exact retry reads without another frame',
      async () => {
        assert.equal((await register()).status, 200);
        assert.equal(await count(), 1);
        const marker = await f.DB.prepare(
          'SELECT sequence,tip FROM work_authority_checkpoint',
        ).first();
        assert.equal((await register()).status, 200);
        assert.equal(await count(), 1);
        assert.deepEqual(
          await f.DB.prepare('SELECT sequence,tip FROM work_authority_checkpoint').first(),
          marker,
        );
        assert.equal(
          Number(
            await f.DB.prepare(
              "SELECT count(*) AS n FROM work_source_audit WHERE source_id='registered-code'",
            ).first('n'),
          ),
          3,
        );
        const inspect = await f.fixture.fetch('https://work.test/authority-fixture', {
          method: 'POST',
          body: JSON.stringify({
            action: 'inspect-source',
            source_id: source.source_id,
            account: f.first.account,
          }),
        });
        assert.equal(inspect.status, 200);
        const record = (await inspect.json()) as { source: { body: string; owner_epoch: number } };
        assert.deepEqual(JSON.parse(record.source.body).data.data, source);
        assert.equal(record.source.owner_epoch, 0);
        const list = (await (await f.http('/work/sources')).json()) as {
          record: { sources: { source_id: string }[] };
        };
        assert.ok(list.record.sources.some((s) => s.source_id === source.source_id));
        assert.deepEqual(
          (
            (await (await f.http('/work/sources', f.foreign)).json()) as {
              record: { sources: unknown[] };
            }
          ).record.sources,
          [],
        );
      },
    );
    await t.test(
      'the owner can compose a code-only preparation from operator-registered facts without another source read or consent',
      async () => {
        const response = await f.http('/work/preparations', f.first, {
          method: 'POST',
          body: JSON.stringify({
            format_version: 1,
            code: { source_id: source.source_id, source_revision: 1, access_revision: 1 },
            contexts: [],
            expires_at: Math.floor(Date.now() / 1000) + 600,
          }),
        });
        assert.equal(response.status, 200, await response.clone().text());
        assert.equal(
          Number(await f.DB.prepare('SELECT count(*) AS n FROM work_preparation').first('n')),
          1,
        );
        for (const table of [
          'source_reader_calls',
          'work_copy_consent',
          'work_credential_attempt',
          'work_task_repository',
          'work_grant',
          'work_run',
        ]) {
          assert.equal(
            Number(await f.DB.prepare(`SELECT count(*) AS n FROM ${table}`).first('n')),
            0,
          );
        }
      },
    );
    await t.test(
      'different bytes, stale epochs, foreign ownership and malformed registration cannot replace retained facts',
      async () => {
        for (const patch of [
          { source: { ...source, commit: '0'.repeat(40) } },
          { expected_epoch: 1 },
          { account: f.foreign.account },
          { source: { ...source, source_revision: 2 } },
          { source: { ...source, unexpected: 'caller content' } },
          { source: { ...source, code: { ...source.code, object_bytes: 67108865 } } },
        ])
          assert.equal((await register(patch)).status, 409);
        assert.equal(await count(), 1);
        assert.equal(
          Number(
            await f.DB.prepare(
              "SELECT count(*) AS n FROM work_source_version WHERE source_id='registered-code'",
            ).first('n'),
          ),
          1,
        );
      },
    );
    await t.test(
      'source audit failure rolls back registration and releases the aborted frame',
      async () => {
        await f.DB.prepare(
          "CREATE TRIGGER fail_registration_audit BEFORE INSERT ON work_source_audit BEGIN SELECT RAISE(ABORT,'SQLITE_CONSTRAINT injected'); END",
        ).run();
        try {
          assert.equal(
            (await register({ source: { ...source, source_id: 'audit-failure' } })).status,
            409,
          );
        } finally {
          await f.DB.prepare('DROP TRIGGER fail_registration_audit').run();
        }
        assert.equal(
          Number(
            await f.DB.prepare(
              "SELECT count(*) AS n FROM work_source_version WHERE source_id='audit-failure'",
            ).first('n'),
          ),
          0,
        );
        assert.equal(await count(), 1);
        assert.equal(
          (await register({ source: { ...source, source_id: 'after-abort' } })).status,
          200,
        );
      },
    );
    await t.test(
      'public transport and raw RPC refuse registration; frozen authority refuses new metadata',
      async () => {
        assert.equal(
          (await f.worker.fetch('https://work.test/authority', { method: 'POST', body: '{}' }))
            .status,
          404,
        );
        assert.equal((await f.checkpoint({ action: 'named-admin-raw-rpc' })).status, 404);
        assert.equal((await f.checkpoint({ action: 'freeze' })).status, 200);
        assert.equal(
          (await register({ source: { ...source, source_id: 'after-freeze' } })).status,
          409,
        );
        assert.equal(
          Number(
            await f.DB.prepare(
              "SELECT count(*) AS n FROM work_source_head WHERE source_id='after-freeze'",
            ).first('n'),
          ),
          0,
        );
      },
    );
  } finally {
    await f.close();
  }
});
