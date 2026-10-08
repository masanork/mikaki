import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { Response as WorkerResponse } from 'miniflare';
import { effectFixture } from './support/work-effect-fixture.ts';
import { localGit } from '../../scripts/work-git-disclosure.ts';
import { PreparedGitCopy } from '../../scripts/work-git-copy.ts';
import { copyThroughBroker } from '../../scripts/work-git-broker.ts';
import { packet, readbackBody } from '../../crates/work-effect-worker/git-protocol.ts';
import type { GitRecord } from '../../crates/work-effect-worker/git-protocol.ts';
async function fixture(role: 'task' | 'snapshot' = 'task') {
  let directory = '',
    mode = 'normal';
  const events: { method: string; path: string }[] = [];
  const http: NonNullable<Parameters<typeof effectFixture>[1]> = async (request) => {
    const url = new URL(request.url),
      service = url.searchParams.get('service') ?? url.pathname.split('/').at(-1)!;
    events.push({ method: request.method, path: url.pathname });
    if (mode === 'unavailable') return new WorkerResponse(null, { status: 503 });
    if (mode === 'redirect')
      return new WorkerResponse(null, {
        status: 302,
        headers: { Location: 'https://unrequested.invalid/' },
      });
    if (!/^Bearer SYNTHETIC_MINT_SECRET_\d+$/.test(request.headers.get('Authorization') ?? ''))
      return new WorkerResponse(null, { status: 403 });
    const dir = join(directory, 'remote-' + role);
    let bytes: Buffer;
    if (request.method === 'GET') {
      bytes = Buffer.concat([
        Buffer.from(packet(`# service=${service}\n`) + '0000'),
        localGit(dir, [
          service === 'git-receive-pack' ? 'receive-pack' : 'upload-pack',
          '--stateless-rpc',
          '--advertise-refs',
          dir,
        ]),
      ]);
      if (mode === 'wrong-refs')
        bytes = Buffer.from(
          packet(`# service=${service}\n`) +
            '0000' +
            packet(`${'a'.repeat(40)} refs/heads/foreign\0report-status\n`) +
            '0000',
        );
    } else {
      bytes = localGit(
        dir,
        [service === 'git-receive-pack' ? 'receive-pack' : 'upload-pack', '--stateless-rpc', dir],
        Buffer.from(await request.arrayBuffer()),
      );
      if (mode === 'lost-post') throw new Error('synthetic_lost_response');
      if (mode === 'bad-status') bytes = Buffer.from('0000');
    }
    return new WorkerResponse(new Uint8Array(bytes).buffer, {
      headers: {
        'Content-Type': `application/x-${service}-${request.method === 'GET' ? 'advertisement' : 'result'}`,
      },
    });
  };
  const f = await effectFixture({}, http);
  directory = f.directory;
  try {
    await mkdir(join(directory, 'remote-' + role));
    localGit(join(directory, 'remote-' + role), ['init', '--bare', '--quiet', '--template=']);
    localGit(join(directory, 'remote-' + role), [
      'symbolic-ref',
      'HEAD',
      `refs/heads/${role === 'task' ? 'work' : 'snapshot'}`,
    ]);
    await f.execute(role === 'task' ? f.task.id : f.snapshot.id);
    const ids: { upload: string; readback: string } = { upload: '', readback: '' };
    for (const purpose of ['upload', 'readback'] as const) {
      const a = await f.call({
        action: 'reserve-credential',
        credential: { preparation_id: f.p.id, role, purpose },
      });
      ids[purpose] = a.id;
      if (purpose === 'upload')
        assert.equal(
          (await f.effect<{ state: string }>({ action: 'mint', input: { attempt_id: a.id } }))
            .state,
          'custodied',
        );
    }
    const source =
      role === 'task'
        ? f.code
        : {
            dir: f.selected.gitDir,
            commit: f.selected.input.snapshot.commit,
            tree: f.selected.input.snapshot.tree,
          };
    const copy = await PreparedGitCopy.prepare(
      { gitDir: source.dir, commit: source.commit, tree: source.tree },
      role,
    );
    const request = (
      purpose: 'upload' | 'readback' = 'upload',
      change: Record<string, unknown> = {},
      bytes?: Uint8Array,
    ) =>
      new Request('https://private.invalid/copy', {
        method: 'POST',
        headers: {
          'X-Mikaki-Attempt-ID': ids[purpose],
          'X-Mikaki-Copy': JSON.stringify({ ...copy.manifest, ...change }),
        },
        body: new Uint8Array(
          bytes ?? (purpose === 'upload' ? copy.uploadBody() : readbackBody(copy.manifest)),
        ).buffer,
      });
    const mintReadback = async () => {
      await f.call({ action: 'credential-revoke', id: ids.upload });
      await f.effect({ action: 'mint', input: { attempt_id: ids.upload } });
      await f.effect({ action: 'mint-reconcile', input: { attempt_id: ids.upload } });
      const closed = await f.effect<{ state: string; op_synchronized: boolean }>({
        action: 'mint-close',
        input: { attempt_id: ids.upload },
      });
      assert.equal(closed.state, 'closed');
      assert.equal(closed.op_synchronized, true);
      assert.equal(
        (await f.effect<{ state: string }>({ action: 'mint', input: { attempt_id: ids.readback } }))
          .state,
        'custodied',
      );
      return ids.readback;
    };
    const attempts = { upload: ids.upload, readback: mintReadback };
    return {
      ...f,
      copy,
      ids,
      attempts,
      events,
      request,
      providerMode: f.mode,
      mode: (v: string) => {
        mode = v;
      },
      ledger: () =>
        f.effect<GitRecord | null>({
          action: 'git-call',
          binding: 'GIT_LOOKUP',
          method: 'lookup',
          args: [ids.upload],
        }),
    };
  } catch (e) {
    await f.close();
    throw e;
  }
}
for (const role of ['task', 'snapshot'] as const)
  test(`${role}: Native custody sends one exact Git copy and independent readback through real Git`, async () => {
    const f = await fixture(role);
    try {
      const facts = await copyThroughBroker(f.copy, f.attempts, (r) => broker(f, r));
      assert.equal(facts.stage, 'readback_verified');
    } finally {
      await f.close();
    }
  });
// The adapter below preserves the private Native receipt and status without reading a bearer.
async function broker(f: Awaited<ReturnType<typeof fixture>>, r: Request) {
  const response = await f.gitFetch(r);
  return new Response(await response.arrayBuffer(), {
    status: response.status,
    headers: Object.fromEntries(response.headers),
  });
}
test('successful copy remains dispatched and charged, cannot grant or replay after restart', async () => {
  const f = await fixture();
  try {
    const result = await copyThroughBroker(f.copy, f.attempts, (r) => broker(f, r));
    assert.equal(result.stage, 'readback_verified');
    assert.equal(result.commit, f.copy.manifest.commit);
    assert.equal(f.events.length, 4);
    assert.equal((await f.ledger())!.consumed, true);
    assert.equal(await f.DB.prepare('SELECT count(*) AS n FROM work_grant').first('n'), 0);
    assert.equal(
      await f.DB.prepare('SELECT state FROM work_preparation WHERE operation_id=?')
        .bind(f.p.id)
        .first('state'),
      'dispatched',
    );
    assert.equal((await f.row(f.ids.upload))!.state, 'closed');
    assert.doesNotMatch(
      JSON.stringify([result, await f.ledger()]),
      /SYNTHETIC_MINT_SECRET|plaintext|Authorization/,
    );
    const before = [...f.events];
    await f.restart();
    assert.equal((await f.gitFetch(f.request())).status, 409);
    assert.deepEqual(f.events, before);
  } finally {
    await f.close();
  }
});
for (const mode of ['unavailable', 'redirect', 'wrong-refs', 'lost-post', 'bad-status'])
  test(`${mode}: unknown send retains the permanent admission and never repeats`, async () => {
    const f = await fixture();
    try {
      f.mode(mode);
      assert.equal((await f.gitFetch(f.request())).status, 409);
      assert.equal((await f.ledger())!.consumed, true);
      const before = [...f.events];
      f.mode('normal');
      await f.restart();
      assert.equal((await f.gitFetch(f.request())).status, 409);
      assert.deepEqual(f.events, before);
    } finally {
      await f.close();
    }
  });
for (const change of [
  { commit: 'a'.repeat(40) },
  { tree: 'b'.repeat(40) },
  { role: 'snapshot' },
  { ref: 'refs/heads/foreign' },
  { request_sha256: 'c'.repeat(64) },
  { plaintext: 'unrequested' },
])
  test(`substituted ${Object.keys(change)[0]} is refused before admission or Git`, async () => {
    const f = await fixture();
    try {
      assert.equal((await f.gitFetch(f.request('upload', change))).status, 409);
      assert.equal(await f.ledger(), null);
      assert.equal(f.events.length, 0);
    } finally {
      await f.close();
    }
  });
for (const override of [
  { WORK_GIT_STORE_ENABLED: 'false' },
  { WORK_GIT_BROKER_ENABLED: 'false' },
  { WORK_GIT_TRANSPORT_ENABLED: 'false' },
  { WORK_CREDENTIAL_KEY_FLOOR: '2', WORK_CREDENTIAL_KEY_V1: '' },
])
  test(`cold/missing ${Object.keys(override)[0]} cannot send`, async () => {
    const f = await fixture();
    try {
      await f.restart(
        Object.fromEntries(
          Object.entries(override).filter(
            (pair): pair is [string, string] => typeof pair[1] === 'string',
          ),
        ),
      );
      assert.equal((await f.gitFetch(f.request())).status, 409);
      assert.equal(f.events.length, 0);
    } finally {
      await f.close();
    }
  });
test('revocation, checkpoint freeze and restore cannot reuse captured productive authority', async () => {
  const f = await fixture();
  try {
    await f.backup();
    await f.call({ action: 'credential-revoke', id: f.ids.upload });
    assert.equal((await f.gitFetch(f.request())).status, 409);
    assert.equal(f.events.length, 0);
    await f.restore();
    await f.checkpoint({ action: 'freeze' });
    assert.equal((await f.gitFetch(f.request())).status, 409);
    assert.equal(f.events.length, 0);
  } finally {
    await f.close();
  }
});
test('public and raw or broadened capabilities cannot obtain credentials or transmit', async () => {
  const f = await fixture();
  try {
    await f.effect({ action: 'git-public' }, 404);
    for (const binding of ['OP_EFFECT_STORE', 'OP_MINT_STORE', 'OP_PUBLIC'])
      await f.effect({ action: 'store-call', binding, path: '/git-effect', input: {} }, 404);
    for (const method of ['claim', 'take', 'reset', 'freeze'])
      await f.effect({ action: 'git-call', binding: 'GIT_LOOKUP', method, args: [] }, 409);
    await f.effect(
      { action: 'git-call', binding: 'OP_GIT_STORE', method: 'administer_work_effect' },
      404,
    );
    await f.effect(
      { action: 'git-call', binding: 'OP_GIT_STORE', method: 'administer_op_authority' },
      404,
    );
    assert.equal(f.events.length, 0);
    assert.deepEqual(
      (await f.bindingNames('work-git')).filter((n) => !n.startsWith('WORK_')).sort(),
      ['GIT_CHECKPOINT', 'OP_GIT_STORE'],
    );
    assert.deepEqual(
      (await f.bindingNames('git-transport')).filter((n) => !n.startsWith('WORK_')).sort(),
      ['ARTIFACTS', 'GIT_LOOKUP', 'GIT_TRANSMISSION', 'MINT_LOOKUP'],
    );
  } finally {
    await f.close();
  }
});

test('concurrent private requests cause exactly one admitted physical send', async () => {
  const f = await fixture();
  try {
    const result = await Promise.all([f.gitFetch(f.request()), f.gitFetch(f.request())]);
    assert.deepEqual(result.map((r) => r.status).sort(), [200, 409]);
    assert.equal(f.events.length, 2);
  } finally {
    await f.close();
  }
});
test('whole primary restore cannot forget a productive transmission', async () => {
  const f = await fixture();
  try {
    await f.backup();
    assert.equal((await f.gitFetch(f.request())).status, 200);
    const before = [...f.events];
    await f.restore();
    assert.equal((await f.gitFetch(f.request())).status, 409);
    assert.deepEqual(f.events, before);
    assert.equal((await f.ledger())!.consumed, true);
  } finally {
    await f.close();
  }
});
test('changed upload bytes are refused before allocating a send', async () => {
  const f = await fixture();
  try {
    const body = f.copy.uploadBody();
    body[body.length - 1] ^= 1;
    assert.equal((await f.gitFetch(f.request('upload', {}, body))).status, 409);
    assert.equal(await f.ledger(), null);
    assert.equal(f.events.length, 0);
  } finally {
    await f.close();
  }
});

for (const mode of [
  'replaced-repo',
  'wrong-description',
  'mint-substitute-scope',
  'mint-substitute-expiry',
  'incomplete-inventory',
])
  test(`${mode}: productive identity/inventory substitution cannot reach Git`, async () => {
    const f = await fixture();
    try {
      await f.providerMode(mode);
      assert.equal((await f.gitFetch(f.request())).status, 409);
      assert.equal(f.events.length, 0);
      assert.equal((await f.ledger())!.consumed, true);
    } finally {
      await f.close();
    }
  });
for (const fault of ['LOCAL_GIT_CLAIM_LOST', 'LOCAL_GIT_TAKE_LOST'])
  test(`${fault}: durable admission survives a lost acknowledgement before network I/O`, async () => {
    const f = await fixture();
    try {
      await f.restart({ [fault]: 'true' });
      assert.equal((await f.gitFetch(f.request())).status, 409);
      const retained = await f.ledger();
      assert.ok(retained);
      assert.equal(retained.consumed, fault === 'LOCAL_GIT_TAKE_LOST');
      assert.equal(f.events.length, 0);
      await f.restart();
      assert.equal((await f.gitFetch(f.request())).status, 409);
      assert.equal(f.events.length, 0);
    } finally {
      await f.close();
    }
  });
test('lost source access and a caller Authorization header cannot admit productive bytes', async () => {
  const f = await fixture();
  try {
    const withCredential = f.request();
    withCredential.headers.set('Authorization', 'Bearer UNREQUESTED_SECRET');
    assert.equal((await f.gitFetch(withCredential)).status, 409);
    assert.equal(await f.ledger(), null);
    await f.DB.prepare(
      'UPDATE work_source_access SET active=0,access_revision=access_revision+1',
    ).run();
    assert.equal((await f.gitFetch(f.request())).status, 409);
    assert.equal(await f.ledger(), null);
    assert.equal(f.events.length, 0);
  } finally {
    await f.close();
  }
});
