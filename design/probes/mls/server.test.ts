import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import type { Head } from './device-store.js';
import { fixture, ORIGIN, keys, pub, digest, proof } from './server-support.ts';

test('SSO-owned registration: immutable namespace, challenge/proof context, strict profile and exact completion retry', async () => {
  const f = await fixture();
  try {
    const account = await f.response<{ issuer: string; account_id: string }>(
      await f.request('/messaging/account', 'POST', {}),
    );
    assert.equal(account.issuer, ORIGIN);
    assert.notEqual(account.account_id, f.a.owner);
    assert.deepEqual(await f.response(await f.request('/messaging/account', 'POST', {})), account);
    assert.deepEqual(await f.response(await f.request('/messaging/account')), account);
    const d = await f.start();
    assert.equal(d.c.device.account_id, account.account_id);
    const again = await f.response(
      await f.request('/messaging/enrollments', 'POST', d.payload, f.a, {
        'X-Operation-ID': d.operation,
      }),
    );
    assert.deepEqual(again, d.c);
    await f.response(
      await f.request(
        '/messaging/enrollments',
        'POST',
        { ...d.payload, device_id: randomUUID() },
        f.a,
        { 'X-Operation-ID': d.operation },
      ),
      409,
    );
    assert.equal(
      (
        await f.request(
          `/messaging/enrollments/${d.c.enrollment_id}/complete`,
          'POST',
          { proof: proof(d.c, d.k) },
          f.b,
        )
      ).status,
      404,
    );
    for (const token of [
      proof(d.c, d.k, { nonce: randomBytes(32).toString('base64url') }),
      proof(d.c, d.k, { aud: 'https://wrong.test' }),
      proof(d.c, d.k, { device: { ...d.c.device, account_id: randomUUID() } }),
      proof(d.c, d.k, { device: { ...d.c.device, generation: 2 } }),
      proof(d.c, keys()),
      proof(d.c, d.k, { exp: Math.floor(Date.now() / 1000) + 120 }),
      proof(d.c, d.k, { iat: Math.floor(Date.now() / 1000) + 60 }),
      proof(d.c, d.k, {}, { alg: 'ES256' }),
      proof(d.c, d.k, {}, { typ: 'mikaki-device-binding+jwt' }),
      proof(d.c, d.k, {}, { jwk: { kty: 'OKP' } }),
      `${proof(d.c, d.k)}=`,
    ])
      await f.complete(d, token, 400);
    const token = proof(d.c, d.k),
      accepted = await f.complete(d, token);
    const result = f.binding(accepted.binding);
    assert.deepEqual(result.device, d.c.device);
    assert.equal(result.public_key, pub(d.k.publicKey));
    assert.equal(result.revision, 1);
    assert.equal(result.status, 'active');
    assert.equal(result.exp - result.iat, 300);
    assert.equal(
      d.c.scope.fingerprint,
      digest(
        JSON.stringify([
          'mikaki-device-fingerprint-v1',
          {
            issuer: d.c.device.issuer,
            account_id: d.c.device.account_id,
            device_id: d.c.device.device_id,
            generation: d.c.device.generation,
          },
          'Ed25519',
          pub(d.k.publicKey),
        ]),
      ),
    );
    assert.equal(f.binding((await f.complete(d, token)).binding).revision, 1);
    await f.complete(d, proof(d.c, d.k, { exp: 1 }), 409);
    const row = await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_generation').first<{
      n: number;
    }>();
    assert.equal(row!.n, 1);
    const own = await f.response<{ binding: string }>(
      await f.request(`/messaging/devices/${d.c.device.device_id}/binding`),
    );
    assert.deepEqual(f.binding(own.binding).device, d.c.device);
    assert.equal(
      (await f.request(`/messaging/devices/${d.c.device.device_id}/binding`, 'GET', undefined, f.b))
        .status,
      404,
    );
    assert.equal(
      (
        await f.worker.fetch(`${ORIGIN}/messaging/account`, {
          headers: { Authorization: 'Bearer not-an-owner-session' },
        })
      ).status,
      401,
    );
    assert.equal(
      (
        await f.request('/messaging/enrollments', 'POST', d.payload, f.a, {
          Origin: 'https://evil.test',
          'X-Operation-ID': randomUUID(),
        })
      ).status,
      403,
    );
    assert.equal(
      (
        await f.request('/messaging/account', 'GET', undefined, f.a, {
          'Sec-Fetch-Site': 'cross-site',
        })
      ).status,
      403,
    );
    for (const bad of [
      { ...d.payload, account_id: randomUUID() },
      { ...d.payload, public_key: `${d.payload.public_key}=` },
      { ...d.payload, expected_revision: -1 },
    ])
      assert.equal(
        (
          await f.request('/messaging/enrollments', 'POST', bad, f.a, {
            'X-Operation-ID': randomUUID(),
          })
        ).status,
        400,
      );
    assert.equal(
      (
        await f.request('/messaging/enrollments', 'POST', 'x'.repeat(1025), f.a, {
          'X-Operation-ID': randomUUID(),
        })
      ).status,
      413,
    );
  } finally {
    await f.close();
  }
});
test('registered scope witness: durable CAS, exact retries, parallel conflict, owner isolation and no implicit scope creation', async () => {
  const f = await fixture();
  try {
    const d = await f.start();
    await f.complete(d);
    const path = `/messaging/heads/${f.scope(d.c)}`;
    const genesis: Head = { revision: 0, hash: null };
    assert.deepEqual(await f.response(await f.request(path)), genesis);
    const next: Head = { revision: 1, hash: randomBytes(32).toString('base64url') };
    assert.deepEqual(
      await f.response(await f.request(path, 'PUT', { expected: genesis, next })),
      next,
    );
    assert.deepEqual(
      await f.response(await f.request(path, 'PUT', { expected: genesis, next })),
      next,
    );
    const candidates = [0, 1].map(() => ({
      revision: 2,
      hash: randomBytes(32).toString('base64url'),
    }));
    await Promise.all(
      candidates.map((candidate) => f.request(path, 'PUT', { expected: next, next: candidate })),
    );
    const winner = await f.response<Head>(await f.request(path));
    assert.equal(
      candidates.some((c) => JSON.stringify(c) === JSON.stringify(winner)),
      true,
    );
    assert.deepEqual(
      await f.response(await f.request(path, 'PUT', { expected: genesis, next })),
      winner,
      'old retry must report the actual head, never an old historical receipt',
    );
    assert.equal((await f.request(path, 'GET', undefined, f.b)).status, 404);
    assert.equal(
      (await f.request(`/messaging/heads/${randomBytes(32).toString('base64url')}`)).status,
      404,
    );
    for (const body of [
      { expected: next, next: { revision: 4, hash: next.hash } },
      { expected: { revision: 0, hash: next.hash }, next },
      { expected: next, next: { revision: 2, hash: `${next.hash}=` } },
      { expected: next, next: { revision: 2, hash: null } },
      { expected: next, next: { revision: 2, hash: next.hash }, extra: 1 },
    ])
      assert.equal((await f.request(path, 'PUT', body)).status, 400);
    await f.response(
      await f.request(`/messaging/devices/${d.c.device.device_id}/revoke`, 'POST', {
        expected_revision: 1,
      }),
    );
    assert.equal((await f.request(path)).status, 404);
    assert.equal(
      (await f.request(path, 'PUT', { expected: winner, next: { revision: 3, hash: next.hash } }))
        .status,
      404,
    );
    assert.deepEqual(
      await f.env.DB.prepare(
        'SELECT head_revision AS revision,head_hash AS hash FROM messaging_generation WHERE scope_hash=?',
      )
        .bind(f.scope(d.c))
        .first(),
      winner,
    );
  } finally {
    await f.close();
  }
});
test('generation replacement and revocation retain tombstones, reject old key/scope reuse and never refresh an old active lease', async () => {
  const f = await fixture();
  try {
    const old = await f.start(),
      oldProof = proof(old.c, old.k);
    await f.complete(old, oldProof);
    const replacement = await f.start(keys(), old.c.device.device_id, 1);
    assert.equal(replacement.c.device.generation, 2);
    await f.complete(replacement);
    const current = f.binding(
      (
        await f.response<{ binding: string }>(
          await f.request(`/messaging/devices/${old.c.device.device_id}/binding`),
        )
      ).binding,
    );
    assert.equal(current.device.generation, 2);
    assert.equal(current.revision, 2);
    await f.complete(old, oldProof, 409);
    assert.equal((await f.request(`/messaging/heads/${f.scope(old.c)}`)).status, 404);
    assert.equal(
      (
        await f.request(
          '/messaging/enrollments',
          'POST',
          { ...old.payload, expected_revision: 2 },
          f.a,
          { 'X-Operation-ID': randomUUID() },
        )
      ).status,
      409,
    );
    const retired = await f.env.DB.prepare(
      'SELECT status,revision,scope_hash FROM messaging_generation WHERE generation=1',
    ).first<{ status: string; revision: number }>();
    assert.equal(retired!.status, 'revoked');
    assert.equal(retired!.revision, 2);
    const rev = f.binding(
      (
        await f.response<{ binding: string }>(
          await f.request(`/messaging/devices/${old.c.device.device_id}/revoke`, 'POST', {
            expected_revision: 2,
          }),
        )
      ).binding,
    );
    assert.equal(rev.status, 'revoked');
    assert.equal(rev.revision, 3);
    assert.equal(
      f.binding(
        (
          await f.response<{ binding: string }>(
            await f.request(`/messaging/devices/${old.c.device.device_id}/revoke`, 'POST', {
              expected_revision: 2,
            }),
          )
        ).binding,
      ).revision,
      3,
    );
    assert.equal((await f.request(`/messaging/heads/${f.scope(replacement.c)}`)).status, 404);
    const third = await f.start(keys(), old.c.device.device_id, 3);
    assert.equal(third.c.device.generation, 3);
    await f.complete(third);
  } finally {
    await f.close();
  }
});
test('atomic registration rollback and one winning enrollment per expected device revision', async () => {
  const f = await fixture();
  try {
    const original = await f.start();
    await f.complete(original);
    const d = await f.start(keys(), original.c.device.device_id, 1),
      token = proof(d.c, d.k);
    await f.env.DB.exec(
      "CREATE TRIGGER fixture_abort BEFORE INSERT ON messaging_generation BEGIN SELECT RAISE(ABORT,'synthetic failure'); END",
    );
    await f.complete(d, token, 503);
    const previous = await f.env.DB.prepare(
      'SELECT status,revision FROM messaging_generation WHERE generation=1',
    ).first();
    assert.deepEqual(previous, { status: 'active', revision: 1 });
    assert.equal(
      (await f.env.DB.prepare(
        'SELECT consumed_proof FROM messaging_enrollment WHERE enrollment_id=?',
      )
        .bind(d.c.enrollment_id)
        .first<{ consumed_proof: string | null }>())!.consumed_proof,
      null,
    );
    await f.env.DB.exec('DROP TRIGGER fixture_abort');
    const other = await f.start(keys(), original.c.device.device_id, 1);
    const responses = await Promise.all(
      [d, other].map((x) =>
        f.request(`/messaging/enrollments/${x.c.enrollment_id}/complete`, 'POST', {
          proof: proof(x.c, x.k),
        }),
      ),
    );
    assert.equal(responses.filter((r) => r.status === 200).length, 1);
    assert.equal(responses.filter((r) => r.status === 409).length, 1);
    assert.equal(
      (await f.env.DB.prepare(
        'SELECT count(*) AS n FROM messaging_generation WHERE generation=2',
      ).first<{ n: number }>())!.n,
      1,
    );
  } finally {
    await f.close();
  }
});
test('database-time challenge expiry and session binding cannot be bypassed by a valid device signature', async () => {
  const f = await fixture();
  try {
    const d = await f.start();
    await f.env.DB.prepare(
      'UPDATE messaging_enrollment SET expires_at=unixepoch()-1 WHERE enrollment_id=?',
    )
      .bind(d.c.enrollment_id)
      .run();
    await f.complete(d, proof(d.c, d.k), 410);
    const active = await f.start();
    const secondSecret = randomBytes(32).toString('base64url'),
      secondSession = randomUUID();
    await f.env.DB.batch([
      f.env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,unixepoch()+3600,0)').bind(
        secondSession,
        f.a.owner,
        f.a.credential,
      ),
      f.env.DB.prepare('INSERT INTO sso_context VALUES(?,?,unixepoch())').bind(
        secondSession,
        digest(secondSecret),
      ),
    ]);
    assert.equal(
      (
        await f.request(
          `/messaging/enrollments/${active.c.enrollment_id}/complete`,
          'POST',
          { proof: proof(active.c, active.k) },
          { ...f.a, secret: secondSecret },
        )
      ).status,
      404,
    );
    for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
      const who = await f.seed(),
        target = await f.start(keys(), randomUUID(), 0, who);
      await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
        .bind('INSERT INTO messaging_generation', mode, who.owner)
        .run();
      assert.equal(
        (
          await f.request(
            `/messaging/enrollments/${target.c.enrollment_id}/complete`,
            'POST',
            { proof: proof(target.c, target.k) },
            who,
          )
        ).status,
        403,
      );
      assert.equal(
        (await f.env.DB.prepare(
          'SELECT consumed_proof FROM messaging_enrollment WHERE enrollment_id=?',
        )
          .bind(target.c.enrollment_id)
          .first<{ consumed_proof: string | null }>())!.consumed_proof,
        null,
      );
    }
  } finally {
    await f.close();
  }
});
test('authority is rechecked at witness mutation and after asynchronous binding signing', async () => {
  const f = await fixture();
  try {
    for (const mode of ['account', 'epoch', 'credential', 'session', 'expiry']) {
      const who = await f.seed(),
        d = await f.start(keys(), randomUUID(), 0, who);
      await f.complete(d);
      await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
        .bind('UPDATE messaging_generation SET head_revision', mode, who.owner)
        .run();
      assert.equal(
        (
          await f.request(
            `/messaging/heads/${f.scope(d.c)}`,
            'PUT',
            {
              expected: { revision: 0, hash: null },
              next: { revision: 1, hash: randomBytes(32).toString('base64url') },
            },
            who,
          )
        ).status,
        404,
      );
      assert.equal(
        (await f.env.DB.prepare('SELECT head_revision FROM messaging_generation WHERE scope_hash=?')
          .bind(f.scope(d.c))
          .first<{ head_revision: number }>())!.head_revision,
        0,
      );
    }
    const d = await f.start();
    await f.complete(d);
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,2)')
      .bind('WHERE g.device_id=?1', 'session', f.a.owner)
      .run();
    assert.equal(
      (await f.request(`/messaging/devices/${d.c.device.device_id}/binding`)).status,
      403,
    );
  } finally {
    await f.close();
  }
});

test('proof expiry is fenced by database time at the atomic commit, after signature verification', async () => {
  const f = await fixture();
  try {
    const d = await f.start();
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('INSERT INTO messaging_generation', 'proof_expiry', f.a.owner)
      .run();
    await f.complete(d, proof(d.c, d.k, { exp: Math.floor(Date.now() / 1000) + 2 }), 409);
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_generation').first<{
        n: number;
      }>())!.n,
      0,
    );
    assert.equal(
      (await f.env.DB.prepare(
        'SELECT consumed_proof FROM messaging_enrollment WHERE enrollment_id=?',
      )
        .bind(d.c.enrollment_id)
        .first<{ consumed_proof: string | null }>())!.consumed_proof,
      null,
    );
  } finally {
    await f.close();
  }
});
test('pending challenge bounds and simultaneous last-device admission are enforced inside SQL', async () => {
  const f = await fixture();
  try {
    for (let i = 0; i < 4; i++) await f.start();
    assert.equal(
      (
        await f.request(
          '/messaging/enrollments',
          'POST',
          {
            device_id: randomUUID(),
            public_key: pub(keys().publicKey),
            storage_id: randomUUID(),
            key_id: randomUUID(),
            expected_revision: 0,
          },
          f.a,
          { 'X-Operation-ID': randomUUID() },
        )
      ).status,
      409,
    );
    await f.env.DB.prepare('UPDATE messaging_enrollment SET expires_at=unixepoch()-1').run();
    for (let i = 0; i < 7; i++) {
      const d = await f.start();
      await f.complete(d);
    }
    const candidates = [await f.start(), await f.start()];
    const results = await Promise.all(
      candidates.map((d) =>
        f.request(`/messaging/enrollments/${d.c.enrollment_id}/complete`, 'POST', {
          proof: proof(d.c, d.k),
        }),
      ),
    );
    assert.equal(results.filter((r) => r.status === 200).length, 1);
    assert.equal(results.filter((r) => r.status === 409).length, 1);
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_device_head').first<{
        n: number;
      }>())!.n,
      8,
    );
  } finally {
    await f.close();
  }
});

test('lost successful registration database reply reconciles the original durable proof outcome', async () => {
  const f = await fixture();
  try {
    const d = await f.start(),
      token = proof(d.c, d.k);
    await f.env.DB.prepare('INSERT INTO fixture_messaging_fault VALUES(1,?,?,?,1)')
      .bind('INSERT INTO messaging_generation', 'lost_enrollment_reply', f.a.owner)
      .run();
    assert.equal(f.binding((await f.complete(d, token)).binding).revision, 1);
    assert.equal(f.binding((await f.complete(d, token)).binding).revision, 1);
    assert.equal(
      (await f.env.DB.prepare('SELECT count(*) AS n FROM messaging_generation').first<{
        n: number;
      }>())!.n,
      1,
    );
    assert.equal(
      (await f.env.DB.prepare(
        'SELECT consumed_proof FROM messaging_enrollment WHERE enrollment_id=?',
      )
        .bind(d.c.enrollment_id)
        .first<{ consumed_proof: string | null }>())!.consumed_proof,
      digest(token),
    );
  } finally {
    await f.close();
  }
});
