import assert from 'node:assert/strict';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
} from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { readFile, readdir } from 'node:fs/promises';
import { unstable_splitSqlQuery } from 'wrangler';
import { test } from 'node:test';
import { resolve } from 'node:path';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const origin = 'https://auth.example';
const cookie = 'qualification-sso-secret';
const hash = createHash('sha256').update(cookie).digest('base64url');
const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const { x, y } = key.publicKey.export({ format: 'jwk' });
const enc = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
function proof(
  path,
  nonce,
  jti = randomUUID(),
  signingKey = key,
  jwk = { kty: 'EC', crv: 'P-256', x, y },
) {
  const claims = { htm: 'POST', htu: origin + path, iat: Math.floor(Date.now() / 1000), jti };
  if (nonce) claims.nonce = nonce;
  const payload = `${enc({ typ: 'dpop+jwt', alg: 'ES256', jwk })}.${enc(claims)}`;
  return `${payload}.${sign('sha256', Buffer.from(payload), { key: signingKey.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
}

test('qualification Worker binds live SSO and signed key to one D1 installation', async () => {
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modulesRoot: resolve('local/generated/installation'),
      modules: [
        { type: 'ESModule', path: resolve('local/generated/installation/worker.bundle.mjs') },
        {
          type: 'CompiledWasm',
          path: resolve('local/generated/installation/qualification_bg.wasm'),
        },
      ],
      compatibilityDate: '2026-10-19',
      d1Databases: { DB: 'installation' },
      bindings: { MIKAKI_ISSUER: origin },
    }),
  );
  try {
    const db = await mf.getD1Database('DB');
    // Apply the repository's real D1 migrations, including triggers and DBSC,
    // rather than maintaining a parallel sketch of the authority schema.
    const migrationDir = 'crates/worker/migrations';
    const migrations = (await readdir(migrationDir)).filter((name) => name.endsWith('.sql')).sort();
    for (const name of migrations) {
      const sql = await readFile(`${migrationDir}/${name}`, 'utf8');
      await db.batch(unstable_splitSqlQuery(sql).map((statement) => db.prepare(statement)));
    }
    const extra = await readFile('crates/worker/installation-qualification/0001.sql', 'utf8');
    await db.batch(unstable_splitSqlQuery(extra).map((statement) => db.prepare(statement)));
    await db.batch([
      db.prepare('CREATE TABLE fixture_installation_fault(id INTEGER PRIMARY KEY,mode TEXT)'),
      db.prepare("INSERT INTO account_security VALUES('account',1,1)"),
      db.prepare("INSERT INTO credential VALUES('credential','account',1)"),
      db.prepare(
        "INSERT INTO sso_session VALUES('session','account','credential',1,unixepoch()+3600,0)",
      ),
      db.prepare('INSERT INTO sso_context VALUES(?,?,unixepoch())').bind('session', hash),
      db.prepare(
        "INSERT INTO client(client_id,revision,active,client_type,auth_method,allow_missing_pkce,sector_identifier) VALUES('dfd936fd-f33d-4f82-ae39-f25e08ec7948',1,1,'native','none',0,'app.mikaki.org')",
      ),
      db.prepare(
        "INSERT INTO client_redirect_uri VALUES('dfd936fd-f33d-4f82-ae39-f25e08ec7948','https://app.mikaki.org/oidc/native/callback',1)",
      ),
    ]);
    async function send(path, body, dpop, withCookie = true) {
      return mf.dispatchFetch(origin + path, {
        method: 'POST',
        headers: {
          origin,
          'content-type': 'application/json',
          'x-mikaki-app': '1',
          dpop,
          ...(withCookie ? { cookie: `__Host-op-sso=${cookie}` } : {}),
        },
        body: JSON.stringify(body),
      });
    }
    const start = '/native/installations/start',
      complete = '/native/installations/complete',
      status = '/native/installations/status';
    assert.equal((await send(start, {}, proof(start), false)).status, 401);
    const startProof = proof(start);
    const response = await send(start, {}, startProof);
    assert.equal(response.status, 200, await response.clone().text());
    const pending = await response.json();
    assert.equal((await send(start, {}, startProof)).status, 409);
    assert.equal((await send(complete, { id: pending.id }, proof(complete, 'wrong'))).status, 400);
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const otherPublic = other.publicKey.export({ format: 'jwk' });
    const otherJwk = { kty: 'EC', crv: 'P-256', x: otherPublic.x, y: otherPublic.y };
    assert.equal(
      (
        await send(
          complete,
          { id: pending.id },
          proof(complete, pending.nonce, randomUUID(), other, otherJwk),
        )
      ).status,
      400,
    );
    const results = await Promise.all([
      send(complete, { id: pending.id }, proof(complete, pending.nonce)),
      send(complete, { id: pending.id }, proof(complete, pending.nonce)),
    ]);
    assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
    assert.equal((await results.find((r) => r.status === 200).json()).status, 'active');
    assert.equal(
      (await send(complete, { id: pending.id }, proof(complete, pending.nonce))).status,
      409,
    );
    // Invoke the same Rust proof builder used by the Android adapter. This
    // signer deliberately uses a public fixed fixture key, not Android Keystore.
    function nativeProof(nonce = null, status = false) {
      return execFileSync(resolve('target/debug/examples/installation_native_probe'), [], {
        input: JSON.stringify({
          jti: randomBytes(32).toString('base64url'),
          now: Math.floor(Date.now() / 1000),
          nonce,
          status,
        }),
        encoding: 'utf8',
        timeout: 10000,
      }).trim();
    }
    const nativeStart = await send(start, {}, nativeProof());
    assert.equal(nativeStart.status, 200, await nativeStart.clone().text());
    const nativeChallenge = await nativeStart.json();
    const incorrectNonce = randomBytes(32).toString('base64url');
    assert.equal(
      (await send(complete, { id: nativeChallenge.id }, nativeProof(incorrectNonce))).status,
      400,
    );
    const nativeStatus = () => nativeProof(null, true);
    const preStatus = await send(status, { id: nativeChallenge.id }, nativeStatus());
    assert.equal(preStatus.status, 200);
    assert.equal((await preStatus.json()).status, 'pending');
    assert.equal((await send(status, { id: nativeChallenge.id }, proof(status))).status, 409);
    const nativeCompleteProof = nativeProof(nativeChallenge.nonce);
    await db.prepare("INSERT INTO fixture_installation_fault VALUES(1,'lost_reply')").run();
    const lostResponse = await send(complete, { id: nativeChallenge.id }, nativeCompleteProof);
    assert.equal(lostResponse.status, 500);
    const statusProof = nativeStatus();
    const recovered = await send(status, { id: nativeChallenge.id }, statusProof);
    assert.equal(recovered.status, 200, await recovered.clone().text());
    assert.equal((await recovered.json()).status, 'active');
    assert.equal((await send(status, { id: nativeChallenge.id }, statusProof)).status, 409);
    await db.prepare("INSERT INTO fixture_installation_fault VALUES(1,'session')").run();
    assert.equal((await send(status, { id: nativeChallenge.id }, nativeStatus())).status, 409);
    await db.prepare("UPDATE sso_session SET revoked=0 WHERE sso_id='session'").run();
    await db
      .prepare("UPDATE installation_device SET state='revoked' WHERE id=?")
      .bind(nativeChallenge.id)
      .run();
    const revokedStatus = await send(status, { id: nativeChallenge.id }, nativeStatus());
    assert.equal(revokedStatus.status, 200);
    assert.equal((await revokedStatus.json()).status, 'revoked');
    await db
      .prepare("UPDATE installation_device SET state='active' WHERE id=?")
      .bind(nativeChallenge.id)
      .run();

    const header = JSON.parse(
      Buffer.from(nativeCompleteProof.split('.')[0], 'base64url').toString(),
    );
    const { x: nativeX, y: nativeY } = header.jwk;
    const nativeThumbprint = createHash('sha256')
      .update(JSON.stringify({ crv: 'P-256', kty: 'EC', x: nativeX, y: nativeY }))
      .digest('base64url');
    assert.equal(
      (
        await db
          .prepare('SELECT thumbprint FROM installation_device WHERE id=?')
          .bind(nativeChallenge.id)
          .first()
      ).thumbprint,
      nativeThumbprint,
    );

    assert.equal(
      (await send(complete, { id: nativeChallenge.id }, nativeCompleteProof)).status,
      409,
    );
    assert.equal((await db.prepare('SELECT count(*) AS n FROM installation_device').first()).n, 2);
    // Optional local emulator qualification. The instrumented test package has
    // its own identity and synthetic key; it is not the production app key.
    // Drive the native transaction state through the actual qualification
    // Worker, including a committed completion whose response is lost.
    const child = spawn(resolve('target/debug/examples/installation_transaction_probe'), [], {
      stdio: ['pipe', 'pipe', 'inherit'],
    });
    const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
    const exchange = async (input) => {
      child.stdin.write(`${JSON.stringify(input)}\n`);
      const timer = AbortSignal.timeout(10000);
      const next = await Promise.race([
        lines.next(),
        new Promise((_, reject) =>
          timer.addEventListener('abort', () => reject(new Error('native fixture timeout')), {
            once: true,
          }),
        ),
      ]);
      assert.equal(next.done, false);
      const parsed = JSON.parse(next.value);
      assert.equal(parsed.error, undefined);
      return parsed;
    };
    const jti = () => randomBytes(32).toString('base64url');
    const now = () => Math.floor(Date.now() / 1000);
    try {
      const started = await exchange({ action: 'start', jti: jti(), now: now() });
      const startReply = await send(start, {}, started.proof);
      assert.equal(startReply.status, 200, await startReply.clone().text());
      const challenge = await startReply.json();
      const completion = await exchange({
        action: 'challenge',
        response: challenge,
        jti: jti(),
        now: now(),
      });
      assert.equal(completion.id, challenge.id);
      await db.prepare("INSERT INTO fixture_installation_fault VALUES(1,'lost_reply')").run();
      const lost = await send(complete, { id: completion.id }, completion.proof);
      assert.equal(lost.status, 500);
      const query = await exchange({ action: 'status', jti: jti(), now: now() });
      assert.equal(query.id, challenge.id);
      const queryReply = await send(status, { id: query.id }, query.proof);
      assert.equal(queryReply.status, 200, await queryReply.clone().text());
      const result = await exchange({ action: 'result', response: await queryReply.json() });
      assert.equal(result.status, 'active');
      assert.equal((await send(status, { id: query.id }, query.proof)).status, 409);
    } finally {
      child.stdin.end();
      child.kill();
    }
    let expectedDevices = 3;
    const serial = process.env.MIKAKI_ANDROID_KEYSTORE_SERIAL;
    if (serial) {
      const adb = process.env.MIKAKI_ANDROID_ADB;
      assert.ok(adb && adb.startsWith('/'), 'set an absolute MIKAKI_ANDROID_ADB path');
      const keyId = randomBytes(16).toString('hex');
      const invoke = (mode, input) => {
        const args = [
          '-s',
          serial,
          'shell',
          'am',
          'instrument',
          '-w',
          '-r',
          '-e',
          'class',
          'app.mikaki.native_dpop.InstallationProbeTest#perform',
          '-e',
          'probe_mode',
          mode,
          '-e',
          'probe_id',
          keyId,
        ];
        if (input) args.push('-e', 'probe_input', input);
        args.push('app.mikaki.native_dpop.test/androidx.test.runner.AndroidJUnitRunner');
        const out = execFileSync(adb, args, { encoding: 'utf8', timeout: 60000 });
        assert.match(out, /OK \(1 test\)/);
        const match = out.match(/^INSTRUMENTATION_STATUS: probe_result=(.+)\r?$/m);
        assert.ok(match, out);
        return match[1].trim();
      };
      let created = false;
      try {
        created = true; // Clean up even if the create response is lost.
        const [x, y] = invoke('create').split('.');
        const jwk = { kty: 'EC', crv: 'P-256', x, y };
        const publicKey = createPublicKey({ key: jwk, format: 'jwk' });
        const androidProof = (path, nonce) => {
          const claims = {
            htm: 'POST',
            htu: origin + path,
            iat: Math.floor(Date.now() / 1000),
            jti: randomUUID(),
          };
          if (nonce) claims.nonce = nonce;
          const payload = `${enc({ typ: 'dpop+jwt', alg: 'ES256', jwk })}.${enc(claims)}`;
          const der = Buffer.from(invoke('sign', payload), 'base64url');
          assert.ok(verify('sha256', Buffer.from(payload), publicKey, der));
          // DER ECDSA SEQUENCE of two minimally encoded positive P-256 integers.
          assert.equal(der[0], 0x30);
          assert.equal(der[1], der.length - 2);
          let offset = 2;
          const integer = () => {
            assert.equal(der[offset++], 2);
            const length = der[offset++];
            const bytes = der.subarray(offset, offset + length);
            offset += length;
            assert.ok(length >= 1 && length <= 33 && !(bytes[0] & 0x80));
            assert.ok(length === 1 || bytes[0] !== 0 || bytes[1] & 0x80);
            const value = length === 33 ? bytes.subarray(1) : bytes;
            assert.ok(value.length <= 32);
            return Buffer.concat([Buffer.alloc(32 - value.length), value]);
          };
          const raw = Buffer.concat([integer(), integer()]);
          assert.equal(offset, der.length);
          return `${payload}.${raw.toString('base64url')}`;
        };
        const started = await send(start, {}, androidProof(start));
        assert.equal(started.status, 200, await started.clone().text());
        const challenge = await started.json();
        const finished = await send(
          complete,
          { id: challenge.id },
          androidProof(complete, challenge.nonce),
        );
        assert.equal(finished.status, 200, await finished.clone().text());
        assert.equal((await finished.json()).status, 'active');
        const checked = await send(status, { id: challenge.id }, androidProof(status));
        assert.equal(checked.status, 200, await checked.clone().text());
        assert.equal((await checked.json()).status, 'active');
        expectedDevices++;
      } finally {
        if (created) assert.equal(invoke('delete'), 'deleted');
      }
    }
    const next = await send(start, {}, proof(start));
    const pending2 = await next.json();
    // Invalidate authority after the owner and pending reads but before D1's
    // completion batch. None of these attempts may consume the challenge.
    const resets = {
      session: "UPDATE sso_session SET revoked=0 WHERE sso_id='session'",
      expiry: "UPDATE sso_session SET expires_at=unixepoch()+3600 WHERE sso_id='session'",
      dbsc: "DELETE FROM dbsc_session WHERE session_id='dbsc'",
      account: "UPDATE account_security SET active=1 WHERE account_id='account'",
      epoch: "UPDATE account_security SET epoch=1 WHERE account_id='account'",
      credential: "UPDATE credential SET active=1 WHERE credential_id='credential'",
      client: 'UPDATE client SET active=1,revision=revision+1',
      redirect: 'UPDATE client_redirect_uri SET active=1',
    };
    for (const [mode, reset] of Object.entries(resets)) {
      await db.prepare('INSERT INTO fixture_installation_fault VALUES(1,?)').bind(mode).run();
      const attempted = proof(complete, pending2.nonce);
      assert.equal((await send(complete, { id: pending2.id }, attempted)).status, 409, mode);
      assert.equal(
        (
          await db
            .prepare('SELECT consumed FROM installation_pending WHERE id=?')
            .bind(pending2.id)
            .first()
        ).consumed,
        0,
        mode,
      );
      await db.prepare(reset).run();
    }
    // The same key was already registered above. The final insert fails its
    // unique constraint after the preceding update and replay insert; the D1
    // batch must roll both writes back.
    const replayId = randomUUID();
    const replayHash = createHash('sha256').update(replayId).digest('base64url');
    const duplicate = await send(
      complete,
      { id: pending2.id },
      proof(complete, pending2.nonce, replayId),
    );
    assert.equal(duplicate.status, 500);
    assert.equal(
      (
        await db
          .prepare('SELECT consumed FROM installation_pending WHERE id=?')
          .bind(pending2.id)
          .first()
      ).consumed,
      0,
    );
    assert.equal(
      await db
        .prepare('SELECT jti_hash FROM installation_proof_use WHERE jti_hash=?')
        .bind(replayHash)
        .first(),
      null,
    );
    await db.prepare("UPDATE sso_session SET revoked=1 WHERE sso_id='session'").run();
    assert.equal(
      (await send(complete, { id: pending2.id }, proof(complete, pending2.nonce))).status,
      401,
    );
    assert.equal(
      (await db.prepare('SELECT count(*) AS n FROM installation_device').first()).n,
      expectedDevices,
    );
    assert.equal(
      (
        await db
          .prepare('SELECT consumed FROM installation_pending WHERE id=?')
          .bind(pending2.id)
          .first()
      ).consumed,
      0,
    );
  } finally {
    await mf.dispose();
  }
});
