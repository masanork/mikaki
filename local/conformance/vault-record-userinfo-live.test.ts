/** CI-only runtime qualification: real Rust Workers, disposable Secrets Store and browser WebCrypto. */
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { chromium } from '@playwright/test';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { OwnerKeySession } from '../../crates/worker/ui/vault-owner-session.ts';
import { VaultScope } from '../../crates/worker/ui/vault-lifecycle.ts';
import { vaultCiphertextDigest } from '../../crates/worker/ui/vault-record-source.ts';
import { fetchVerifiedRecordUserInfoRecipient } from '../../crates/worker/ui/recipient-directory-v2.ts';
import { encodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';
import { activateWorkerPolicy } from '../../scripts/worker-policy-store.ts';
const root = fileURLToPath(new URL('../..', import.meta.url));
const secretName = 'VAULT_USERINFO_MLKEM_TEST';
const digest = (v: Uint8Array | string) => createHash('sha256').update(v).digest('base64url');
async function createLocalSecret(state: string, storeId: string, value: string) {
  // Use an isolated config so Wrangler cannot discover repository production bindings.
  const config = join(state, 'wrangler.json');
  await writeFile(
    config,
    JSON.stringify({
      name: 'record-userinfo-local-test',
      compatibility_date: '2026-09-23',
      send_metrics: false,
    }),
  );
  const child = spawn(
    process.execPath,
    [
      join(root, 'node_modules/wrangler/bin/wrangler.js'),
      '--config',
      config,
      'secrets-store',
      'secret',
      'create',
      storeId,
      '--name',
      secretName,
      '--scopes',
      'workers',
      '--remote=false',
      '--persist-to',
      state,
    ],
    {
      cwd: state,
      env: {
        ...process.env,
        CI: 'true',
        WRANGLER_SEND_METRICS: 'false',
        WRANGLER_LOG_PATH: join(state, 'wrangler.log'),
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  // Do not put the seed in command arguments, fixture files, or test output.
  child.stdin.end(`${value}\n`);
  let output = '';
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', (chunk: Buffer) => {
      output += chunk.toString();
    });
  }
  const [exitCode] = await once(child, 'exit');
  assert.equal(exitCode, 0, `local Secrets Store setup failed: ${output.slice(-500)}`);
  const secretId = output.match(new RegExp(`│\\s*${secretName}\\s*│\\s*([a-f0-9]{32})\\s*│`))?.[1];
  assert.ok(secretId, 'local Secrets Store did not return a secret ID');
  return secretId;
}

type ProfileBenchmarkReport = {
  schema_version: 1;
  scope: 'local_synthetic_userinfo_only';
  production_capacity_qualified: false;
  full_auth_flow_measured: false;
  production_build_performance: false;
  authentication: 'preprovisioned_synthetic_sso_client_and_token';
  claims_worker_build: 'conformance_gate_instrumented';
  measured_source_head: string;
  tracked_source_clean: boolean;
  source: { storage_version: 2; kind: 'name'; revision: 1 };
  passed: boolean;
  failure_phase: string | null;
  cleanup_ok: boolean;
  phases: Array<{
    phase: string;
    sample: number;
    status: number | null;
    duration_ms: number | null;
    expected_shape: 'sub_only' | 'name' | 'fail_closed';
    passed: boolean;
  }>;
  summary: Record<string, unknown>;
};

const profilePercentile = (values: number[], fraction: number) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] ?? null;
};

async function qualifyRecordUserInfo(browserCrypto: boolean, profileBenchmark = false) {
  const temporary = await mkdtemp(join(tmpdir(), 'mikaki-record-userinfo-'));
  let mf: Miniflare | undefined;
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  let releaseGate: (() => void) | undefined;
  let failurePhase: string | null = profileBenchmark ? 'setup' : null;
  let testFailed = false;
  let cleanupOk = true;
  const benchmarkDeadline = profileBenchmark ? performance.now() + 180_000 : 0;
  const benchmark: ProfileBenchmarkReport | undefined = profileBenchmark
    ? {
        schema_version: 1,
        scope: 'local_synthetic_userinfo_only',
        production_capacity_qualified: false,
        full_auth_flow_measured: false,
        production_build_performance: false,
        authentication: 'preprovisioned_synthetic_sso_client_and_token',
        claims_worker_build: 'conformance_gate_instrumented',
        measured_source_head: 'unavailable',
        tracked_source_clean: false,
        source: { storage_version: 2, kind: 'name', revision: 1 },
        passed: false,
        failure_phase: null,
        cleanup_ok: true,
        phases: [],
        summary: {},
      }
    : undefined;
  try {
    if (benchmark) {
      benchmark.measured_source_head = execFileSync('git', ['rev-parse', 'HEAD'], {
        cwd: root,
        encoding: 'utf8',
      }).trim();
      benchmark.tracked_source_clean =
        execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], {
          cwd: root,
          encoding: 'utf8',
        }).trim() === '';
    }
    const seed = randomBytes(64),
      storeId = randomBytes(16).toString('hex');
    await createLocalSecret(temporary, storeId, seed.toString('base64url'));
    const keys = ml_kem768.keygen(seed);
    seed.fill(0);
    const keyId = digest(keys.publicKey);
    const origin = 'https://mikaki.test';
    let beforeAudit: (() => Promise<void>) | undefined;
    let claimFailure: 'none' | 'throw' | 'unavailable' | 'missing-secret' = 'none';
    const claimBuild = join(root, 'crates/userinfo-claim-worker/build-conformance');
    const opBuild = join(root, 'crates/worker/build');
    const authorityBuild = join(temporary, 'authority');
    await mkdir(authorityBuild);
    await build({
      entryPoints: [join(root, 'crates/worker/service/entrypoint.ts')],
      outfile: join(authorityBuild, 'index.js'),
      bundle: true,
      format: 'esm',
      platform: 'browser',
      target: 'es2022',
      external: ['cloudflare:workers'],
      loader: { '.sql': 'text' },
      plugins: [
        {
          name: 'wasm-reference',
          setup(builder) {
            builder.onResolve({ filter: /\.wasm$/ }, () => ({
              path: './index_bg.wasm',
              external: true,
            }));
          },
        },
      ],
    });
    const options = convertV4MiniflareOptions({
      name: 'mikaki-userinfo-claim-worker',
      compatibilityDate: '2026-09-23',
      modules: true,
      scriptPath: join(claimBuild, 'index.js'),
      modulesRoot: claimBuild,
      resourcePersistencePath: join(temporary, 'v3'),
      bindings: { MIKAKI_ISSUER: origin },
      serviceBindings: {
        CLAIM_STORE: { name: 'mikaki-op-worker', entrypoint: 'ClaimStore' },
        CONFORMANCE_GATE: async () => {
          await beforeAudit?.();
          return new Response(null, { status: 200 });
        },
      },
      secretsStoreSecrets: { [secretName]: { store_id: storeId, secret_name: secretName } },
    });
    options.workers[0].config.manifest!.modules['index_bg.wasm'] = {
      type: 'wasm',
      contents: new Uint8Array(await readFile(join(claimBuild, 'index_bg.wasm'))),
    };
    const opOptions = convertV4MiniflareOptions({
      name: 'mikaki-op-worker',
      // Register only this synthetic host with Miniflare's local request proxy.
      routes: ['mikaki.test/*'],
      compatibilityDate: '2026-09-23',
      modules: true,
      scriptPath: join(authorityBuild, 'index.js'),
      modulesRoot: authorityBuild,
      bindings: { MIKAKI_ISSUER: origin },
      d1Databases: { DB: 'record-userinfo' },
      r2Buckets: { VAULT_BLOBS: 'record-userinfo' },
      serviceBindings: {
        USERINFO_CLAIMS: async (request, runtime) => {
          if (claimFailure === 'throw') throw new Error('simulated claim transport failure');
          if (claimFailure === 'unavailable') return new Response(null, { status: 503 });
          const name =
            claimFailure === 'missing-secret'
              ? 'claims-without-secret'
              : 'mikaki-userinfo-claim-worker';
          return (await runtime.getWorker(name)).fetch(request);
        },
      },
    });
    opOptions.workers[0].config.manifest!.modules['index_bg.wasm'] = {
      type: 'wasm',
      contents: new Uint8Array(await readFile(join(opBuild, 'index_bg.wasm'))),
    };
    const noSecret = convertV4MiniflareOptions({
      name: 'claims-without-secret',
      compatibilityDate: '2026-09-23',
      modules: true,
      scriptPath: join(claimBuild, 'index.js'),
      modulesRoot: claimBuild,
      bindings: { MIKAKI_ISSUER: origin },
      serviceBindings: { CLAIM_STORE: { name: 'mikaki-op-worker', entrypoint: 'ClaimStore' } },
    });
    noSecret.workers[0].config.manifest!.modules['index_bg.wasm'] =
      options.workers[0].config.manifest!.modules['index_bg.wasm'];
    options.workers.push(noSecret.workers[0]);
    options.workers.unshift(opOptions.workers[0]);
    mf = new Miniflare(options);
    const db = await mf.getD1Database('DB'),
      blobs = await mf.getR2Bucket('VAULT_BLOBS');
    for (const name of (await readdir(join(root, 'crates/worker/migrations')))
      .filter((n) => n.endsWith('.sql'))
      .sort())
      await db.batch(
        splitSqlQuery(await readFile(join(root, 'crates/worker/migrations', name), 'utf8')).map(
          (s) => db.prepare(s),
        ),
      );
    await activateWorkerPolicy(
      db,
      JSON.parse(await readFile(join(root, 'local/generated/worker-policy.json'), 'utf8')),
      { actor: 'record-userinfo-test', reason: 'Isolated v2 profile qualification' },
    );
    const now = Math.floor(Date.now() / 1000),
      cookie = randomBytes(32).toString('base64url'),
      access = randomBytes(32).toString('base64url');
    await db.batch([
      db.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      db.prepare("INSERT INTO credential VALUES('AQ','owner',1)"),
      db.prepare("INSERT INTO sso_session VALUES('sso','owner','AQ',1,?,0)").bind(now + 3600),
      db.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(digest(cookie), now),
      db.prepare(
        "INSERT INTO client(client_id,revision,active,sector_identifier) VALUES('rp',1,1,'https://rp.test')",
      ),
      db.prepare(
        "INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES('rp','https://rp.test/callback')",
      ),
      db.prepare("INSERT INTO app_connection VALUES('owner','rp',1,1)"),
      db.prepare("INSERT INTO client_session VALUES('rp','sid','sso','owner','pairwise',1,0)"),
      db.prepare("INSERT INTO signing_key VALUES('op',1,1,'ES256','{}')"),
      db
        .prepare(
          "INSERT INTO authorization_code(code_hash,client_id,sid,client_revision,redirect_uri,pkce_challenge,expires_at,consumed_by,consumed_at) VALUES(?,'rp','sid',1,'https://rp.test/callback','',?,'issue',?)",
        )
        .bind(digest('code'), now + 60, now),
      db
        .prepare("INSERT INTO code_context(code_hash,nonce,scope) VALUES(?,NULL,'openid profile')")
        .bind(digest('code')),
      db
        .prepare(
          "INSERT INTO token_issue(code_hash,operation_id,access_hash,access_expires_at,signing_kid,issued_at,revoked) VALUES(?,'issue',?,?,'op',?,0)",
        )
        .bind(digest('code'), digest(access), now + 3600, now),
      db
        .prepare(
          "INSERT INTO vault_recipient_key(key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at) VALUES(?,'userinfo','ML-KEM-768',?,?,1,'staged',1,?)",
        )
        .bind(keyId, keys.publicKey, secretName, now),
    ]);
    await db
      .prepare(
        "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=? WHERE key_id=?",
      )
      .bind(now, keyId)
      .run();
    const op = await mf.getWorker('mikaki-op-worker');
    const userinfo = () =>
      op.fetch(origin + '/userinfo', { headers: { Authorization: `Bearer ${access}` } });
    assert.deepEqual(await (await userinfo()).json(), { sub: 'pairwise' });
    const audits = () =>
      db.prepare('SELECT count(*) AS n FROM vault_claim_disclosure_audit').first<number>('n');
    const profileRequest = async (
      phase: string,
      sample: number,
      expectedShape: 'sub_only' | 'name',
      expected: Record<string, string>,
    ) => {
      if (!benchmark) throw new Error('profile_benchmark_not_enabled');
      const remainingMs = benchmarkDeadline - performance.now();
      if (remainingMs <= 0) {
        failurePhase = phase;
        throw new Error('profile_benchmark_deadline');
      }
      const started = performance.now();
      let status: number | null = null;
      try {
        const response = await op.fetch(origin + '/userinfo', {
          headers: { Authorization: `Bearer ${access}` },
          signal: AbortSignal.timeout(Math.min(10_000, remainingMs)),
        });
        status = response.status;
        const body: unknown = await response.json();
        const expectedKeys = Object.keys(expected).sort();
        const bodyRecord =
          typeof body === 'object' && body !== null && !Array.isArray(body)
            ? (body as Record<string, unknown>)
            : null;
        const actualKeys = bodyRecord ? Object.keys(bodyRecord).sort() : [];
        const passed =
          status === 200 &&
          actualKeys.length === expectedKeys.length &&
          actualKeys.every((key, index) => key === expectedKeys[index]) &&
          expectedKeys.every((key) => bodyRecord?.[key] === expected[key]);
        benchmark.phases.push({
          phase,
          sample,
          status,
          duration_ms: Math.round((performance.now() - started) * 1000) / 1000,
          expected_shape: expectedShape,
          passed,
        });
        if (!passed) throw new Error('profile_benchmark_response_mismatch');
      } catch {
        if (!benchmark.phases.some((row) => row.phase === phase && row.sample === sample))
          benchmark.phases.push({
            phase,
            sample,
            status,
            duration_ms: Math.round((performance.now() - started) * 1000) / 1000,
            expected_shape: expectedShape,
            passed: false,
          });
        failurePhase = phase;
        throw new Error('profile_benchmark_request_failed');
      }
    };
    const profileSeries = async (
      phase: 'preconsent' | 'consented',
      expectedShape: 'sub_only' | 'name',
      expected: Record<string, string>,
    ) => {
      const warmupCount = 2;
      const sampleCount = 20;
      for (let index = 1; index <= warmupCount; index++)
        await profileRequest(`${phase}_warmup`, index, expectedShape, expected);
      for (let index = 1; index <= sampleCount; index++)
        await profileRequest(`${phase}_sample`, index, expectedShape, expected);
      const measurements = benchmark!.phases.filter((row) => row.phase === `${phase}_sample`);
      assert.equal(measurements.length, sampleCount);
      assert.ok(measurements.every((row) => row.passed && row.status === 200));
      const durations = measurements.map((row) => row.duration_ms!);
      benchmark!.summary[phase] = {
        warmups: warmupCount,
        samples: sampleCount,
        requests: warmupCount + sampleCount,
        status_counts: { '200': warmupCount + sampleCount },
        latency_ms: {
          p50: profilePercentile(durations, 0.5),
          p95: profilePercentile(durations, 0.95),
          p99: profilePercentile(durations, 0.99),
        },
      };
    };
    let prepared: any;
    if (browserCrypto) {
      const bundle = await build({
        stdin: {
          resolveDir: root,
          contents: `
import { OwnerKeySession } from './crates/worker/ui/vault-owner-session.ts';
import { VaultScope } from './crates/worker/ui/vault-lifecycle.ts';
import { vaultCiphertextDigest } from './crates/worker/ui/vault-record-source.ts';
import { fetchVerifiedRecordUserInfoRecipient } from './crates/worker/ui/recipient-directory-v2.ts';
import { encodeBase64Url } from './crates/worker/ui/vault-crypto.ts';
window.recordProbe=async()=>{
 const identity={account_id:'owner',credential_id:'AQ',session_tag:'s'.repeat(43)};
 const scope=new VaultScope(()=>{},undefined,undefined,async()=>Response.json(identity));scope.observe(identity);
 const context={origin:'https://mikaki.test',ownerId:'owner',vaultId:'vault',keyGeneration:1};
 const session=new OwnerKeySession(scope,context);let ceremonies=0;
 const ownerEnvelope=await session.initialize(async()=>{ceremonies++;return{credentialId:new Uint8Array([1]),output:new Uint8Array(32).fill(4)}});
 const record=await session.seal(new TextEncoder().encode('Alice 山田 😀'),{collectionId:'personal',recordId:'name',kind:'name',revision:1});
 const source={storage_version:2,origin:context.origin,owner_id:'owner',vault_id:'vault',collection_id:'personal',record_id:'name',kind:'name',revision:1,ciphertext_sha256:await vaultCiphertextDigest(record.ciphertext)};
 const authority={key_generation:1,owner_key_revision:1};const recipient=await fetchVerifiedRecordUserInfoRecipient(fetch,localStorage);
 const frame=encodeBase64Url(await session.sealUserInfoRecipient(record,source,authority,recipient));
 const pending=session.sealUserInfoRecipient(record,source,authority,recipient);session.suspend();let rejected=false;try{await pending}catch{rejected=true}if(!rejected)throw new Error('late result escaped');session.dispose();
 return{ownerEnvelope,record,source,authority,recipient,frame,ceremonies,lateRejected:rejected};
};`,
        },
        bundle: true,
        write: false,
        format: 'iife',
        platform: 'browser',
      });
      browser = await chromium.launch();
      const page = await browser.newPage();
      await page.context().addCookies([
        {
          name: '__Host-op-sso',
          value: cookie,
          url: origin,
          secure: true,
          httpOnly: true,
          sameSite: 'Lax',
        },
      ]);
      await page.route(origin + '/**', async (route) => {
        const request = route.request();
        const path = new URL(request.url()).pathname;
        if (path === '/probe') {
          await route.fulfill({
            status: 200,
            contentType: 'text/html',
            body: '<!doctype html><script src="/probe.js"></script>',
          });
          return;
        }
        if (path === '/probe.js') {
          await route.fulfill({
            status: 200,
            contentType: 'text/javascript',
            body: bundle.outputFiles[0]!.text,
          });
          return;
        }
        const response = await op.fetch(request.url(), {
          method: request.method(),
          headers: await request.allHeaders(),
          body: request.postDataBuffer() ?? undefined,
        });
        await route.fulfill({
          status: response.status,
          headers: Object.fromEntries(response.headers.entries()),
          body: Buffer.from(await response.arrayBuffer()),
        });
      });
      await page.goto(origin + '/probe');
      prepared = await page.evaluate(() =>
        (window as unknown as { recordProbe: () => Promise<any> }).recordProbe(),
      );
    } else {
      const identity = { account_id: 'owner', credential_id: 'AQ', session_tag: 's'.repeat(43) };
      const scope = new VaultScope(
        () => {},
        undefined,
        undefined,
        async () => Response.json(identity),
      );
      scope.observe(identity);
      const context = { origin, ownerId: 'owner', vaultId: 'vault', keyGeneration: 1 };
      const session = new OwnerKeySession(scope, context);
      let ceremonies = 0;
      const ownerEnvelope = await session.initialize(async () => {
        ceremonies++;
        return { credentialId: new Uint8Array([1]), output: new Uint8Array(32).fill(4) };
      });
      const record = await session.seal(new TextEncoder().encode('Alice 山田 😀'), {
        collectionId: 'personal',
        recordId: 'name',
        kind: 'name',
        revision: 1,
      });
      const source = {
        storage_version: 2 as const,
        origin,
        owner_id: 'owner',
        vault_id: 'vault',
        collection_id: 'personal' as const,
        record_id: 'name' as const,
        kind: 'name' as const,
        revision: 1,
        ciphertext_sha256: await vaultCiphertextDigest(record.ciphertext),
      };
      const authority = { key_generation: 1, owner_key_revision: 1 };
      const storage = new Map<string, string>();
      const recipient = await fetchVerifiedRecordUserInfoRecipient(
        (async (input: string | URL | Request, init?: RequestInit) => {
          const requestHeaders = new Headers(init?.headers);
          requestHeaders.set('Cookie', `__Host-op-sso=${cookie}`);
          const response = await op.fetch(new URL(String(input), origin), {
            method: init?.method ?? 'GET',
            headers: Object.fromEntries(requestHeaders.entries()),
          });
          return new Response(await response.arrayBuffer(), {
            status: response.status,
            headers: Object.fromEntries(response.headers.entries()),
          });
        }) as typeof fetch,
        {
          getItem: (key) => storage.get(key) ?? null,
          setItem: (key, value) => {
            storage.set(key, value);
          },
        },
      );
      const frame = encodeBase64Url(
        await session.sealUserInfoRecipient(record, source, authority, recipient),
      );
      const pending = session.sealUserInfoRecipient(record, source, authority, recipient);
      session.suspend();
      let lateRejected = false;
      try {
        await pending;
      } catch {
        lateRejected = true;
      }
      session.dispose();
      prepared = {
        ownerEnvelope,
        record,
        source,
        authority,
        recipient,
        frame,
        ceremonies,
        lateRejected,
      };
    }
    assert.equal(prepared.ceremonies, 1);
    assert.equal(prepared.lateRejected, true);
    await blobs.put('record-blob', Buffer.from(prepared.record.ciphertext, 'base64url'));
    await db.batch([
      db
        .prepare(
          "INSERT INTO vault_owner_key_head VALUES('owner','vault',?,1,1,2,'PRF-HKDF-SHA256-AES256GCM-v2',?,?,?)",
        )
        .bind(origin, digest('root-op'), digest('root-body'), now),
      db
        .prepare("INSERT INTO vault_owner_key_wrap VALUES('owner',1,'AQ',?)")
        .bind(JSON.stringify(prepared.ownerEnvelope)),
      db
        .prepare(
          "INSERT INTO vault_owner_record_head VALUES('owner','vault','personal','name','name',1,1,2,'record-blob',?,?,0,?)",
        )
        .bind(prepared.source.ciphertext_sha256, prepared.record.key_envelope, now),
    ]);
    const operation = () => randomBytes(32).toString('base64url');
    const headers = (id: string, version: number) => ({
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: origin,
      'Content-Type': 'application/json',
      'X-Operation-ID': id,
      'If-Match': `"${version}"`,
    });
    const sharing = origin + '/vault/records/personal/name/sharing',
      releases = origin + '/vault/records/personal/name/releases';
    const sharingStatus = async (path: string) => {
      const result = await op.fetch(path, { headers: { Cookie: `__Host-op-sso=${cookie}` } });
      assert.equal(result.status, 200);
      assert.equal(result.headers.get('Cache-Control'), 'no-store');
      return result.json() as Promise<Record<string, unknown>>;
    };
    const shareBody = {
      source: prepared.source,
      authority: prepared.authority,
      key_id: keyId,
      generation: 1,
      directory_revision: 2,
      policy_revision: 2,
      expected_grant_version: 0,
      frame: prepared.frame,
    };
    const shareId = operation();
    const share = () =>
      op.fetch(sharing, {
        method: 'POST',
        headers: headers(shareId, 1),
        body: JSON.stringify(shareBody),
      });
    const disabledShare = await share();
    assert.equal(disabledShare.status, 403);
    assert.deepEqual(await disabledShare.json(), { error: 'sharing_disabled_or_changed' });
    assert.equal((await sharingStatus(sharing))['enabled'], false);
    await db.prepare('UPDATE vault_record_share_policy SET enabled=1,revision=2').run();
    let response = await share();
    assert.equal(response.status, 200, await response.text());
    assert.equal((await share()).status, 200);
    assert.equal(
      (
        await op.fetch(sharing, {
          method: 'POST',
          headers: headers(shareId, 1),
          body: JSON.stringify({ ...shareBody, directory_revision: 1 }),
        })
      ).status,
      409,
    );
    assert.deepEqual(await (await userinfo()).json(), { sub: 'pairwise' });
    const stale = await op.fetch(sharing, {
      method: 'POST',
      headers: headers(operation(), 1),
      body: JSON.stringify({ ...shareBody, expected_grant_version: 1, directory_revision: 1 }),
    });
    assert.equal(stale.status, 409);
    await db
      .prepare(
        "CREATE TRIGGER fail_share_audit BEFORE INSERT ON vault_record_share_audit BEGIN SELECT RAISE(ABORT,'test');END",
      )
      .run();
    const failed = await op.fetch(sharing, {
      method: 'POST',
      headers: headers(operation(), 1),
      body: JSON.stringify({ ...shareBody, expected_grant_version: 1 }),
    });
    assert.equal(failed.status, 409);
    assert.equal(
      await db.prepare('SELECT count(*) AS n FROM vault_record_recipient_envelope').first('n'),
      1,
    );
    await db.prepare('DROP TRIGGER fail_share_audit').run();
    await db.prepare('UPDATE vault_claim_release_policy SET enabled=1,revision=2').run();
    const systemStatus = await sharingStatus(sharing);
    assert.equal(systemStatus['enabled'], true);
    assert.equal(systemStatus['grant_ttl_seconds'], 604800);
    assert.equal((systemStatus['grant'] as Record<string, unknown>)['authority_current'], 1);
    assert.equal((systemStatus['grant'] as Record<string, unknown>)['recipient_key_id'], keyId);
    const beforeConsent = await sharingStatus(releases);
    assert.equal(beforeConsent['enabled'], true);
    assert.equal(beforeConsent['ttl_seconds'], 86400);
    const candidate = (beforeConsent['clients'] as Record<string, unknown>[])[0]!;
    assert.equal(candidate['client_id'], 'rp');
    assert.equal(candidate['release_status'], null);
    assert.equal(candidate['authority_current'], 0);
    if (profileBenchmark) {
      failurePhase = 'preconsent';
      await profileSeries('preconsent', 'sub_only', { sub: 'pairwise' });
      assert.equal(await audits(), 0, 'pre-consent profile requests must disclose no name');
    }
    const consentBody = {
      source: prepared.source,
      authority: prepared.authority,
      client_id: 'rp',
      client_revision: 1,
      connection_grant_version: 1,
      policy_revision: 2,
      expected_release_version: 0,
    };
    const consent = () =>
      op.fetch(releases, {
        method: 'POST',
        headers: headers(operation(), 1),
        body: JSON.stringify(consentBody),
      });
    response = await consent();
    assert.equal(response.status, 200, await response.text());
    assert.equal(
      ((await sharingStatus(releases))['clients'] as Record<string, unknown>[])[0]![
        'authority_current'
      ],
      1,
    );
    response = await userinfo();
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { sub: 'pairwise', name: 'Alice 山田 😀' });
    let expectedDisclosureAudits = 1;
    assert.equal(await audits(), expectedDisclosureAudits);
    if (profileBenchmark) {
      failurePhase = 'consented';
      await profileSeries('consented', 'name', { sub: 'pairwise', name: 'Alice 山田 😀' });
      expectedDisclosureAudits += 22;
      assert.equal(await audits(), expectedDisclosureAudits);
    }
    const assertUnavailable = async () => {
      const started = profileBenchmark ? performance.now() : 0;
      let status: number | null = null;
      const sample = benchmark
        ? benchmark.phases.filter((row) => row.phase === 'fail_closed').length + 1
        : 1;
      try {
        const result = await userinfo();
        status = result.status;
        assert.equal(result.status, 503);
        assert.equal(result.headers.get('Retry-After'), '5');
        assert.equal(result.headers.get('Cache-Control'), 'no-store');
        assert.equal(result.headers.get('WWW-Authenticate'), null);
        assert.ok(!(await result.text()).includes('Alice'));
        assert.equal(
          await audits(),
          expectedDisclosureAudits,
          'failure must not create disclosure evidence',
        );
        if (benchmark)
          benchmark.phases.push({
            phase: 'fail_closed',
            sample,
            status: result.status,
            duration_ms: Math.round((performance.now() - started) * 1000) / 1000,
            expected_shape: 'fail_closed',
            passed: true,
          });
      } catch (error) {
        if (benchmark) {
          failurePhase = 'fail_closed';
          if (!benchmark.phases.some((row) => row.phase === 'fail_closed' && row.sample === sample))
            benchmark.phases.push({
              phase: 'fail_closed',
              sample,
              status,
              duration_ms: Math.round((performance.now() - started) * 1000) / 1000,
              expected_shape: 'fail_closed',
              passed: false,
            });
          throw new Error('userinfo_fail_closed_contract_failed');
        }
        throw error;
      }
    };
    for (const failure of ['missing-secret', 'throw', 'unavailable'] as const) {
      claimFailure = failure;
      await assertUnavailable();
    }
    claimFailure = 'none';
    await blobs.put('record-blob', Buffer.from('tampered-ciphertext'));
    await assertUnavailable();
    await blobs.delete('record-blob');
    await assertUnavailable();
    await blobs.put('record-blob', Buffer.from(prepared.record.ciphertext, 'base64url'));
    const view = await db
      .prepare("SELECT sql FROM sqlite_master WHERE type='view' AND name='valid_client_session'")
      .first<string>('sql');
    assert.ok(view);
    await db.prepare('DROP VIEW valid_client_session').run();
    try {
      await assertUnavailable();
    } finally {
      await db.prepare(view).run();
    }
    const invalidTokenStarted = profileBenchmark ? performance.now() : 0;
    if (profileBenchmark) failurePhase = 'invalid_token';
    let invalidTokenStatus: number | null = null;
    try {
      const invalidToken = await op.fetch(origin + '/userinfo', {
        headers: { Authorization: `Bearer ${randomBytes(32).toString('base64url')}` },
      });
      invalidTokenStatus = invalidToken.status;
      const invalidTokenBody = await invalidToken.text();
      assert.equal(invalidToken.status, 401);
      assert.match(invalidToken.headers.get('WWW-Authenticate') ?? '', /Bearer.*invalid_token/);
      assert.equal(invalidToken.headers.get('Retry-After'), null);
      assert.ok(!invalidTokenBody.includes('Alice'));
      assert.equal(await audits(), expectedDisclosureAudits);
      if (benchmark)
        benchmark.phases.push({
          phase: 'invalid_token',
          sample: 1,
          status: invalidToken.status,
          duration_ms: Math.round((performance.now() - invalidTokenStarted) * 1000) / 1000,
          expected_shape: 'fail_closed',
          passed: true,
        });
    } catch (error) {
      if (benchmark) {
        failurePhase = 'invalid_token';
        if (!benchmark.phases.some((row) => row.phase === 'invalid_token'))
          benchmark.phases.push({
            phase: 'invalid_token',
            sample: 1,
            status: invalidTokenStatus,
            duration_ms: Math.round((performance.now() - invalidTokenStarted) * 1000) / 1000,
            expected_shape: 'fail_closed',
            passed: false,
          });
        throw new Error('userinfo_invalid_token_contract_failed');
      }
      throw error;
    }
    let entered!: () => void;
    const enteredPromise = new Promise<void>((resolve) => (entered = resolve));
    const resume = new Promise<void>((resolve) => (releaseGate = resolve));
    beforeAudit = async () => {
      entered();
      await resume;
    };
    if (profileBenchmark) failurePhase = 'post_release_inflight';
    const pending = userinfo();
    await Promise.race([
      enteredPromise,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('postdecrypt gate not reached')), 5000),
      ),
    ]);
    response = await op.fetch(releases, {
      method: 'DELETE',
      headers: headers(operation(), 1),
      body: JSON.stringify({ client_id: 'rp' }),
    });
    assert.equal(response.status, 200, await response.text());
    if (profileBenchmark) failurePhase = 'post_revoke';
    releaseGate!();
    beforeAudit = undefined;
    const pendingResponse = await pending;
    try {
      assert.equal(pendingResponse.status, 503);
      assert.equal(await audits(), expectedDisclosureAudits);
    } catch (error) {
      if (benchmark) {
        failurePhase = 'post_release_inflight';
        benchmark.phases.push({
          phase: 'post_revoke_inflight',
          sample: 1,
          status: pendingResponse.status,
          duration_ms: null,
          expected_shape: 'fail_closed',
          passed: false,
        });
        throw new Error('userinfo_post_revoke_inflight_contract_failed');
      }
      throw error;
    }
    if (benchmark) {
      const pendingText = await pendingResponse.text();
      if (pendingText.includes('Alice')) {
        failurePhase = 'post_release_inflight';
        benchmark.phases.push({
          phase: 'post_revoke_inflight',
          sample: 1,
          status: pendingResponse.status,
          duration_ms: null,
          expected_shape: 'fail_closed',
          passed: false,
        });
        throw new Error('userinfo_post_revoke_inflight_disclosed');
      }
      benchmark.phases.push({
        phase: 'post_revoke_inflight',
        sample: 1,
        status: pendingResponse.status,
        duration_ms: null,
        expected_shape: 'fail_closed',
        passed: true,
      });
      failurePhase = 'post_release_revoke';
      await profileRequest('post_release_revoke', 1, 'sub_only', { sub: 'pairwise' });
      assert.equal(await audits(), expectedDisclosureAudits);
      benchmark.summary['post_release_revoke'] = {
        requests: 1,
        status_counts: { '200': 1 },
        result: 'sub_only',
        audit_entries_unchanged: true,
        latency_ms: {
          p50:
            benchmark.phases.find((row) => row.phase === 'post_release_revoke')?.duration_ms ??
            null,
        },
      };
    } else {
      assert.deepEqual(await (await userinfo()).json(), { sub: 'pairwise' });
    }
    const withdrawn = ((await sharingStatus(releases))['clients'] as Record<string, unknown>[])[0]!;
    assert.equal(withdrawn['release_status'], 'revoked');
    assert.equal(withdrawn['authority_current'], 0);
    consentBody.expected_release_version = 2;
    response = await consent();
    assert.equal(response.status, 200, await response.text());
    await db
      .prepare(
        "CREATE TRIGGER fail_record_audit BEFORE INSERT ON vault_claim_disclosure_audit BEGIN SELECT RAISE(ABORT,'test'); END",
      )
      .run();
    const auditFailureStarted = profileBenchmark ? performance.now() : 0;
    if (profileBenchmark) failurePhase = 'fail_closed';
    const auditFailureSample = benchmark
      ? benchmark.phases.filter((row) => row.phase === 'fail_closed').length + 1
      : 1;
    let auditFailureStatus: number | null = null;
    try {
      const auditFailure = await userinfo();
      auditFailureStatus = auditFailure.status;
      assert.equal(auditFailure.status, 503);
      assert.equal(await audits(), expectedDisclosureAudits);
      if (benchmark)
        benchmark.phases.push({
          phase: 'fail_closed',
          sample: auditFailureSample,
          status: auditFailure.status,
          duration_ms: Math.round((performance.now() - auditFailureStarted) * 1000) / 1000,
          expected_shape: 'fail_closed',
          passed: true,
        });
    } catch (error) {
      if (benchmark) {
        failurePhase = 'fail_closed';
        if (
          !benchmark.phases.some(
            (row) => row.phase === 'fail_closed' && row.sample === auditFailureSample,
          )
        )
          benchmark.phases.push({
            phase: 'fail_closed',
            sample: auditFailureSample,
            status: auditFailureStatus,
            duration_ms: Math.round((performance.now() - auditFailureStarted) * 1000) / 1000,
            expected_shape: 'fail_closed',
            passed: false,
          });
        throw new Error('userinfo_audit_failure_contract_failed');
      }
      throw error;
    }
    await db.prepare('DROP TRIGGER fail_record_audit').run();
    await db
      .prepare(
        "UPDATE vault_recipient_key SET state='disabled',revision=3,retired_at=unixepoch() WHERE key_id=?",
      )
      .bind(keyId)
      .run();
    assert.deepEqual(await (await userinfo()).json(), { sub: 'pairwise' });
    assert.equal(
      (await share()).status,
      200,
      'historical exact receipt remains an acknowledgement',
    );
    assert.equal(
      await db.prepare('SELECT status FROM vault_record_grant').first('status'),
      'revoked',
    );
    assert.equal(await audits(), expectedDisclosureAudits);
    failurePhase = null;
  } catch (error) {
    testFailed = true;
    if (benchmark && failurePhase === null) failurePhase = 'contract';
    throw error;
  } finally {
    releaseGate?.();
    if (!benchmark) {
      await browser?.close();
      await mf?.dispose();
      await rm(temporary, { recursive: true, force: true });
    } else {
      const cleanup = async (work: () => Promise<unknown>) => {
        try {
          await work();
          return true;
        } catch {
          return false;
        }
      };
      const browserClosed = browser ? await cleanup(() => browser!.close()) : true;
      const workersDisposed = mf ? await cleanup(() => mf!.dispose()) : true;
      const temporaryRemoved = await cleanup(() => rm(temporary, { recursive: true, force: true }));
      cleanupOk = browserClosed && workersDisposed && temporaryRemoved;
      benchmark.cleanup_ok = cleanupOk;
      benchmark.failure_phase = failurePhase;
      benchmark.passed = failurePhase === null && cleanupOk;
      const failedClosed = benchmark.phases.filter((row) => row.phase === 'fail_closed');
      const failedClosedTimes = failedClosed.flatMap((row) =>
        row.duration_ms === null ? [] : [row.duration_ms],
      );
      benchmark.summary['fail_closed'] = {
        requests: failedClosed.length,
        status_counts: {
          '503': failedClosed.filter((row) => row.status === 503).length,
        },
        latency_ms: {
          p50: profilePercentile(failedClosedTimes, 0.5),
          p95: profilePercentile(failedClosedTimes, 0.95),
          p99: profilePercentile(failedClosedTimes, 0.99),
        },
      };
      benchmark.summary['invalid_token'] = {
        requests: benchmark.phases.filter((row) => row.phase === 'invalid_token').length,
        status_counts: {
          '401': benchmark.phases.filter(
            (row) => row.phase === 'invalid_token' && row.status === 401,
          ).length,
        },
        latency_ms: {
          p50: profilePercentile(
            benchmark.phases
              .filter((row) => row.phase === 'invalid_token' && row.duration_ms !== null)
              .map((row) => row.duration_ms!),
            0.5,
          ),
          p95: profilePercentile(
            benchmark.phases
              .filter((row) => row.phase === 'invalid_token' && row.duration_ms !== null)
              .map((row) => row.duration_ms!),
            0.95,
          ),
          p99: profilePercentile(
            benchmark.phases
              .filter((row) => row.phase === 'invalid_token' && row.duration_ms !== null)
              .map((row) => row.duration_ms!),
            0.99,
          ),
        },
      };
      benchmark.summary['post_release_inflight'] = {
        requests: benchmark.phases.filter((row) => row.phase === 'post_revoke_inflight').length,
        status_counts: {
          '503': benchmark.phases.filter(
            (row) => row.phase === 'post_revoke_inflight' && row.status === 503,
          ).length,
        },
        latency_measured: false,
        result: 'no_name_disclosed',
      };
      benchmark.summary['request_counts'] = Object.fromEntries(
        [
          'preconsent_warmup',
          'preconsent_sample',
          'consented_warmup',
          'consented_sample',
          'fail_closed',
          'invalid_token',
          'post_revoke_inflight',
          'post_release_revoke',
        ].map((phase) => [phase, benchmark.phases.filter((row) => row.phase === phase).length]),
      );
      try {
        await mkdir(join(root, 'artifacts'), { recursive: true });
        const reportPath = join(root, 'artifacts/profile-userinfo-benchmark.json');
        await writeFile(reportPath, `${JSON.stringify(benchmark, null, 2)}\n`, { mode: 0o600 });
        await chmod(reportPath, 0o600);
      } catch {
        if (!testFailed) throw new Error('profile_benchmark_report_write_failed');
      }
      if (!cleanupOk && !testFailed) throw new Error('profile_benchmark_cleanup_failed');
    }
  }
}

test('workerd v2 recipient, real sharing CAS, selected RP consent and postdecrypt withdrawal', () =>
  qualifyRecordUserInfo(false));
test('browser v2 recipient, real sharing CAS, selected RP consent and postdecrypt withdrawal', () =>
  qualifyRecordUserInfo(true));

// Opt-in endpoint-only benchmark. The authenticated SSO/client/token fixture is preprovisioned;
// this does not measure a Passkey/OIDC login, production build, remote database or capacity.
// MIKAKI_PROFILE_BENCHMARK=1 node --test --test-concurrency=1 --test-name-pattern='local-only synthetic v2 profile UserInfo benchmark' local/conformance/vault-record-userinfo-live.test.ts
if (process.env['MIKAKI_PROFILE_BENCHMARK'] === '1') {
  test('local-only synthetic v2 profile UserInfo benchmark', { timeout: 240_000 }, () =>
    qualifyRecordUserInfo(true, true),
  );
}
