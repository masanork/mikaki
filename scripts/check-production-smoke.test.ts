import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const checker = fileURLToPath(new URL('./check-production-smoke.ts', import.meta.url));
const versionId = 'e3d8e154-f079-4cc5-a36b-c68cf475e893';
const sourceCommit = 'a'.repeat(40);

test('production smoke records matching runtime identity and rejects a different version or dirty source', () => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-production-smoke-'));
  try {
    writeFileSync(join(directory, 'health.txt'), 'ok');
    writeFileSync(
      join(directory, 'discovery.json'),
      JSON.stringify({
        issuer: 'https://mikaki.tossa.app',
        jwks_uri: 'https://mikaki.tossa.app/jwks',
      }),
    );
    writeFileSync(join(directory, 'jwks.json'), JSON.stringify({ keys: [{ kid: 'test' }] }));
    writeFileSync(join(directory, 'ready-status.txt'), '204');
    const run = (
      expectedVersion = versionId,
      expectedCommit = sourceCommit,
      assets: Record<string, string> = {},
    ) =>
      spawnSync(process.execPath, [checker], {
        cwd: directory,
        encoding: 'utf8',
        env: {
          ...process.env,
          MIKAKI_EXPECTED_VERSION_ID: expectedVersion,
          MIKAKI_EXPECTED_SOURCE_COMMIT: expectedCommit,
          MIKAKI_EXPECTED_LOGIN_JS_SHA256: '',
          MIKAKI_EXPECTED_LOGIN_CSS_SHA256: '',
          ...assets,
        },
      });
    const writeVersion = (sourceClean: boolean) =>
      writeFileSync(
        join(directory, 'version.json'),
        JSON.stringify({
          worker: 'mikaki-op',
          version_id: versionId,
          source_commit: sourceCommit,
          source_clean: sourceClean,
        }),
      );
    writeVersion(true);
    assert.equal(run().status, 0);
    const evidence = JSON.parse(
      readFileSync(join(directory, 'artifacts/production-smoke.json'), 'utf8'),
    );
    assert.equal(evidence.version_id, versionId);
    assert.equal(evidence.source_commit, sourceCommit);
    assert.equal(evidence.readiness, 'ok');
    assert.notEqual(run('00000000-0000-0000-0000-000000000000').status, 0);
    assert.notEqual(run(versionId, 'b'.repeat(40)).status, 0);
    writeFileSync(join(directory, 'login.js'), 'reviewed JavaScript');
    writeFileSync(join(directory, 'login.css'), 'reviewed stylesheet');
    const digest = (value: string) => createHash('sha256').update(value).digest('hex');
    const assets = {
      MIKAKI_EXPECTED_LOGIN_JS_SHA256: digest('reviewed JavaScript'),
      MIKAKI_EXPECTED_LOGIN_CSS_SHA256: digest('reviewed stylesheet'),
    };
    assert.equal(run(versionId, sourceCommit, assets).status, 0);
    const assetEvidence = JSON.parse(
      readFileSync(join(directory, 'artifacts/production-smoke.json'), 'utf8'),
    );
    assert.equal(assetEvidence.login_assets.js_sha256, assets.MIKAKI_EXPECTED_LOGIN_JS_SHA256);
    assert.notEqual(
      run(versionId, sourceCommit, { ...assets, MIKAKI_EXPECTED_LOGIN_CSS_SHA256: '' }).status,
      0,
    );
    assert.notEqual(run('', '', assets).status, 0);
    writeFileSync(join(directory, 'login.js'), 'stale JavaScript');
    assert.notEqual(run(versionId, sourceCommit, assets).status, 0);
    writeFileSync(join(directory, 'login.js'), 'reviewed JavaScript');
    writeFileSync(join(directory, 'login.css'), 'stale stylesheet');
    assert.notEqual(run(versionId, sourceCommit, assets).status, 0);
    writeVersion(false);
    assert.notEqual(run().status, 0);
    writeVersion(true);
    writeFileSync(join(directory, 'ready-status.txt'), '200');
    assert.notEqual(run().status, 0);
    assert.notEqual(run(versionId, '').status, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
