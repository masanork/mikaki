import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
import https from 'node:https';
import { resolve, isAbsolute } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { unstable_splitSqlQuery } from 'wrangler';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const origin = 'https://auth.example:18443';
test(
  'Android HTTPS loses completion reply and recovers after process restart',
  { timeout: 240000 },
  async () => {
    const {
      MIKAKI_ANDROID_APP_SERIAL: serial,
      MIKAKI_ANDROID_ADB: adb,
      MIKAKI_ANDROID_APP_APK: apk,
      MIKAKI_INSTALLATION_TLS_DIR: tls,
    } = process.env;
    assert.match(serial ?? '', /^emulator-\d+$/);
    assert.ok(adb && isAbsolute(adb) && apk && isAbsolute(apk) && tls && isAbsolute(tls));
    const runAdb = (args) =>
      execFileSync(adb, ['-s', serial, ...args], {
        encoding: 'utf8',
        timeout: 120000,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    const packageName = 'app.tossa.mikaki';
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
    let server;
    try {
      const db = await mf.getD1Database('DB');
      const dir = 'crates/worker/migrations';
      for (const name of (await readdir(dir)).filter((v) => v.endsWith('.sql')).sort()) {
        await db.batch(
          unstable_splitSqlQuery(await readFile(`${dir}/${name}`, 'utf8')).map((q) =>
            db.prepare(q),
          ),
        );
      }
      await db.batch(
        unstable_splitSqlQuery(
          await readFile('crates/worker/installation-qualification/0001.sql', 'utf8'),
        ).map((q) => db.prepare(q)),
      );
      const hash = createHash('sha256').update('qualification-sso-secret').digest('base64url');
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
      const counts = { start: 0, complete: 0, status: 0, dropped: 0 };
      server = https.createServer(
        { key: await readFile(`${tls}/server.key`), cert: await readFile(`${tls}/server.crt`) },
        async (req, res) => {
          try {
            const path = req.url;
            const step = path?.split('/').at(-1);
            assert.ok(['start', 'complete', 'status'].includes(step));
            counts[step]++;
            const chunks = [];
            let size = 0;
            for await (const chunk of req) {
              size += chunk.length;
              assert.ok(size <= 1024);
              chunks.push(chunk);
            }
            if (step === 'complete')
              await db
                .prepare("INSERT INTO fixture_installation_fault VALUES(1,'lost_reply')")
                .run();
            const headers = new Headers();
            for (const name of ['origin', 'content-type', 'x-mikaki-app', 'dpop', 'cookie'])
              if (req.headers[name]) headers.set(name, req.headers[name]);
            const reply = await mf.dispatchFetch(origin + path, {
              method: 'POST',
              headers,
              body: Buffer.concat(chunks),
            });
            if (step === 'complete' && reply.status === 500) {
              counts.dropped++;
              res.destroy();
              return;
            }
            res.writeHead(reply.status, { 'content-type': 'application/json' });
            res.end(Buffer.from(await reply.arrayBuffer()));
          } catch {
            res.destroy();
          }
        },
      );
      await new Promise((resolveListen, reject) => {
        server.once('error', reject);
        server.listen(18443, '127.0.0.1', resolveListen);
      });
      const launch = () =>
        runAdb([
          'shell',
          'monkey',
          '-p',
          packageName,
          '-c',
          'android.intent.category.LAUNCHER',
          '1',
        ]);
      const waitFor = async (wanted) => {
        for (let i = 0; i < 600; i++) {
          try {
            const value = runAdb([
              'shell',
              'run-as',
              packageName,
              'cat',
              'installation-https-result.txt',
            ]).trim();
            if (value === wanted) return;
            if (
              wanted === 'untrusted' &&
              value.startsWith('error:start_transport:') &&
              value.includes('UnknownIssuer')
            )
              return;
            if (value.startsWith('error:'))
              throw new Error(`app HTTPS qualification failed: ${value}`);
          } catch (e) {
            if (e.message.startsWith('app HTTPS qualification failed:')) throw e;
          }
          await delay(100);
        }
        throw new Error(`timed out waiting for ${wanted}`);
      };
      runAdb(['install', '-r', '-t', apk]);
      runAdb(['shell', 'am', 'force-stop', packageName]);
      runAdb(['shell', 'pm', 'clear', packageName]); // Disposable emulator only.
      server.setSecureContext({
        key: await readFile(`${tls}/untrusted.key`),
        cert: await readFile(`${tls}/untrusted.crt`),
      });
      launch();
      await waitFor('untrusted');
      assert.deepEqual(counts, { start: 0, complete: 0, status: 0, dropped: 0 });
      runAdb(['shell', 'am', 'force-stop', packageName]);
      runAdb(['shell', 'pm', 'clear', packageName]);
      server.setSecureContext({
        key: await readFile(`${tls}/server.key`),
        cert: await readFile(`${tls}/server.crt`),
      });
      launch();
      await waitFor('reply_lost');
      assert.equal(
        (
          await db
            .prepare("SELECT count(*) AS n FROM installation_device WHERE state='active'")
            .first()
        ).n,
        1,
      );
      const firstPid = runAdb(['shell', 'pidof', packageName]).trim();
      assert.ok(firstPid);
      runAdb(['shell', 'am', 'force-stop', packageName]);
      runAdb(['shell', 'run-as', packageName, 'rm', '-f', 'installation-https-result.txt']);
      launch();
      await waitFor('active');
      const secondPid = runAdb(['shell', 'pidof', packageName]).trim();
      assert.ok(secondPid && secondPid !== firstPid);
      assert.deepEqual(counts, { start: 1, complete: 1, status: 1, dropped: 1 });
    } finally {
      try {
        runAdb(['shell', 'am', 'force-stop', packageName]);
      } catch {
        /* best effort */
      }
      if (server) await new Promise((done) => server.close(done));
      await mf.dispose();
    }
  },
);
