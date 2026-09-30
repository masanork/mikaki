// External emulated-wallet integration for the independent verifier component.
// This is a separate PID/redirect_uri test profile, not the product or membership verifier.
import { createServer } from 'node:https';
import { readFile, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { exportJWK, generateKeyPair, importJWK, jwtVerify, type JWK } from 'jose';
import { verifyAuthorizationResponse, type DcqlQuery } from '@openeudi/openid4vp';
import { chromium } from 'playwright';
import {
  finished,
  generated,
  localRequest,
  localSuite,
  pause,
  saveRun,
  type ModuleResult,
  type RunInfo,
  type RunState,
} from './suite.ts';

const origin = 'https://host.docker.internal:8793';
const responseUri = `${origin}/response`;
const clientId = `redirect_uri:${responseUri}`;
const key = await generateKeyPair('ES256', { extractable: true });
const privateJwk = { ...(await exportJWK(key.privateKey)), kid: 'suite-credential', alg: 'ES256' };
const publicJwk = { ...(await exportJWK(key.publicKey)), kid: 'suite-credential', alg: 'ES256' };
const query: DcqlQuery = {
  credentials: [
    {
      id: 'pid',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['urn:eudi:pid:1'] },
      require_cryptographic_holder_binding: true,
    },
  ],
};
type Session = {
  nonce: string;
  state: string;
  pending: boolean;
  accepted?: boolean;
  deadline: number;
};
let session: Session | undefined;
const server = createServer(
  {
    key: await readFile(new URL('oidf-local.key', generated)),
    cert: await readFile(new URL('oidf-local.crt', generated)),
  },
  async (req, res) => {
    try {
      if (req.url === '/receipt' && req.method === 'GET') {
        res.writeHead(200, { 'content-type': 'text/html', 'cache-control': 'no-store' });
        res.end(
          `<html lang="en"><title>Verifier component receipt</title><h1>Presentation ${session?.accepted === true ? 'accepted' : 'rejected'}</h1><p>Independent verifier component over local HTTPS. Synthetic PID only.</p></html>`,
        );
        return;
      }
      if (
        req.url !== '/response' ||
        req.method !== 'POST' ||
        !/^application\/x-www-form-urlencoded(?:;|$)/i.test(req.headers['content-type'] ?? '')
      ) {
        res.writeHead(404);
        res.end();
        return;
      }
      let text = '';
      for await (const chunk of req) {
        text += chunk.toString('utf8');
        if (Buffer.byteLength(text) > 32768) {
          res.writeHead(413);
          res.end();
          return;
        }
      }
      const form = new URLSearchParams(text);
      const current = session;
      let accepted = false;
      if (
        current?.pending &&
        Date.now() < current.deadline &&
        form.size === 2 &&
        form.getAll('state').length === 1 &&
        form.get('state') === current.state &&
        form.getAll('vp_token').length === 1
      ) {
        current.pending = false;
        try {
          const vp = JSON.parse(form.get('vp_token')!);
          if (
            Object.keys(vp).join() !== 'pid' ||
            !Array.isArray(vp.pid) ||
            vp.pid.length !== 1 ||
            typeof vp.pid[0] !== 'string'
          )
            throw new Error('Invalid envelope');
          const result = await verifyAuthorizationResponse(
            { state: current.state, vp_token: vp },
            query,
            {
              trustedCertificates: [],
              trustedIssuerJwks: [publicJwk],
              nonce: current.nonce,
              audience: clientId,
              requireKeyBinding: true,
              allowedAlgorithms: ['ES256'],
              expectedDocType: 'urn:eudi:pid:1',
            },
          );
          const parts = vp.pid[0].split('~');
          const issuer = await jwtVerify(parts[0], key.publicKey, {
            algorithms: ['ES256'],
            requiredClaims: ['exp', 'iat', 'cnf', 'vct'],
          });
          const holder = (issuer.payload.cnf as { jwk: JWK }).jwk;
          const kb = await jwtVerify(parts.at(-1)!, await importJWK(holder, 'ES256'), {
            algorithms: ['ES256'],
            audience: clientId,
            requiredClaims: ['iat', 'nonce', 'sd_hash'],
            maxTokenAge: 60,
          });
          accepted =
            result.valid &&
            result.match.satisfied &&
            issuer.protectedHeader.typ === 'dc+sd-jwt' &&
            issuer.payload.iat! <= Math.floor(Date.now() / 1000) + 5 &&
            kb.protectedHeader.typ === 'kb+jwt';
        } catch {
          /* Never put credential values or library diagnostics in the receipt. */
        }
        current.accepted = accepted;
      }
      res.writeHead(accepted ? 200 : 400, {
        'content-type': 'application/json',
        'cache-control': 'no-store',
      });
      res.end(
        JSON.stringify(
          accepted ? { redirect_uri: `${origin}/receipt` } : { error: 'invalid_request' },
        ),
      );
    } catch {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    }
  },
);
await new Promise<void>((resolve, reject) => {
  server.once('error', reject);
  server.listen(8793, '0.0.0.0', resolve);
});
const modules = [
  'happy-flow',
  'invalid-credential-signature',
  'invalid-kb-jwt-aud',
  'invalid-kb-jwt-nonce',
  'invalid-kb-jwt-signature',
  'invalid-sd-hash',
  'kb-jwt-iat-in-future',
  'kb-jwt-iat-in-past',
  'minimal-cnf-jwk',
].map((name) => `oid4vp-1final-verifier-${name}`);
let browser;
let runId: string | undefined;
try {
  const suiteVersion = await localSuite('/api/server');
  const plan = await localSuite(
    `/api/plan?${new URLSearchParams({
      planName: 'oid4vp-1final-verifier-test-plan',
      variant: JSON.stringify({
        vp_profile: 'plain_vp',
        credential_format: 'sd_jwt_vc',
        client_id_prefix: 'redirect_uri',
        request_method: 'url_query',
        response_mode: 'direct_post',
      }),
    })}`,
    {
      alias: `mikaki-vp-component-${randomBytes(6).toString('hex')}`,
      description:
        'Independent verifier component HTTPS adapter; synthetic PID; no product certification',
      client: { client_id: responseUri },
      credential: { signing_jwk: privateJwk },
      waitTimeoutSeconds: 60,
    },
  );
  browser = await chromium.launch({
    headless: true,
    args: [
      '--no-sandbox',
      '--host-rules=MAP host.docker.internal 127.0.0.1',
      '--ignore-certificate-errors',
    ],
  });
  const page = await browser.newPage({ ignoreHTTPSErrors: true });
  const results: Array<
    ModuleResult & {
      decision: boolean | null;
      expectedAcceptance: boolean;
      expectationMet: boolean;
    }
  > = [];
  for (const name of modules) {
    session = {
      state: randomBytes(32).toString('base64url'),
      nonce: randomBytes(32).toString('base64url'),
      pending: true,
      deadline: Date.now() + 120_000,
    };
    const run = await localSuite(
      `/api/runner?${new URLSearchParams({ test: name, plan: plan.id })}`,
      undefined,
      'POST',
    );
    runId = run.id;
    let driven = false,
      uploaded = false;
    for (let i = 0; i < 60; i++) {
      const info: RunInfo = await localSuite(`/api/info/${run.id}`);
      const state: RunState = await localSuite(`/api/runner/${run.id}`);
      const endpoint = state.exposed?.authorization_endpoint;
      if (endpoint && !driven) {
        driven = true;
        const target = new URL(endpoint);
        for (const [k, v] of Object.entries({
          response_type: 'vp_token',
          response_mode: 'direct_post',
          client_id: clientId,
          response_uri: responseUri,
          nonce: session.nonce,
          state: session.state,
          dcql_query: JSON.stringify(query),
          client_metadata: JSON.stringify({
            vp_formats_supported: {
              'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] },
            },
          }),
        }))
          target.searchParams.set(k, v);
        // The suite posts back through Docker's host route, exercising real HTTPS/form transport.
        await localRequest(target.toString()).catch(() => {});
      }
      if (info.status === 'WAITING' && !uploaded && session.accepted !== undefined) {
        const log: Array<{ result: string; upload?: string }> = await localSuite(
          `/api/log/${run.id}`,
        );
        const review = log.find((e) => e.result === 'REVIEW' && e.upload);
        if (review) {
          await page.goto(`${origin}/receipt`);
          const screenshot = await page.screenshot();
          // Screenshot endpoints expect a raw data URI, not JSON.
          await new Promise<void>((resolve, reject) => {
            import('node:https').then(({ request }) => {
              const req = request(
                `https://localhost:8443/api/log/${run.id}/images/${review.upload}?description=Component%20verification%20receipt`,
                { method: 'POST', rejectUnauthorized: false },
                (res) => {
                  res.resume();
                  res.on('end', () =>
                    res.statusCode === 200
                      ? resolve()
                      : reject(new Error('Screenshot upload failed')),
                  );
                },
              );
              req.on('error', reject);
              req.end(`data:image/png;base64,${screenshot.toString('base64')}`);
            }, reject);
          });
          uploaded = true;
        }
      }
      if (finished(info)) break;
      await pause();
    }
    const result = await saveRun(plan.id, name, run.id);
    const expectedAcceptance = /happy-flow|minimal-cnf-jwk$/.test(name);
    const row = {
      ...result,
      decision: session.accepted ?? null,
      expectedAcceptance,
      expectationMet: session.accepted === expectedAcceptance,
    };
    results.push(row);
    console.log(JSON.stringify(row));
    if (!finished(result)) await localSuite(`/api/runner/${run.id}`, undefined, 'DELETE');
    runId = undefined;
  }
  const report = {
    generatedAt: new Date().toISOString(),
    suite: suiteVersion,
    planId: plan.id,
    scope: 'OIDF emulated wallet -> independent verifier component over local HTTPS',
    profile: {
      vp_profile: 'plain_vp',
      client_id_prefix: 'redirect_uri',
      request_method: 'url_query',
      response_mode: 'direct_post',
      credential_format: 'sd_jwt_vc',
    },
    exclusions: [
      'Product verifier',
      'Membership policy',
      'Credential status',
      'External wallet application',
      'Hardware holder keys',
      'HAIP certification',
    ],
    results,
  };
  await writeFile(
    new URL('oidf-vp-component-summary.json', generated),
    JSON.stringify(report, null, 2),
    { mode: 0o600 },
  );
  if (
    results.some(
      (r) =>
        !r.expectationMet ||
        r.status !== 'FINISHED' ||
        !['PASSED', 'REVIEW'].includes(r.result ?? ''),
    )
  )
    process.exitCode = 1;
} finally {
  try {
    if (runId) await localSuite(`/api/runner/${runId}`, undefined, 'DELETE');
  } finally {
    try {
      await browser?.close();
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }
}
