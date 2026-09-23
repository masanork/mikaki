// Isolated FIDO test API. Not imported by the product or exposed beyond loopback.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import init, * as wasm from '../../crates/browser-wasm/pkg/mikaki_browser_wasm.js';

await init({
  module_or_path: readFileSync(
    new URL('../../crates/browser-wasm/pkg/mikaki_browser_wasm_bg.wasm', import.meta.url),
  ),
});
const metadataDir = new URL('../../target/fido-metadata/', import.meta.url);
const entries = readdirSync(metadataDir)
  .filter((n) => n.endsWith('.json'))
  .map((n) => {
    const m = JSON.parse(readFileSync(new URL(n, metadataDir), 'utf8'));
    return {
      aaguid: m.aaguid
        ? Buffer.from(m.aaguid.replaceAll('-', ''), 'hex').toString('base64url')
        : '',
      key_ids: m.attestationCertificateKeyIdentifiers ?? [],
      roots: (m.attestationRootCertificates ?? []).map((r) =>
        Buffer.from(r, 'base64').toString('base64url'),
      ),
      types: m.attestationTypes,
      allowed: true,
    };
  });
const target = process.env.FIDO_TARGET ?? 'wasm';
if (!['native', 'wasm'].includes(target)) throw new Error('FIDO_TARGET must be native or wasm');
const port = Number(process.env.FIDO_PORT ?? 8080);
const origin = `http://localhost:${port}`;
const native = fileURLToPath(new URL('../../target/release/examples/conformance', import.meta.url));
const mdsDir = new URL('../../target/fido-mds/', import.meta.url);
for (const file of readdirSync(mdsDir).filter((n) => n.endsWith('.json'))) {
  const input = JSON.parse(readFileSync(new URL(file, mdsDir), 'utf8'));
  input.now = Math.floor(Date.now() / 1000);
  try {
    const verified =
      target === 'wasm'
        ? JSON.parse(wasm.verify_mds(JSON.stringify(input)))
        : JSON.parse(
            spawnSync(native, [], {
              input: JSON.stringify({ mds: input }),
              encoding: 'utf8',
              timeout: 10000,
              maxBuffer: 8388608,
            }).stdout,
          );
    check(verified);
    for (const m of verified.entries) {
      const index = entries.findIndex((e) => e.aaguid === m.aaguid);
      if (index >= 0) entries[index] = m;
      else entries.push(m);
    }
    console.log(`MDS ${file}: verified ${verified.entries.length} entries (${target})`);
  } catch {
    console.log(`MDS ${file}: rejected (${target})`);
  }
}
const token = () => randomBytes(32).toString('base64url');
const transactions = new Map();
const users = new Map();
const credentials = new Map();
const ok = (data = {}) => ({ status: 'ok', errorMessage: '', ...data });
function check(value) {
  if (!value) throw new Error('invalid_request');
}
function verify(input, credential) {
  if (target === 'wasm') {
    return JSON.parse(
      input.ceremony.purpose === 'register'
        ? wasm.register(JSON.stringify(input))
        : wasm.authenticate(JSON.stringify(input), JSON.stringify(credential)),
    );
  }
  const result = spawnSync(native, [], {
    input: JSON.stringify({ ...input, credential }),
    encoding: 'utf8',
    timeout: 5000,
    maxBuffer: 262144,
  });
  check(result.status === 0);
  const proof = JSON.parse(result.stdout);
  check(proof);
  return proof;
}
const server = createServer(async (req, res) => {
  const start = performance.now();
  let status = 'failed';
  const timing = { metadata_ms: 0, verify_ms: 0 };
  const timed = (field, operation) => {
    const start = performance.now();
    try {
      return operation();
    } finally {
      timing[field] += performance.now() - start;
    }
  };
  try {
    check(req.headers.host === `localhost:${port}`);
    check(req.method === 'POST');
    let body = '';
    for await (const chunk of req) {
      body += chunk.toString('utf8');
      check(Buffer.byteLength(body) <= 65536);
    }
    check(wasm.valid_json(body, 65536, 16));
    const data = JSON.parse(body);
    const registration = req.url.startsWith('/attestation/');
    const cookieName = registration ? 'fido2_reg_session' : 'fido2_auth_session';
    let output;
    if (['/attestation/options', '/assertion/options'].includes(req.url)) {
      for (const [id, tx] of transactions) if (tx.expires <= Date.now()) transactions.delete(id);
      check(transactions.size < 1000 && users.size < 1000);
      let user;
      if (registration) {
        check(typeof data.username === 'string' && data.username.length > 0);
        user = users.get(data.username) ?? {
          id: token(),
          name: data.username,
          displayName: data.displayName || data.username,
        };
      } else if (data.username) {
        user = users.get(data.username);
        check(user);
      }
      const id = token();
      const challenge = token();
      const selection = data.authenticatorSelection ?? {};
      const uv = (registration ? selection.userVerification : data.userVerification) ?? 'preferred';
      check(['required', 'preferred', 'discouraged'].includes(uv));
      const resident =
        selection.residentKey ?? (selection.requireResidentKey ? 'required' : 'discouraged');
      check(['required', 'preferred', 'discouraged'].includes(resident));
      const allowed = [...credentials.values()]
        .filter((c) => c.user_handle === user?.id)
        .map((c) => c.id);
      transactions.set(id, {
        challenge,
        user,
        expires: Date.now() + 120000,
        registration,
        uv,
        allowed,
      });
      res.setHeader(
        'Set-Cookie',
        `${cookieName}=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=120`,
      );
      const list = [...credentials.values()]
        .filter((c) => c.user_handle === user?.id)
        .map((c) => ({ type: 'public-key', id: c.id }));
      output = registration
        ? ok({
            rp: { id: 'localhost', name: 'mikaki conformance' },
            user,
            challenge,
            pubKeyCredParams: [-7, -8, -257, -65535].map((alg) => ({ type: 'public-key', alg })),
            timeout: 120000,
            excludeCredentials: list,
            attestation: data.attestation ?? 'none',
            extensions: data.extensions ?? {},
            authenticatorSelection: {
              userVerification: uv,
              residentKey: resident,
              requireResidentKey: resident === 'required',
            },
          })
        : ok({
            challenge,
            rpId: 'localhost',
            timeout: 120000,
            allowCredentials: list,
            userVerification: uv,
            extensions: data.extensions ?? {},
          });
    } else {
      check(['/attestation/result', '/assertion/result'].includes(req.url));
      const id = (req.headers.cookie ?? '')
        .split(';')
        .map((s) => s.trim())
        .find((s) => s.startsWith(`${cookieName}=`))
        ?.slice(cookieName.length + 1);
      const tx = transactions.get(id);
      transactions.delete(id);
      check(tx && tx.expires > Date.now() && tx.registration === registration);
      check(data.type === 'public-key' && typeof data.id === 'string');
      check(data.rawId === undefined || data.rawId === data.id);
      const r = data.response;
      check(r && typeof r.clientDataJSON === 'string');
      const credential = credentials.get(data.id);
      if (!registration) check(credential && (!tx.user || credential.user_handle === tx.user.id));
      const input = {
        ceremony: {
          purpose: registration ? 'register' : 'authenticate',
          browser_hash: id,
          expires_at: Math.floor(tx.expires / 1000),
          failures: 0,
          consumed: false,
          context: {
            challenge: tx.challenge,
            origin,
            rp_id: 'localhost',
            max_bytes: 65536,
            max_depth: 8,
            user_verification: tx.uv,
            algorithms: [-7, -8, -257, -65535],
            attestation: {
              now: Math.floor(Date.now() / 1000),
              entries: registration
                ? timed('metadata_ms', () => {
                    const hint = wasm.attestation_hint(r.attestationObject);
                    return entries.filter((e) => e.aaguid === hint || e.key_ids.includes(hint));
                  })
                : [],
            },
            authentication:
              tx.user && !registration
                ? { mode: 'identified', user_handle: tx.user.id, allowed_credentials: tx.allowed }
                : { mode: 'discoverable' },
          },
        },
        browser_hash: id,
        now: Math.floor(Date.now() / 1000),
        max_failures: 5,
        response: registration
          ? { id: data.id, client_data: r.clientDataJSON, attestation: r.attestationObject }
          : {
              id: data.id,
              client_data: r.clientDataJSON,
              authenticator_data: r.authenticatorData,
              signature: r.signature,
              user_handle: r.userHandle,
            },
      };
      // Synchronous verification and state commit: no request can interleave here.
      const proof = timed('verify_ms', () => verify(input, credential));
      if (registration) {
        check(!credentials.has(proof.id) && credentials.size < 1000);
        users.set(tx.user.name, tx.user);
        credentials.set(proof.id, { ...proof, user_handle: tx.user.id });
      } else credentials.set(data.id, { ...credential, ...proof });
      output = ok();
    }
    status = 'ok';
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(output));
  } catch {
    res.statusCode = 400;
    res.setHeader('Content-Type', 'application/json');
    res.end(
      JSON.stringify({
        status: 'failed',
        errorMessage: 'Request rejected by mikaki profile or verifier',
      }),
    );
  } finally {
    console.log(
      JSON.stringify({
        target,
        path: req.url,
        status,
        ms: +(performance.now() - start).toFixed(3),
        ...(process.env.FIDO_TIMING === '1'
          ? Object.fromEntries(
              Object.entries(timing).map(([key, value]) => [key, +value.toFixed(3)]),
            )
          : {}),
      }),
    );
  }
});
server.requestTimeout = 10000;
server.headersTimeout = 10000;
server.listen({ port, host: '::1' }, () =>
  console.log(
    `FIDO ${target}: ${origin} (loopback, disposable state, server-selected ceremony policy)`,
  ),
);
