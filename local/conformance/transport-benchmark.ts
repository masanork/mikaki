// Local HTTP round trips, with real ES256 verification and synchronous SQLite writes.
// Uses a fresh synthetic credential. No Suite code or authenticator private keys.
import assert from 'node:assert/strict';
import { Agent, request } from 'node:http';
import { createECDH, createHash, createPrivateKey, randomBytes, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
const origin = 'http://localhost:8080';
const b64 = (b: Buffer) => Buffer.from(b).toString('base64url');
const hash = (b: string | Buffer) => createHash('sha256').update(b).digest();
const hex = (s: string) => Buffer.from(s, 'hex');
const key = createECDH('prime256v1');
key.generateKeys();
const pub = key.getPublicKey();
const privateKey = createPrivateKey({
  format: 'jwk',
  key: {
    kty: 'EC',
    crv: 'P-256',
    x: b64(pub.subarray(1, 33)),
    y: b64(pub.subarray(33)),
    d: b64(key.getPrivateKey()),
  },
});
const idBytes = randomBytes(32);
const id = b64(idBytes);
const username = `transport-${b64(randomBytes(16))}`;
const cose = Buffer.concat([
  hex('a5010203262001215820'),
  pub.subarray(1, 33),
  hex('225820'),
  pub.subarray(33),
]);
const auth = Buffer.concat([
  hash('localhost'),
  hex('4500000000'),
  Buffer.alloc(16),
  hex('0020'),
  idBytes,
  cose,
]);
assert(auth.length < 256);
const attestation = Buffer.concat([
  hex('a363666d74646e6f6e656761747453746d74a068617574684461746158'),
  Buffer.from([auth.length]),
  auth,
]);
const client = (type: string, challenge: string) =>
  Buffer.from(JSON.stringify({ type, challenge, origin }));
function post(
  path: string,
  data: unknown,
  cookie: string | null | undefined,
  agent: Agent,
): Promise<{
  result: { status: string; challenge: string; user: { id: string } };
  ms: number;
  cookie?: string;
}> {
  const body = JSON.stringify(data);
  return new Promise((resolve, reject) => {
    const start = performance.now();
    const req = request(
      origin + path,
      {
        method: 'POST',
        family: 6,
        agent,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          ...(cookie ? { Cookie: cookie } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (b) => chunks.push(b));
        res.on('error', reject);
        res.on('end', () => {
          const ms = performance.now() - start;
          try {
            assert.equal(res.statusCode, 200);
            const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            assert.equal(result.status, 'ok');
            resolve({ result, ms, cookie: res.headers['set-cookie']?.[0].split(';')[0] });
          } catch (e) {
            reject(e);
          }
        });
      },
    );
    req.setTimeout(5000, () => req.destroy(new Error('Local HTTP timeout')));
    req.on('error', reject);
    req.end(body);
  });
}
const stats = (values: number[]) => {
  const s = [...values].sort((a, b) => a - b);
  return {
    count: s.length,
    sum_ms: values.reduce((a, b) => a + b, 0),
    p50_ms: s[Math.ceil(s.length * 0.5) - 1],
    p95_ms: s[Math.ceil(s.length * 0.95) - 1],
    p99_ms: s[Math.ceil(s.length * 0.99) - 1],
    max_ms: s.at(-1),
  };
};
const setupAgent = new Agent({ keepAlive: true, maxSockets: 1 });
let handle;
try {
  const options = await post('/attestation/options', { username }, null, setupAgent);
  handle = options.result.user.id;
  await post(
    '/attestation/result',
    {
      type: 'public-key',
      id,
      response: {
        clientDataJSON: b64(client('webauthn.create', options.result.challenge)),
        attestationObject: b64(attestation),
      },
    },
    options.cookie,
    setupAgent,
  );
} finally {
  setupAgent.destroy();
}
let counter = 0;
const runs: Array<Record<string, unknown>> = [];
for (const keepAlive of [true, false]) {
  const agent = new Agent({ keepAlive, maxSockets: 1 });
  const optionsMs: number[] = [],
    resultMs: number[] = [];
  try {
    for (let i = 0; i < 105; i++) {
      const o = await post('/assertion/options', { username }, null, agent);
      const c = client('webauthn.get', o.result.challenge);
      const count = Buffer.alloc(4);
      count.writeUInt32BE(++counter);
      const a = Buffer.concat([hash('localhost'), Buffer.from([5]), count]);
      const signature = sign('sha256', Buffer.concat([a, hash(c)]), privateKey);
      const r = await post(
        '/assertion/result',
        {
          type: 'public-key',
          id,
          response: {
            clientDataJSON: b64(c),
            authenticatorData: b64(a),
            signature: b64(signature),
            userHandle: handle,
          },
        },
        o.cookie,
        agent,
      );
      if (i >= 5) {
        optionsMs.push(o.ms);
        resultMs.push(r.ms);
      }
    }
  } finally {
    agent.destroy();
  }
  runs.push({
    keep_alive: keepAlive,
    warmup_ceremonies: 5,
    options: stats(optionsMs),
    assertion_result: stats(resultMs),
  });
}
const report = {
  recorded_at: new Date().toISOString(),
  node: process.version,
  origin,
  algorithm: 'ES256',
  storage: 'running server configuration; record alongside server log',
  runs,
};
writeFileSync('artifacts/transport-performance.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
