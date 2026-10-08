// Synthetic feasibility harness only. Never import this into a product Worker.
import { createHash, randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT, type JWK } from 'jose';
import { verifyAuthorizationResponse, type DcqlQuery } from '@openeudi/openid4vp';

export const profile = {
  issuer: 'https://issuer.mikaki.test',
  vct: 'https://issuer.mikaki.test/membership/v1',
  clientId: 'mikaki-probe-verifier',
  responseUri: 'https://verifier.mikaki.test/response',
  verifierVersion: '0.13.0',
  format: 'dc+sd-jwt',
  responseMode: 'direct_post',
} as const;

export const query: DcqlQuery = {
  credentials: [
    {
      id: 'membership',
      format: profile.format,
      meta: { vct_values: [profile.vct] },
      require_cryptographic_holder_binding: true,
      claims: [{ path: ['membership_active'], values: [true] }],
    },
  ],
};

export const digest = (text: string): string =>
  createHash('sha256').update(text).digest('base64url');
const token = (): string => randomBytes(32).toString('base64url');
const now = (): number => Math.floor(Date.now() / 1000);

export interface PresentationRequest {
  response_type: 'vp_token';
  response_mode: 'direct_post';
  client_id: string;
  response_uri: string;
  nonce: string;
  state: string;
  dcql_query: DcqlQuery;
}

export function newRequest(): PresentationRequest {
  return {
    response_type: 'vp_token',
    response_mode: 'direct_post',
    client_id: profile.clientId,
    response_uri: profile.responseUri,
    nonce: token(),
    state: token(),
    dcql_query: structuredClone(query),
  };
}

function checkRequest(request: PresentationRequest): void {
  if (
    request.response_type !== 'vp_token' ||
    request.response_mode !== profile.responseMode ||
    request.client_id !== profile.clientId ||
    request.response_uri !== profile.responseUri ||
    !/^[A-Za-z0-9_-]{43}$/.test(request.nonce) ||
    !/^[A-Za-z0-9_-]{43}$/.test(request.state) ||
    !isDeepStrictEqual(request.dcql_query, query)
  )
    throw new Error('Unsupported presentation request');
}

export type Envelope = {
  vp_token?: { membership: string[] };
  state: string;
  error?: 'access_denied';
};

export function formResponse(envelope: Envelope): Request {
  const form = new URLSearchParams({ state: envelope.state });
  if (envelope.error) form.set('error', envelope.error);
  if (envelope.vp_token) form.set('vp_token', JSON.stringify(envelope.vp_token));
  return new Request(profile.responseUri, { method: 'POST', body: form });
}

interface Sealed {
  iv: Uint8Array<ArrayBuffer>;
  ciphertext: ArrayBuffer;
}

async function seal(key: CryptoKey, value: string, purpose: string): Promise<Sealed> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(purpose) },
    key,
    new TextEncoder().encode(value),
  );
  return { iv, ciphertext };
}

async function open(key: CryptoKey, sealed: Sealed, purpose: string): Promise<string> {
  const bytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: sealed.iv, additionalData: new TextEncoder().encode(purpose) },
    key,
    sealed.ciphertext,
  );
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export async function unlockKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// Exact issuer serialization and holder key use separate authenticated envelopes.
// An annotation never rewrites the issuer JWT or its disclosures.
export class FixtureWallet {
  annotation = '';
  #artifact: Sealed;
  #holder: Sealed;

  private constructor(artifact: Sealed, holder: Sealed) {
    this.#artifact = artifact;
    this.#holder = holder;
  }

  static async import(
    artifact: string,
    holder: JWK,
    issuerPublic: JWK,
    key: CryptoKey,
  ): Promise<FixtureWallet> {
    const [issuerJwt, ...parts] = artifact.split('~');
    if (!issuerJwt || parts.pop() !== '' || parts.length !== 3)
      throw new Error('Unsupported credential fixture');
    const { payload, protectedHeader } = await jwtVerify(
      issuerJwt,
      await importJWK(issuerPublic, 'ES256'),
      {
        issuer: profile.issuer,
        algorithms: ['ES256'],
        requiredClaims: ['exp', 'iat', 'cnf', 'vct'],
      },
    );
    const publicHolder = { ...holder };
    delete publicHolder.d;
    if (
      protectedHeader.typ !== profile.format ||
      payload.vct !== profile.vct ||
      !Number.isSafeInteger(payload.iat) ||
      payload.iat! > now() + 5 ||
      payload._sd_alg !== 'sha-256' ||
      !isDeepStrictEqual(payload.cnf, { jwk: publicHolder }) ||
      !Array.isArray(payload._sd) ||
      payload._sd.length !== 3 ||
      new Set(parts).size !== 3 ||
      !parts.every((d) => (payload._sd as unknown[]).includes(digest(d)))
    )
      throw new Error('Credential import rejected');
    const names = parts.map((part) => {
      const value: unknown = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
      if (
        !Array.isArray(value) ||
        value.length !== 3 ||
        typeof value[0] !== 'string' ||
        (value[1] === 'membership_active'
          ? typeof value[2] !== 'boolean'
          : typeof value[2] !== 'string')
      )
        throw new Error('Unsupported disclosure fixture');
      return value[1];
    });
    if (!isDeepStrictEqual(names.sort(), ['member_number', 'membership_active', 'name']))
      throw new Error('Unsupported membership fixture');
    return new FixtureWallet(
      await seal(key, artifact, 'mikaki-probe:issuer-artifact:v1'),
      await seal(key, JSON.stringify(holder), 'mikaki-probe:holder-key:v1'),
    );
  }

  async original(key: CryptoKey): Promise<string> {
    return open(key, this.#artifact, 'mikaki-probe:issuer-artifact:v1');
  }

  async present(
    request: PresentationRequest,
    approved: boolean,
    key: CryptoKey,
  ): Promise<Envelope> {
    checkRequest(request);
    // Cancellation returns no artifact and does not unlock either envelope.
    if (!approved) return { state: request.state, error: 'access_denied' };
    const artifact = await this.original(key);
    const [issuerJwt, ...parts] = artifact.split('~');
    const selected = parts.filter((d) => {
      if (!d) return false;
      const disclosure: unknown = JSON.parse(Buffer.from(d, 'base64url').toString('utf8'));
      return (
        Array.isArray(disclosure) &&
        disclosure.length === 3 &&
        disclosure[1] === 'membership_active'
      );
    });
    if (selected.length !== 1) throw new Error('Missing requested disclosure');
    const sdJwt = `${issuerJwt}~${selected[0]}~`;
    const holder: JWK = JSON.parse(await open(key, this.#holder, 'mikaki-probe:holder-key:v1'));
    const kbJwt = await new SignJWT({ nonce: request.nonce, sd_hash: digest(sdJwt) })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
      .setAudience(request.client_id)
      .setIssuedAt()
      .sign(await importJWK(holder, 'ES256'));
    return { state: request.state, vp_token: { membership: [sdJwt + kbJwt] } };
  }
}

export type Status = 'good' | 'revoked' | 'unknown';
export type Decision = {
  accepted: boolean;
  gate: 'accepted' | 'transport' | 'session' | 'cancelled' | 'envelope' | 'credential' | 'status';
};
const deny = (gate: Decision['gate']): Decision => ({ accepted: false, gate });

export class FixtureVerifier {
  #request: PresentationRequest;
  #pending = true;
  #deadline: number;
  #issuer: JWK;
  #status: (issuerJwtHash: string) => Promise<Status>;

  constructor(
    request: PresentationRequest,
    issuer: JWK,
    status: (hash: string) => Promise<Status>,
    deadline = now() + 120,
  ) {
    checkRequest(request);
    this.#request = structuredClone(request);
    this.#issuer = structuredClone(issuer);
    this.#status = status;
    this.#deadline = deadline;
  }

  async receive(request: Request): Promise<Decision> {
    if (
      request.url !== profile.responseUri ||
      request.method !== 'POST' ||
      !/^application\/x-www-form-urlencoded(?:;|$)/i.test(request.headers.get('content-type') ?? '')
    )
      return deny('transport');
    const body = await request.text();
    if (Buffer.byteLength(body) > 32768) return deny('transport');
    const form = new URLSearchParams(body);
    if (
      !this.#pending ||
      now() >= this.#deadline ||
      form.getAll('state').length !== 1 ||
      form.get('state') !== this.#request.state
    )
      return deny('session');
    // Consume synchronously before crypto/status await: concurrent attempts have one winner.
    this.#pending = false;
    if (form.has('error')) {
      return form.size === 2 && form.get('error') === 'access_denied'
        ? deny('cancelled')
        : deny('envelope');
    }
    if (form.size !== 2 || form.getAll('vp_token').length !== 1) return deny('envelope');
    let vp: unknown;
    try {
      vp = JSON.parse(form.get('vp_token') ?? '');
    } catch {
      return deny('envelope');
    }
    if (!vp || typeof vp !== 'object' || !isDeepStrictEqual(Object.keys(vp), ['membership']))
      return deny('envelope');
    const presentations = (vp as Record<string, unknown>).membership;
    if (
      !Array.isArray(presentations) ||
      presentations.length !== 1 ||
      typeof presentations[0] !== 'string'
    )
      return deny('envelope');
    const presentation = presentations[0];
    try {
      const result = await verifyAuthorizationResponse(
        { state: this.#request.state, vp_token: { membership: [presentation] } },
        this.#request.dcql_query,
        {
          trustedCertificates: [],
          trustedIssuerJwks: [this.#issuer],
          nonce: this.#request.nonce,
          audience: profile.clientId,
          requireKeyBinding: true,
          allowedAlgorithms: ['ES256'],
          expectedDocType: profile.vct,
        },
      );
      if (!result.valid || !result.match.satisfied) return deny('credential');
      const pieces = presentation.split('~');
      const issuerJwt = pieces[0]!;
      const kbJwt = pieces.at(-1)!;
      // Pin issuer identity and require time/type claims in addition to the independent parser.
      const { payload, protectedHeader } = await jwtVerify(
        issuerJwt,
        await importJWK(this.#issuer, 'ES256'),
        {
          issuer: profile.issuer,
          algorithms: ['ES256'],
          requiredClaims: ['exp', 'iat', 'cnf', 'vct'],
        },
      );
      if (protectedHeader.typ !== profile.format || payload.iat! > now() + 5 || pieces.length !== 3)
        return deny('credential');
      const cnf = payload.cnf as { jwk: JWK };
      const kb = await jwtVerify(kbJwt, await importJWK(cnf.jwk, 'ES256'), {
        audience: profile.clientId,
        algorithms: ['ES256'],
        requiredClaims: ['iat', 'nonce', 'sd_hash'],
        maxTokenAge: 60,
      });
      if (kb.protectedHeader.typ !== 'kb+jwt') return deny('credential');
      // Probe-only trusted local status service; not a Token Status List implementation.
      const status = await this.#status(digest(issuerJwt));
      if (status !== 'good') return deny('status');
      if (now() >= this.#deadline) return deny('session');
      return { accepted: true, gate: 'accepted' };
    } catch {
      // Library diagnostics can include claim values. Never copy them to the report.
      return deny('credential');
    }
  }
}

export async function fixture(
  options: { active?: boolean; expiry?: number; issuer?: string; vct?: string } = {},
) {
  const issuer = await generateKeyPair('ES256', { extractable: true });
  const holder = await generateKeyPair('ES256', { extractable: true });
  const issuerPublic = await exportJWK(issuer.publicKey);
  const holderPublic = await exportJWK(holder.publicKey);
  const holderPrivate = await exportJWK(holder.privateKey);
  const disclosures = [
    ['membership_active', options.active ?? true],
    ['name', 'Synthetic Member'],
    ['member_number', 'SYNTHETIC-0001'],
  ].map(([name, value]) =>
    Buffer.from(JSON.stringify([token(), name, value])).toString('base64url'),
  );
  const issuerJwt = await new SignJWT({
    vct: options.vct ?? profile.vct,
    cnf: { jwk: holderPublic },
    _sd_alg: 'sha-256',
    _sd: disclosures.map(digest).sort(),
  })
    .setProtectedHeader({ alg: 'ES256', typ: profile.format })
    .setIssuer(options.issuer ?? profile.issuer)
    .setIssuedAt()
    .setExpirationTime(options.expiry ?? now() + 300)
    .sign(issuer.privateKey);
  const artifact = `${issuerJwt}~${disclosures.join('~')}~`;
  const key = await unlockKey();
  return {
    issuer,
    issuerPublic,
    holder,
    holderPrivate,
    artifact,
    key,
    issuerJwt,
    wallet:
      options.expiry !== undefined || options.issuer !== undefined || options.vct !== undefined
        ? null
        : await FixtureWallet.import(artifact, holderPrivate, issuerPublic, key),
  };
}
