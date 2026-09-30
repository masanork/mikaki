// Isolated sender-constraint feasibility probe. Not a product OAuth endpoint.
import { createHash, randomBytes } from 'node:crypto';
import {
  calculateJwkThumbprint,
  compactVerify,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  SignJWT,
  type JWK,
} from 'jose';
import {
  Oauth2AuthorizationServer,
  createDpopHeadersForRequest,
  type CallbackContext,
  type RequestLike,
} from '@openid4vc/oauth2';
import { IssuerFixture, jsonResponse, profile, type Transport } from '../oid4vci/probe.ts';

export const dpopProfile = {
  algorithm: 'ES256',
  libraryVersion: '0.6.0',
  maxAgeSeconds: 60,
  clockSkewSeconds: 10,
  replayCapacity: 1000,
} as const;
const now = () => Math.floor(Date.now() / 1000);
const random = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value, 'ascii').digest('base64url');
type DpopCallbacks = Pick<CallbackContext, 'hash' | 'generateRandom' | 'signJwt' | 'verifyJwt'>;

function publicP256(key: JWK): boolean {
  return (
    key.kty === 'EC' &&
    key.crv === 'P-256' &&
    (['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'] as const).every(
      (name) => key[name] === undefined,
    ) &&
    [key.x, key.y].every(
      (value) =>
        typeof value === 'string' &&
        /^[A-Za-z0-9_-]{43}$/.test(value) &&
        Buffer.from(value, 'base64url').toString('base64url') === value,
    )
  );
}
function callbacks(privateKey?: JWK): DpopCallbacks {
  return {
    hash: (data, algorithm) => createHash(algorithm.replace('-', '')).update(data).digest(),
    generateRandom: (length) => randomBytes(length),
    async signJwt(signer, jwt) {
      if (!privateKey || signer.method !== 'jwk' || signer.alg !== 'ES256')
        throw new Error('Unsupported fixture signer');
      const compact = await new SignJWT(jwt.payload)
        .setProtectedHeader(jwt.header)
        .sign(await importJWK(privateKey, 'ES256'));
      return { jwt: compact, signerJwk: signer.publicJwk };
    },
    async verifyJwt(signer, jwt) {
      if (signer.method !== 'jwk' || signer.alg !== 'ES256' || !publicP256(signer.publicJwk))
        return { verified: false };
      try {
        // DPoP's optional exp/nbf are not authority; freshness is checked from iat below.
        await compactVerify(jwt.compact, await importJWK(signer.publicJwk, 'ES256'), {
          algorithms: ['ES256'],
        });
        return { verified: true, signerJwk: signer.publicJwk };
      } catch {
        return { verified: false };
      }
    },
  };
}

function requestLike(request: Request): RequestLike {
  if (request.method !== 'GET' && request.method !== 'POST')
    throw new Error('Unsupported fixture method');
  return { url: request.url, method: request.method, headers: request.headers };
}

export async function dpopKey() {
  const key = await generateKeyPair('ES256', { extractable: true });
  const privateJwk = await exportJWK(key.privateKey);
  const publicJwk = await exportJWK(key.publicKey);
  return { privateJwk, publicJwk, jkt: await calculateJwkThumbprint(publicJwk, 'sha256') };
}

export async function proofHeaders(
  key: JWK,
  request: Request,
  options: {
    nonce?: string;
    accessToken?: string;
    issuedAt?: number;
    payload?: Record<string, unknown>;
  } = {},
) {
  const { d: _private, ...publicJwk } = key;
  if (!publicP256(publicJwk)) throw new Error('Unsupported fixture key');
  return createDpopHeadersForRequest({
    request: requestLike(request),
    signer: { method: 'jwk', alg: 'ES256', publicJwk: { ...publicJwk, kty: 'EC' } },
    callbacks: callbacks(key),
    nonce: options.nonce,
    accessToken: options.accessToken,
    issuedAt: new Date((options.issuedAt ?? now()) * 1000),
    additionalPayload: options.payload,
  });
}

// Shared per-issuer AS/RS ledger. Reserve only AFTER signature and binding validation.
// OWF's optional uniqueness callback runs before its signature callback; do not use it here.
export class DpopGate {
  #ledger = new Map<string, number>();
  #clock: () => number;
  #capacity: number;
  readonly library: Oauth2AuthorizationServer;
  constructor(clock = now, capacity: number = dpopProfile.replayCapacity) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) throw new Error('Invalid replay capacity');
    this.#clock = clock;
    this.#capacity = capacity;
    const unsupported = async (): Promise<never> => {
      throw new Error('Unsupported fixture operation');
    };
    this.library = new Oauth2AuthorizationServer({
      callbacks: {
        ...callbacks(),
        clientAuthentication: unsupported,
      },
    });
  }
  async verify(
    request: Request,
    options: { nonce: string; accessToken?: string; expectedJkt?: string },
  ) {
    const compact = request.headers.get('dpop') ?? '';
    if (
      new URL(request.url).protocol !== 'https:' ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(compact) ||
      compact.length > 8192 ||
      !options.nonce
    )
      throw new Error('Invalid DPoP proof');
    const header = decodeProtectedHeader(compact);
    if (
      header.alg !== 'ES256' ||
      header.typ !== 'dpop+jwt' ||
      !header.jwk ||
      !publicP256(header.jwk) ||
      header.crit ||
      header.jku ||
      header.x5u
    )
      throw new Error('Invalid DPoP proof');
    if (options.accessToken !== undefined) {
      if (
        !options.expectedJkt ||
        !options.accessToken ||
        !/^[\x21-\x7e]+$/.test(options.accessToken) ||
        /^DPoP (.+)$/i.exec(request.headers.get('authorization') ?? '')?.[1] !== options.accessToken
      )
        throw new Error('Invalid DPoP token binding');
    }
    const verified = await this.library.verifyDpopJwt({
      dpopJwt: compact,
      request: requestLike(request),
      expectedNonce: options.nonce,
      accessToken: options.accessToken,
      expectedJwkThumbprint: options.expectedJkt,
      allowedSigningAlgs: ['ES256'],
      maxProofAgeSeconds: dpopProfile.maxAgeSeconds,
      allowedClockSkewSeconds: dpopProfile.clockSkewSeconds,
      now: new Date(this.#clock() * 1000),
    });
    const current = this.#clock();
    const { iat, jti } = verified.payload;
    if (
      !Number.isSafeInteger(iat) ||
      iat > current + 10 ||
      iat < current - 70 ||
      typeof jti !== 'string' ||
      !jti ||
      jti.length > 256 ||
      /[\x00-\x20\x7f]/.test(jti)
    )
      throw new Error('Invalid DPoP time or replay identifier');
    for (const [key, deadline] of this.#ledger) if (deadline < current) this.#ledger.delete(key);
    const id = JSON.stringify([verified.jwkThumbprint, jti]);
    if (this.#ledger.has(id) || this.#ledger.size >= this.#capacity)
      throw new Error('DPoP replay rejected');
    this.#ledger.set(id, iat + 70);
    return { jkt: verified.jwkThumbprint };
  }
}

// Isolated DPoP-required wrapper around the existing anonymous pre-authorized issuer.
// Its external endpoint rejects Bearer; the underlying core interface remains Bearer.
// DPoP is NOT client authentication.
export class DpopIssuanceFixture {
  readonly issuer: IssuerFixture;
  readonly gate: DpopGate;
  readonly nonce = random();
  #tokens = new Map<string, { jkt: string; deadline: number }>();
  #clock: () => number;
  constructor(issuer: IssuerFixture, clock = now) {
    this.issuer = issuer;
    this.#clock = clock;
    this.gate = new DpopGate(clock);
  }
  readonly transport: Transport = async (request) => {
    if (request.url === profile.authorizationMetadataEndpoint && request.method === 'GET') {
      const response = await this.issuer.transport(request);
      return jsonResponse({
        ...(await response.json()),
        dpop_signing_alg_values_supported: ['ES256'],
      });
    }
    if (request.url !== profile.tokenEndpoint && request.url !== profile.credentialEndpoint)
      return this.issuer.transport(request);
    const resource = request.url === profile.credentialEndpoint;
    const token = /^DPoP ([A-Za-z0-9_-]{43})$/i.exec(
      request.headers.get('authorization') ?? '',
    )?.[1];
    const row = token ? this.#tokens.get(hash(token)) : undefined;
    if (resource && (!row || this.#clock() >= row.deadline)) {
      const response = jsonResponse({ error: 'invalid_token' }, 401);
      response.headers.set('www-authenticate', 'DPoP error="invalid_token"');
      return response;
    }
    for (const [key, value] of this.#tokens)
      if (this.#clock() >= value.deadline) this.#tokens.delete(key);
    if (!resource && this.#tokens.size >= 1000)
      return jsonResponse({ error: 'temporarily_unavailable' }, 503);
    let jkt: string;
    try {
      ({ jkt } = await this.gate.verify(request, {
        nonce: this.nonce,
        accessToken: resource ? token : undefined,
        expectedJkt: row?.jkt,
      }));
    } catch {
      let error = 'invalid_dpop_proof';
      try {
        if (decodeJwt(request.headers.get('dpop') ?? '').nonce !== this.nonce)
          error = 'use_dpop_nonce';
      } catch {
        if (!request.headers.has('dpop')) error = 'use_dpop_nonce';
      }
      const response = jsonResponse({ error }, resource ? 401 : 400);
      response.headers.set('dpop-nonce', this.nonce);
      if (resource) response.headers.set('www-authenticate', `DPoP error="${error}"`);
      return response;
    }
    const headers = new Headers(request.headers);
    headers.delete('dpop');
    if (resource) headers.set('authorization', `Bearer ${token}`);
    const response = await this.issuer.transport(new Request(request, { headers }));
    if (resource || !response.ok) return response;
    const body = (await response.json()) as { access_token: string; expires_in: number };
    this.#tokens.set(hash(body.access_token), { jkt, deadline: this.#clock() + body.expires_in });
    return jsonResponse({ ...body, token_type: 'DPoP' });
  };
}

// Bounded wallet transport: external DPoP token translated to the existing receipt API only.
// A dedicated sender key is separate from the credential holder key created by receiveOffer().
export async function dpopReceiptTransport(transport: Transport, sender: JWK): Promise<Transport> {
  let nonce: string | undefined;
  return async (request) => {
    if (request.url === profile.authorizationMetadataEndpoint) {
      const response = await transport(request);
      const body = (await response.clone().json()) as {
        dpop_signing_alg_values_supported?: string[];
      };
      if (
        !response.ok ||
        !Array.isArray(body.dpop_signing_alg_values_supported) ||
        !body.dpop_signing_alg_values_supported.includes('ES256')
      )
        throw new Error('DPoP metadata downgrade');
      return response;
    }
    const tokenEndpoint = request.url === profile.tokenEndpoint;
    const resource = request.url === profile.credentialEndpoint;
    if (!tokenEndpoint && !resource) return transport(request);
    const token = resource
      ? /^Bearer (.+)$/.exec(request.headers.get('authorization') ?? '')?.[1]
      : undefined;
    const send = async () => {
      const headers = new Headers(request.headers);
      for (const [name, value] of Object.entries(
        await proofHeaders(sender, request, { nonce, accessToken: token }),
      ))
        headers.set(name, value);
      if (resource) headers.set('authorization', `DPoP ${token}`);
      return transport(new Request(request.clone(), { headers }));
    };
    let response = await send();
    if (tokenEndpoint && response.status === 400 && !nonce) {
      const challenge = response.headers.get('dpop-nonce');
      const body = (await response.clone().json()) as { error?: string };
      if (challenge && /^[A-Za-z0-9_-]{43}$/.test(challenge) && body.error === 'use_dpop_nonce') {
        nonce = challenge;
        response = await send();
      }
    }
    if (tokenEndpoint && response.ok) {
      const body = (await response.json()) as { token_type?: string };
      if (body.token_type !== 'DPoP') throw new Error('DPoP response downgrade');
      // The original wallet still has an internal Bearer interface, qualified separately.
      return jsonResponse({ ...body, token_type: 'Bearer' });
    }
    return response;
  };
}
