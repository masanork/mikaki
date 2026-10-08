// Synthetic component probe only; not a product issuer or wallet service.
import { createHash, randomBytes, randomInt } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import {
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
} from 'jose';
import {
  Openid4vciIssuer,
  Openid4vciVersion,
  type IssuerMetadataResult,
} from '@openid4vc/openid4vci';
import { FixtureWallet, digest, profile as presentationProfile } from '../oid4vp/probe.ts';

export const profile = {
  issuer: presentationProfile.issuer,
  vct: presentationProfile.vct,
  configurationId: 'membership_v1',
  grantType: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
  issuerLibraryVersion: '0.7.0',
  tokenEndpoint: `${presentationProfile.issuer}/token`,
  nonceEndpoint: `${presentationProfile.issuer}/nonce`,
  credentialEndpoint: `${presentationProfile.issuer}/credential`,
  metadataEndpoint: `${presentationProfile.issuer}/.well-known/openid-credential-issuer`,
  authorizationMetadataEndpoint: `${presentationProfile.issuer}/.well-known/oauth-authorization-server`,
} as const;

const randomToken = () => randomBytes(32).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);
export const jsonResponse = (value: unknown, status = 200) =>
  Response.json(value, {
    status,
    headers: { 'cache-control': 'no-store' },
  });
const errorResponse = (error: string, status = 400) => jsonResponse({ error }, status);
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Invalid protocol object');
  return value as Record<string, unknown>;
}
export type Transport = (request: Request) => Promise<Response>;
const issuerRequest = (url: string, init?: RequestInit) =>
  new Request(url, { ...init, redirect: 'error' });

type Callbacks = ConstructorParameters<typeof Openid4vciIssuer>[0]['callbacks'];
function callbacks(clock: () => number): Callbacks {
  const unsupported = async (): Promise<never> => {
    throw new Error('Unsupported fixture operation');
  };
  return {
    hash: (data, alg) => createHash(alg.replace('-', '')).update(data).digest(),
    generateRandom: (length) => randomBytes(length),
    signJwt: unsupported,
    encryptJwe: unsupported,
    clientAuthentication: unsupported,
    async verifyJwt(signer, jwt) {
      if (signer.method !== 'jwk' || signer.alg !== 'ES256') return { verified: false };
      try {
        await jwtVerify(jwt.compact, await importJWK(signer.publicJwk, 'ES256'), {
          algorithms: ['ES256'],
          currentDate: new Date(clock() * 1000),
        });
        return { verified: true, signerJwk: signer.publicJwk };
      } catch {
        return { verified: false };
      }
    },
  };
}

export class IssuerFixture {
  readonly library: Openid4vciIssuer;
  readonly metadata: IssuerMetadataResult;
  readonly offer: Record<string, unknown>;
  readonly txCode = randomInt(1_000_000).toString().padStart(6, '0');
  readonly issuerPublic: JWK;
  readonly clock: () => number;
  #issuerKey: CryptoKey;
  #code: string;
  #codePending = true;
  #codeDeadline: number;
  #failedCodes = 0;
  #tokens = new Map<string, { deadline: number; pending: boolean; configuration: string }>();
  #nonces = new Map<string, { deadline: number; pending: boolean }>();
  requests = 0;
  issued = 0;

  private constructor(key: CryptoKey, publicKey: JWK, clock: () => number) {
    this.#issuerKey = key;
    this.issuerPublic = publicKey;
    this.clock = clock;
    this.#code = randomToken();
    this.#codeDeadline = clock() + 90;
    this.library = new Openid4vciIssuer({ callbacks: callbacks(clock) });
    const credentialIssuer = this.library.createCredentialIssuerMetadata({
      credential_issuer: profile.issuer,
      authorization_servers: [profile.issuer],
      credential_endpoint: profile.credentialEndpoint,
      nonce_endpoint: profile.nonceEndpoint,
      credential_configurations_supported: {
        [profile.configurationId]: {
          format: 'dc+sd-jwt',
          vct: profile.vct,
          scope: 'membership',
          cryptographic_binding_methods_supported: ['jwk'],
          credential_signing_alg_values_supported: ['ES256'],
          proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
          credential_metadata: { display: [{ name: 'Synthetic membership' }] },
        },
      },
    });
    this.metadata = {
      originalDraftVersion: Openid4vciVersion.V1,
      credentialIssuer,
      authorizationServers: [
        {
          issuer: profile.issuer,
          token_endpoint: profile.tokenEndpoint,
          grant_types_supported: [profile.grantType],
          'pre-authorized_grant_anonymous_access_supported': true,
        },
      ],
      knownCredentialConfigurations:
        this.library.getKnownCredentialConfigurationsSupported(credentialIssuer),
    };
    this.offer = {}; // Filled by the independent offer builder in create().
  }

  static async create(clock: () => number = now): Promise<IssuerFixture> {
    const key = await generateKeyPair('ES256', { extractable: true });
    const fixture = new IssuerFixture(
      key.privateKey as CryptoKey,
      await exportJWK(key.publicKey),
      clock,
    );
    const { credentialOfferObject } = await fixture.library.createCredentialOffer({
      issuerMetadata: fixture.metadata,
      credentialConfigurationIds: [profile.configurationId],
      grants: {
        [profile.grantType]: {
          'pre-authorized_code': fixture.#code,
          tx_code: { input_mode: 'numeric', length: 6 },
        },
      },
    });
    Object.assign(fixture.offer, credentialOfferObject);
    return fixture;
  }

  async verifyProof(jwt: string, nonce: string) {
    // This method exposes the independent proof verifier for separate-layer tests.
    return this.library.verifyCredentialRequestJwtProof({
      issuerMetadata: this.metadata,
      jwt,
      expectedNonce: nonce,
      nonceExpiresAt: new Date((this.clock() + 60) * 1000),
      now: new Date(this.clock() * 1000),
    });
  }

  async signedArtifact(
    holderPublic: JWK,
    overrides: Record<string, unknown> = {},
  ): Promise<string> {
    const disclosures = [
      ['membership_active', true],
      ['name', 'Synthetic Member'],
      ['member_number', 'SYNTHETIC-0001'],
    ].map(([name, value]) =>
      Buffer.from(JSON.stringify([randomToken(), name, value])).toString('base64url'),
    );
    const jwt = await new SignJWT({
      iss: profile.issuer,
      vct: profile.vct,
      iat: this.clock(),
      exp: this.clock() + 300,
      cnf: { jwk: holderPublic },
      _sd_alg: 'sha-256',
      _sd: disclosures.map(digest).sort(),
      ...overrides,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' })
      .sign(this.#issuerKey);
    return `${jwt}~${disclosures.join('~')}~`;
  }

  readonly transport: Transport = async (request) => {
    this.requests++;
    if (request.url === profile.metadataEndpoint && request.method === 'GET')
      return jsonResponse(this.metadata.credentialIssuer);
    if (request.url === profile.authorizationMetadataEndpoint && request.method === 'GET')
      return jsonResponse(this.metadata.authorizationServers[0]);
    if (request.method !== 'POST') return errorResponse('invalid_request');
    if (request.url === profile.nonceEndpoint) {
      const nonce = randomToken();
      this.#nonces.set(digest(nonce), { deadline: this.clock() + 60, pending: true });
      return jsonResponse(this.library.createNonceResponse({ cNonce: nonce }));
    }
    const type = request.headers.get('content-type') ?? '';
    const body = await request.text();
    if (Buffer.byteLength(body) > 32768) return errorResponse('invalid_request');
    if (request.url === profile.tokenEndpoint) {
      if (!/^application\/x-www-form-urlencoded(?:;|$)/i.test(type))
        return errorResponse('invalid_request');
      const form = new URLSearchParams(body);
      if (
        form.size !== 3 ||
        form.getAll('grant_type').length !== 1 ||
        form.getAll('pre-authorized_code').length !== 1 ||
        form.getAll('tx_code').length !== 1 ||
        form.get('grant_type') !== profile.grantType
      )
        return errorResponse('invalid_request');
      if (
        !this.#codePending ||
        this.clock() >= this.#codeDeadline ||
        form.get('pre-authorized_code') !== this.#code
      )
        return errorResponse('invalid_grant');
      if (form.get('tx_code') !== this.txCode) {
        if (++this.#failedCodes >= 3) this.#codePending = false;
        return errorResponse('invalid_grant');
      }
      this.#codePending = false;
      const accessToken = randomToken();
      this.#tokens.set(digest(accessToken), {
        deadline: this.clock() + 120,
        pending: true,
        configuration: profile.configurationId,
      });
      return jsonResponse({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 120,
        scope: 'membership',
      });
    }
    if (request.url !== profile.credentialEndpoint) return errorResponse('invalid_request');
    const auth = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(request.headers.get('authorization') ?? '');
    const authority = auth ? this.#tokens.get(digest(auth[1]!)) : undefined;
    if (!authority?.pending || this.clock() >= authority.deadline)
      return errorResponse('invalid_token', 401);
    if (!/^application\/json(?:;|$)/i.test(type)) return errorResponse('invalid_request');
    let raw: Record<string, unknown>;
    try {
      raw = object(JSON.parse(body));
    } catch {
      return errorResponse('invalid_request');
    }
    // Final subset only: never normalize legacy proof/format into this profile.
    if (!isDeepStrictEqual(Object.keys(raw).sort(), ['credential_configuration_id', 'proofs']))
      return errorResponse('invalid_request');
    if (raw.credential_configuration_id !== authority.configuration)
      return errorResponse('unknown_credential_configuration');
    let parsed: ReturnType<Openid4vciIssuer['parseCredentialRequest']>;
    let proof: string;
    try {
      parsed = this.library.parseCredentialRequest({
        issuerMetadata: this.metadata,
        credentialRequest: raw,
      });
      const proofs = object(raw.proofs);
      if (
        !isDeepStrictEqual(Object.keys(proofs), ['jwt']) ||
        !Array.isArray(proofs.jwt) ||
        proofs.jwt.length !== 1 ||
        typeof proofs.jwt[0] !== 'string'
      )
        return errorResponse('invalid_proof');
      proof = proofs.jwt[0];
    } catch {
      return errorResponse('invalid_proof');
    }
    let nonce: string;
    try {
      const value = decodeJwt(proof).nonce;
      if (typeof value !== 'string') return errorResponse('invalid_proof');
      nonce = value;
    } catch {
      return errorResponse('invalid_proof');
    }
    const nonceRow = this.#nonces.get(digest(nonce));
    if (!nonceRow?.pending || this.clock() >= nonceRow.deadline)
      return errorResponse('invalid_nonce');
    nonceRow.pending = false;
    try {
      const verified = await this.verifyProof(proof, nonce);
      const publicKey = verified.signer.publicJwk;
      const header = verified.header;
      const payload = verified.payload;
      if (
        header.alg !== 'ES256' ||
        !header.jwk ||
        header.kid ||
        header.x5c ||
        header.key_attestation ||
        header.trust_chain ||
        !isDeepStrictEqual(Object.keys(publicKey).sort(), ['crv', 'kty', 'x', 'y']) ||
        publicKey.kty !== 'EC' ||
        publicKey.crv !== 'P-256' ||
        payload.iss !== undefined ||
        payload.aud !== profile.issuer ||
        !Number.isSafeInteger(payload.iat) ||
        payload.iat > this.clock() + 5 ||
        payload.iat < this.clock() - 60
      )
        return errorResponse('invalid_proof');
      if (!authority.pending || this.clock() >= authority.deadline)
        return errorResponse('invalid_token', 401);
      authority.pending = false;
      const artifact = await this.signedArtifact(publicKey);
      const { credentialResponse } = await this.library.createCredentialResponse({
        credentialRequest: parsed,
        credentials: [{ credential: artifact }],
      });
      this.issued++;
      return jsonResponse(credentialResponse);
    } catch {
      return errorResponse('invalid_proof');
    }
  };
}

export async function makeProof(
  holderPrivate: JWK,
  nonce: string,
  overrides: Record<string, unknown> = {},
  headerOverrides: Record<string, unknown> = {},
): Promise<string> {
  const publicKey = { ...holderPrivate };
  delete publicKey.d;
  return new SignJWT({ aud: profile.issuer, iat: now(), nonce, ...overrides })
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'openid4vci-proof+jwt',
      jwk: publicKey,
      ...headerOverrides,
    })
    .sign(await importJWK(holderPrivate, 'ES256'));
}

async function readJson(response: Response, status: number): Promise<Record<string, unknown>> {
  if (
    response.status !== status ||
    response.redirected ||
    !/(?:^|,)\s*no-store\s*(?:,|$)/i.test(response.headers.get('cache-control') ?? '') ||
    response.headers.has('location') ||
    !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? '')
  )
    throw new Error('Unsupported issuer response');
  const body = await response.text();
  if (Buffer.byteLength(body) > 32768) throw new Error('Issuer response too large');
  return object(JSON.parse(body));
}

export async function importResponse(
  response: Response,
  holderPrivate: JWK,
  issuerPublic: JWK,
  key: CryptoKey,
): Promise<FixtureWallet> {
  const body = await readJson(response, 200);
  // Reject draft response forms, deferred issuance, extra instances and mixed states.
  if (
    !isDeepStrictEqual(Object.keys(body), ['credentials']) ||
    !Array.isArray(body.credentials) ||
    body.credentials.length !== 1
  )
    throw new Error('Unsupported credential response');
  const entry = object(body.credentials[0]);
  if (
    !isDeepStrictEqual(Object.keys(entry), ['credential']) ||
    typeof entry.credential !== 'string'
  )
    throw new Error('Invalid credential response');
  return FixtureWallet.import(entry.credential, holderPrivate, issuerPublic, key);
}

export async function receiveOffer(options: {
  offer: unknown;
  txCode: string;
  approved: boolean;
  transport: Transport;
  issuerPublic: JWK;
  key: CryptoKey;
}): Promise<FixtureWallet | null> {
  if (!options.approved) return null;
  const offer = object(options.offer);
  const grants = object(offer.grants);
  const grant = object(grants[profile.grantType]);
  if (
    offer.credential_issuer !== profile.issuer ||
    !isDeepStrictEqual(offer.credential_configuration_ids, [profile.configurationId]) ||
    !isDeepStrictEqual(Object.keys(grants), [profile.grantType]) ||
    typeof grant['pre-authorized_code'] !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(grant['pre-authorized_code']) ||
    !isDeepStrictEqual(grant.tx_code, { input_mode: 'numeric', length: 6 }) ||
    !/^\d{6}$/.test(options.txCode) ||
    grant.authorization_server !== undefined
  )
    throw new Error('Unsupported credential offer');
  // Fixed trusted endpoints: never follow an offer/metadata URL to another origin or redirect.
  const metadata = await readJson(
    await options.transport(issuerRequest(profile.metadataEndpoint)),
    200,
  );
  const configs = object(metadata.credential_configurations_supported);
  const config = object(configs[profile.configurationId]);
  if (
    metadata.credential_issuer !== profile.issuer ||
    metadata.credential_endpoint !== profile.credentialEndpoint ||
    metadata.nonce_endpoint !== profile.nonceEndpoint ||
    !isDeepStrictEqual(metadata.authorization_servers, [profile.issuer]) ||
    metadata.credential_request_encryption !== undefined ||
    metadata.credential_response_encryption !== undefined ||
    config.format !== 'dc+sd-jwt' ||
    config.vct !== profile.vct ||
    config.scope !== 'membership' ||
    !isDeepStrictEqual(config.cryptographic_binding_methods_supported, ['jwk']) ||
    !isDeepStrictEqual(config.credential_signing_alg_values_supported, ['ES256']) ||
    !isDeepStrictEqual(config.proof_types_supported, {
      jwt: { proof_signing_alg_values_supported: ['ES256'] },
    })
  )
    throw new Error('Unsupported issuer metadata');
  const as = await readJson(
    await options.transport(issuerRequest(profile.authorizationMetadataEndpoint)),
    200,
  );
  if (
    as.issuer !== profile.issuer ||
    as.token_endpoint !== profile.tokenEndpoint ||
    !isDeepStrictEqual(as.grant_types_supported, [profile.grantType]) ||
    as['pre-authorized_grant_anonymous_access_supported'] !== true
  )
    throw new Error('Unsupported authorization metadata');
  const body = new URLSearchParams({
    grant_type: profile.grantType,
    'pre-authorized_code': grant['pre-authorized_code'],
    tx_code: options.txCode,
  });
  const token = await readJson(
    await options.transport(issuerRequest(profile.tokenEndpoint, { method: 'POST', body })),
    200,
  );
  if (
    typeof token.access_token !== 'string' ||
    !/^[A-Za-z0-9_-]{43}$/.test(token.access_token) ||
    token.token_type !== 'Bearer' ||
    token.scope !== 'membership' ||
    !Number.isSafeInteger(token.expires_in) ||
    (token.expires_in as number) <= 0 ||
    (token.expires_in as number) > 120 ||
    token.refresh_token !== undefined ||
    token.authorization_details !== undefined
  )
    throw new Error('Unsupported issuance token');
  const nonce = await readJson(
    await options.transport(issuerRequest(profile.nonceEndpoint, { method: 'POST' })),
    200,
  );
  if (typeof nonce.c_nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce.c_nonce))
    throw new Error('Invalid issuer nonce');
  const holder = await generateKeyPair('ES256', { extractable: true });
  const holderPrivate = await exportJWK(holder.privateKey);
  const proof = await makeProof(holderPrivate, nonce.c_nonce);
  const response = await options.transport(
    issuerRequest(profile.credentialEndpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token.access_token}`,
      },
      body: JSON.stringify({
        credential_configuration_id: profile.configurationId,
        proofs: { jwt: [proof] },
      }),
    }),
  );
  return importResponse(response, holderPrivate, options.issuerPublic, options.key);
}
