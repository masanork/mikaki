// Independent Node verifier for Rust Wallet presentations, including live OID4VCI receipts.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { importJWK, jwtVerify } from 'jose';
import type { JWK } from 'jose';
import { decodeCbor, embedded, encodeCbor, field, verifyMdocIssuer } from './mdoc-test.ts';
import type { Cbor } from './mdoc-test.ts';

interface Vector {
  format: string;
  credential: string;
  request: string;
  presentation: string;
  values: Record<string, boolean>;
  mismatches: string[];
  request_claims: { nonce: string };
}
interface AgeFixture {
  issuer: string;
  issuer_jwk: JWK;
  holder_jwk: JWK;
  now: number;
  source_verified_at: number;
  registry: { client_id: string; response_uri: string; jwk: JWK };
  vectors: Vector[];
}
export function agePresentationVectors(issued?: {
  sd: string;
  mdoc: string;
  holder_private_jwk: JWK;
  issuer_kid: string;
}): AgeFixture {
  return JSON.parse(
    execFileSync(
      'cargo',
      [
        'run',
        '-q',
        '-p',
        'mikaki-identity',
        '--example',
        'age_presentation_fixture',
        '--offline',
        '--locked',
        ...(issued ? ['--', '--issued'] : []),
      ],
      {
        encoding: 'utf8',
        maxBuffer: 100_000,
        ...(issued ? { input: JSON.stringify(issued) } : {}),
      },
    ),
  );
}
const digest = (value: string | Buffer) => createHash('sha256').update(value).digest();
export async function verifyAgePresentations(
  f: AgeFixture,
  issuedClaims = ['age_over_18', 'age_over_20'],
) {
  const issuer = await importJWK(f.issuer_jwk, 'ES256');
  const holder = await importJWK(f.holder_jwk, 'ES256');
  const verifier = await importJWK(f.registry.jwk, 'ES256');
  for (const v of f.vectors) {
    assert.deepEqual(v.mismatches, ['credential_does_not_match', 'credential_does_not_match']);
    const request = await jwtVerify(v.request, verifier, {
      algorithms: ['ES256'],
      typ: 'oauth-authz-req+jwt',
      audience: 'https://self-issued.me/v2',
      issuer: f.registry.client_id,
    });
    assert.equal(request.payload.response_uri, f.registry.response_uri);
    const query = (
      request.payload.dcql_query as { credentials: { claims: { path: string[] }[] }[] }
    ).credentials[0];
    assert.deepEqual(
      query.claims.map((c) => c.path),
      [
        v.format === 'dc+sd-jwt'
          ? ['age_over_18']
          : ['app.tossa.mikaki.linked_document.1', 'age_over_18'],
      ],
    );
    assert.deepEqual(v.values, { age_over_18: true });
    if (v.format === 'dc+sd-jwt') {
      const full = v.credential.split('~');
      const issued = await jwtVerify(full[0], issuer, {
        algorithms: ['ES256'],
        typ: 'dc+sd-jwt',
        issuer: f.issuer,
      });
      assert.deepEqual(issued.payload.cnf, { jwk: f.holder_jwk });
      for (const name of ['name', 'address', 'birthdate', 'gender', 'document_expiry_date'])
        assert.equal(Object.hasOwn(issued.payload, name), false);
      const disclosures = full.slice(1, -1).map((d) => {
        assert.ok((issued.payload._sd as string[]).includes(digest(d).toString('base64url')));
        const [, name, value] = JSON.parse(Buffer.from(d, 'base64url').toString());
        assert.equal(typeof value, 'boolean');
        return name;
      });
      assert.deepEqual(disclosures.sort(), [...issuedClaims].sort());
      assert.equal((issued.payload._sd as string[]).length, issuedClaims.length);
      const evidence = issued.payload.evidence as Record<string, unknown>;
      assert.equal(evidence.assurance, 'issuer_signed_static_data');
      assert.equal(evidence.live_possession_verified, false);
      assert.equal(evidence.government_credential, false);
      assert.equal(evidence.predicate_source, 'birthdate');
      assert.equal(evidence.source_verified_at, f.source_verified_at);
      assert.ok(Number(evidence.verified_at) >= issued.payload.iat!);
      const parts = v.presentation.split('~');
      const kb = parts.pop()!;
      assert.equal(parts.length, 2);
      assert.equal(parts[0], full[0]);
      const [, name, value] = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      assert.deepEqual({ [name]: value }, { age_over_18: true });
      assert.ok((issued.payload._sd as string[]).includes(digest(parts[1]).toString('base64url')));
      const binding = await jwtVerify(kb, holder, {
        algorithms: ['ES256'],
        typ: 'kb+jwt',
        audience: f.registry.client_id,
      });
      assert.equal(binding.payload.nonce, request.payload.nonce);
      assert.equal(binding.payload.sd_hash, digest(`${parts.join('~')}~`).toString('base64url'));
      await assert.rejects(jwtVerify(kb, holder, { audience: 'different-verifier' }));
    } else {
      const full = verifyMdocIssuer(v.credential, f.holder_jwk, f.issuer_jwk);
      assert.deepEqual(Object.keys(full.values).sort(), [...issuedClaims].sort());
      for (const value of Object.values(full.values)) assert.equal(typeof value, 'boolean');
      const evidence = field(full.mso, 'mikakiEvidence');
      assert.equal(field(evidence, 'assurance'), 'issuer_signed_static_data');
      assert.equal(field(evidence, 'live_possession_verified'), false);
      assert.equal(field(evidence, 'government_credential'), false);
      assert.equal(field(evidence, 'predicate_source'), 'birthdate');
      const response = decodeCbor(Buffer.from(v.presentation, 'base64url'));
      const docs = field(response, 'documents');
      assert.ok(Array.isArray(docs) && docs.length === 1);
      const document = docs[0];
      const selected = verifyMdocIssuer(
        encodeCbor(field(document, 'issuerSigned')).toString('base64url'),
        f.holder_jwk,
        f.issuer_jwk,
      );
      assert.deepEqual(selected.values, { age_over_18: true });
      const transcript = [
        null,
        null,
        [
          'OpenID4VPHandover',
          digest(
            encodeCbor([
              f.registry.client_id,
              request.payload.nonce as string,
              null,
              f.registry.response_uri,
            ]),
          ),
        ],
      ] as Cbor;
      const device = field(document, 'deviceSigned');
      const ns = field(device, 'nameSpaces');
      assert.deepEqual(embedded(ns), new Map());
      const payload = encodeCbor({
        tag: 24,
        value: encodeCbor([
          'DeviceAuthentication',
          transcript,
          'app.tossa.mikaki.linked_document.1',
          ns,
        ]),
      });
      const auth = field(field(device, 'deviceAuth'), 'deviceSignature');
      assert.ok(Array.isArray(auth) && auth.length === 4);
      assert.equal(auth[2], null);
      const input = encodeCbor(['Signature1', auth[0], Buffer.alloc(0), payload]);
      const key = createPublicKey({ key: f.holder_jwk, format: 'jwk' });
      assert.equal(
        verify('sha256', input, { key, dsaEncoding: 'ieee-p1363' }, auth[3] as Buffer),
        true,
      );
      const changed = Buffer.from(input);
      changed[changed.length - 1] ^= 1;
      assert.equal(
        verify('sha256', changed, { key, dsaEncoding: 'ieee-p1363' }, auth[3] as Buffer),
        false,
      );
    }
  }
}
