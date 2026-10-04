import assert from 'node:assert/strict';
import { cp, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

/** Use a dedicated attester and supported proof preference in a private source copy. */
export async function prepareEudiAttesterFixture(checkout: string, directory: string) {
  const copied = join(directory, 'upstream');
  await cp(checkout, copied, {
    recursive: true,
    filter: (path) => !['.git', 'eudi'].includes(path.split('/').at(-1)!),
  });
  const source = join(copied, 'internal/wallet/issuance_authcode.go');
  let text = await readFile(source, 'utf8');
  for (const name of ['createClientAttestationHeaders', 'createKeyAttestation']) {
    const begin = text.indexOf(`func ${name}(`);
    const end = text.indexOf('\nfunc ', begin + 1);
    assert.ok(begin >= 0 && end > begin);
    const original = text.slice(begin, end);
    const body = original.indexOf('\n');
    let changed =
      original.slice(0, body) +
      '\n\tsigner, chain := mikakiAttestationMaterial(w)' +
      original.slice(body);
    changed = changed.replaceAll('w.IssuerKey', 'signer').replaceAll('w.CertChain', 'chain');
    assert.notEqual(changed, original);
    text = text.slice(0, begin) + changed + text.slice(end);
  }
  const declaration = 'func credentialProofType(metadata map[string]any, configID string) string {';
  assert.equal(text.split(declaration).length, 2);
  text = text.replace(
    declaration,
    declaration +
      '\n\tif mikakiFixtureJWTProof() { if _, offered := credentialProofTypes(metadata, configID)["jwt"]; offered { return "jwt" } }',
  );
  await writeFile(source, text);
  const issuance = join(copied, 'internal/wallet/issuance.go');
  let issuanceText = await readFile(issuance, 'utf8');
  const hook =
    'func (w *Wallet) requestCredentialWithNonceRetry(a credentialRequestAttempt, proofs credentialProofs) (map[string]any, error) {';
  assert.equal(issuanceText.split(hook).length, 2);
  issuanceText = issuanceText.replace(
    hook,
    hook + '\n\tif err := w.mikakiProbeKeyAttestations(a, proofs); err != nil { return nil, err }',
  );
  await writeFile(issuance, issuanceText);
  const fixture = await readFile(new URL('../eudi/MikakiAttesterFixture.go', import.meta.url));
  await writeFile(join(copied, 'internal/wallet/mikaki_attester_fixture.go'), fixture);
  return {
    checkout: copied,
    adapterSha256: createHash('sha256').update(fixture).digest('hex'),
    patchedSourceSha256: createHash('sha256').update(text).digest('hex'),
    patchedIssuanceSha256: createHash('sha256').update(issuanceText).digest('hex'),
  };
}
