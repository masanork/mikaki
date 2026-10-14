import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { productionIdentityTestProfile } from './identity-test-profile.ts';
import { assertIdentityHaipSecrets } from './identity-haip-profile.ts';

test('HAIP operator profile requires exact public trust, Wallet policy, service and separate custody', () => {
  const config = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
  assert.equal(productionIdentityTestProfile(config), 'operator-card-haip-age');
  for (const change of [
    (c: typeof config) => {
      c.vars.IDENTITY_ENABLED = 'false';
    },
    (c: typeof config) => {
      c.vars.IDENTITY_HAIP_ENABLED = 'false';
    },
    (c: typeof config) => {
      c.vars.IDENTITY_ISSUANCE_CLAIMS = '["birthdate"]';
    },
    (c: typeof config) => {
      c.vars.MIKAKI_DPOP_NONCE_MODE = 'off';
    },
    (c: typeof config) => {
      c.vars.IDENTITY_HAIP_AGE_BATCH_ENABLED = 'true';
    },
    (c: typeof config) => {
      c.vars.IDENTITY_CREDENTIAL_CERTIFICATES = '{}';
    },
    (c: typeof config) => {
      c.vars.IDENTITY_HAIP_POLICY_SHA256 = '0'.repeat(64);
    },
    (c: typeof config) => {
      c.vars.IDENTITY_WALLET_CLIENTS = '[]';
    },
    (c: typeof config) => {
      c.services.find(
        (s: { binding: string }) => s.binding === 'IDENTITY_ANDROID_VERIFIER',
      ).service = 'other';
    },
    (c: typeof config) => {
      c.secrets.required = c.secrets.required.filter(
        (s: string) => s !== 'IDENTITY_ATTESTER_SIGNING',
      );
    },
  ]) {
    const changed = structuredClone(config);
    change(changed);
    assert.throws(() => productionIdentityTestProfile(changed));
  }
  assert.throws(
    () => assertIdentityHaipSecrets({ IDENTITY_ATTESTER_SIGNING: 'never expose this value' }),
    (e: unknown) => e instanceof Error && !e.message.includes('never expose this value'),
  );
});
