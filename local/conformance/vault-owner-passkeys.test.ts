import assert from 'node:assert/strict';
import test from 'node:test';
import { VaultScope } from '../../crates/worker/ui/vault-lifecycle.ts';
import { OwnerVaultController } from '../../crates/worker/ui/vault-owner-controller.ts';
import { encodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';
import {
  prepareOwnerPasskey,
  finishOwnerPasskey,
  listOwnerPasskeys,
} from '../../crates/worker/ui/vault-owner-passkeys.ts';

test('login enrollment pins origin/UV/discoverability, retains exact public retry bytes and never sends owner keys or PRF outputs', async () => {
  const source = new Uint8Array(32).fill(8),
    target = new Uint8Array(32).fill(18);
  const identity = {
    account_id: 'owner',
    credential_id: encodeBase64Url(source),
    session_tag: 's'.repeat(43),
  };
  let root: Record<string, unknown> | null = null;
  let lost = true,
    registered = false,
    wrongRp = false,
    wrongReceipt = false,
    creates = 0;
  const sent: string[] = [];
  const output = new Uint8Array(32).fill(9);
  const scope = new VaultScope(
    () => {},
    undefined,
    undefined,
    async (input, init) => {
      switch (String(input)) {
        case '/vault/session':
          return Response.json(identity);
        case '/vault/owner-key':
          if (init?.method === 'PUT')
            root = {
              ...JSON.parse(String(init.body)),
              owner_id: 'owner',
              origin: 'https://mikaki.test',
              revision: 1,
            };
          return root
            ? Response.json(root, { headers: { ETag: '"1"' } })
            : Response.json({ error: 'owner_key_missing' }, { status: 404 });
        case '/vault/passkeys':
          return Response.json([
            { credential_id: identity.credential_id },
            ...(registered ? [{ credential_id: encodeBase64Url(target) }] : []),
          ]);
        case '/vault/passkeys/start':
          return Response.json({
            transaction_id: 't'.repeat(43),
            challenge: encodeBase64Url(new Uint8Array(32).fill(3)),
            user_handle: encodeBase64Url(new Uint8Array(32).fill(4)),
            rp_id: wrongRp ? 'evil.test' : 'mikaki.test',
            exclude_credentials: [{ credential_id: identity.credential_id }],
          });
        case '/vault/passkeys/finish':
          sent.push(String(init?.body));
          registered = true;
          if (lost) {
            lost = false;
            throw new TypeError('lost committed response');
          }
          return Response.json({ credential_id: encodeBase64Url(wrongReceipt ? source : target) });
        default:
          throw new Error('unexpected endpoint');
      }
    },
  );
  const owner = new OwnerVaultController(scope, 'https://mikaki.test', async () => ({
    credentialId: source,
    output,
  }));
  class Attestation {
    clientDataJSON = new Uint8Array([1, 2]).buffer;
    attestationObject = new Uint8Array([3, 4]).buffer;
  }
  class Credential {
    rawId = target.slice().buffer;
    id = encodeBase64Url(target);
    response = new Attestation();
    getClientExtensionResults() {
      return { credProps: { rk: true } };
    }
  }
  const originals = new Map(
    ['navigator', 'PublicKeyCredential', 'AuthenticatorAttestationResponse'].map((name) => [
      name,
      Object.getOwnPropertyDescriptor(globalThis, name),
    ]),
  );
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    value: {
      credentials: {
        create: async (options: CredentialCreationOptions) => {
          creates++;
          assert.equal(options.publicKey?.rp.id, 'mikaki.test');
          assert.equal(options.publicKey?.authenticatorSelection?.userVerification, 'required');
          assert.equal(options.publicKey?.authenticatorSelection?.residentKey, 'required');
          assert.equal(options.publicKey?.excludeCredentials?.length, 1);
          assert.deepEqual(options.publicKey?.extensions?.prf, {});
          return new Credential();
        },
      },
    },
  });
  Object.defineProperty(globalThis, 'PublicKeyCredential', {
    configurable: true,
    value: Credential,
  });
  Object.defineProperty(globalThis, 'AuthenticatorAttestationResponse', {
    configurable: true,
    value: Attestation,
  });
  try {
    await owner.open();
    assert.ok(output.every((byte) => byte === 0));
    const prepared = await prepareOwnerPasskey(owner);
    assert.equal(prepared.credentialId, encodeBase64Url(target));
    await assert.rejects(finishOwnerPasskey(owner, prepared), /lost committed response/);
    await finishOwnerPasskey(owner, prepared);
    assert.equal(creates, 1);
    assert.equal(sent[0], sent[1]);
    assert.deepEqual(Object.keys(JSON.parse(prepared.body)).sort(), ['response', 'transaction_id']);
    assert.deepEqual(Object.keys(JSON.parse(prepared.body).response).sort(), [
      'attestation',
      'client_data',
      'id',
    ]);
    assert.equal((await listOwnerPasskeys(owner)).length, 2);
    wrongReceipt = true;
    await assert.rejects(finishOwnerPasskey(owner, prepared), /registration_unconfirmed/);
    wrongRp = true;
    await assert.rejects(prepareOwnerPasskey(owner), /invalid passkey response/);
    assert.equal(creates, 1, 'A different RP is rejected before a ceremony');
  } finally {
    owner.dispose();
    for (const [name, descriptor] of originals)
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else Reflect.deleteProperty(globalThis, name);
  }
});
