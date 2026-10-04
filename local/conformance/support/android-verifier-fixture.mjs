// Disposable fixture PKI verifier ONLY. Not Android/Google/app-integrity validation.
// Never deploy this worker as IDENTITY_ANDROID_VERIFIER.
import { X509Certificate } from 'node:crypto';
export default {
  async fetch(request, env) {
    const b = await request.json();
    const fail = () => Response.json({ verified: false }, { status: 403 });
    if (
      b.format !== 'android-key-attestation-verification-v1' ||
      b.verifier_policy_hash !== env.FIXTURE_POLICY_HASH ||
      b.evidence.certificate_chain.length !== 3
    )
      return fail();
    try {
      const certificates = b.evidence.certificate_chain.map(
        (c) => new X509Certificate(Buffer.from(c, 'base64')),
      );
      if (
        !certificates[2].raw.equals(Buffer.from(env.FIXTURE_ROOT, 'base64')) ||
        !certificates[0].verify(certificates[1].publicKey) ||
        !certificates[1].verify(certificates[2].publicKey)
      )
        return fail();
      const actual = certificates[0].publicKey.export({ format: 'jwk' });
      if (['kty', 'crv', 'x', 'y'].some((k) => actual[k] !== b.evidence.public_key[k]))
        return fail();
    } catch {
      return fail();
    }
    const response = {
      format: 'android-key-attestation-verdict-v1',
      verified: true,
      client_id: b.client_id,
      purpose: b.purpose,
      challenge: b.evidence.challenge,
      public_key: b.evidence.public_key,
      verifier_policy_hash: b.verifier_policy_hash,
      expires_at: Math.floor(Date.now() / 1000) + 600,
    };
    switch (env.FIXTURE_MODE) {
      case 'timeout':
        await new Promise((resolve) => setTimeout(resolve, 11000));
        break;
      case 'reject':
        response.verified = false;
        break;
      case 'key':
        response.public_key = { ...response.public_key, x: 'wrong' };
        break;
      case 'challenge':
        response.challenge = 'wrong';
        break;
      case 'client':
        response.client_id = 'wrong';
        break;
      case 'purpose':
        response.purpose = 'wrong';
        break;
      case 'policy':
        response.verifier_policy_hash = 'wrong';
        break;
      case 'expired':
        response.expires_at = 1;
        break;
      case 'oversized':
        return Response.json({ ...response, extra: 'x'.repeat(4096) });
      case 'redirect':
        return new Response(null, { status: 302, headers: { Location: 'https://evil.example/' } });
    }
    return Response.json(response);
  },
};
