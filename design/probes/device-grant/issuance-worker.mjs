// Test-only D1 store fixture. It assumes inputs have already been validated;
// this is not an HTTP authorization endpoint or a proof verifier.
export default {
  async fetch(request, env) {
    const { deviceDigest, userIndex, client, scope, key, proofId, expires, fault } =
      await request.json();
    try {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO replay_probe VALUES(?,?)').bind(key, proofId),
        env.DB.prepare(
          `INSERT INTO grant_probe
          (code_digest,user_index,client_id,scope,key_thumbprint,expires_at,state)
          VALUES(?,?,?,?,?,?,'pending')`,
        ).bind(deviceDigest, userIndex, client, scope, key, expires),
        env.DB.prepare('INSERT INTO audit_probe VALUES(?)').bind(
          fault ? 'duplicate' : deviceDigest,
        ),
      ]);
      return new Response(null, { status: 201 });
    } catch {
      return new Response(null, { status: 409 });
    }
  },
};
