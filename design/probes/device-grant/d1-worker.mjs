// Isolated test fixture only. No authentication, routing, or production use.
export default {
  async fetch(request, env) {
    const { code, client, key, now, token } = await request.json();
    try {
      const result = await env.DB.batch([
        env.DB.prepare(
          `UPDATE grant_probe SET state='redeemed'
          WHERE code_digest=? AND client_id=? AND key_thumbprint=?
            AND expires_at>? AND state='approved'`,
        ).bind(code, client, key, now),
        env.DB.prepare(
          `INSERT INTO token_probe(token_digest,owner)
          SELECT ?,owner FROM grant_probe WHERE code_digest=? AND changes()=1
          RETURNING owner`,
        ).bind(token, code),
      ]);
      return Response.json({ changed: result[0].meta.changes, tokens: result[1].results });
    } catch {
      return Response.json({ error: 'transaction_failed' }, { status: 409 });
    }
  },
};
