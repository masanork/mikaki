// Local D1 experiment only. Inputs stand in for authenticated sessions and
// already verified key proofs; this is not an API or a production migration.
export default {
  async fetch(request, env) {
    const input = await request.json();
    try {
      if (input.action === 'complete') {
        const result = await env.DB.batch([
          env.DB.prepare(
            `UPDATE enrollment SET state='consumed'
            WHERE id=?1 AND session_id=?2 AND owner=?3 AND key_thumbprint=?4
              AND state='pending' AND expires_at>?5 AND nonce_hash=?6
              AND EXISTS (SELECT 1 FROM session s WHERE s.id=?2 AND s.owner=?3
                AND s.active=1 AND s.expires_at>?5)`,
          ).bind(input.id, input.session, input.owner, input.key, input.now, input.nonceHash),
          env.DB.prepare(
            `INSERT INTO replay(key_thumbprint,jti_hash)
            SELECT ?1,?2 WHERE changes()=1`,
          ).bind(input.key, input.proofId),
          env.DB.prepare(
            `INSERT INTO device(id,owner,key_thumbprint,state,revision)
            SELECT device_id,owner,key_thumbprint,'active',1 FROM enrollment
            WHERE id=?1 AND changes()=1 RETURNING id`,
          ).bind(input.id),
        ]);
        return Response.json({ completed: result[2].results });
      }
      if (input.action === 'revoke') {
        const result = await env.DB.prepare(
          `UPDATE device SET state='revoked',revision=revision+1
          WHERE id=?1 AND owner=?2 AND state='active' AND revision=?3
            AND EXISTS (SELECT 1 FROM session s WHERE s.id=?4 AND s.owner=?2
              AND s.active=1 AND s.expires_at>?5) RETURNING revision`,
        )
          .bind(input.id, input.owner, input.revision, input.session, input.now)
          .all();
        return Response.json({ revoked: result.results });
      }
      return new Response(null, { status: 400 });
    } catch {
      return Response.json({ error: 'transaction_failed' }, { status: 409 });
    }
  },
};
