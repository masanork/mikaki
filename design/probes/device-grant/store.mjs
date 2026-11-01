// Host SQLite concurrency probe. Not a D1 migration or production endpoint.
export const SCHEMA = `
CREATE TABLE device_grant_probe (
  code_digest TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  key_thumbprint TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','approved','denied','redeemed')),
  owner TEXT,
  CHECK ((state IN ('approved','redeemed') AND owner IS NOT NULL)
      OR (state IN ('pending','denied') AND owner IS NULL))
) STRICT;`;

// A caller must validate the proof cryptographically and derive its thumbprint
// before calling. `codeDigest` must be computed from a high-entropy secret.
// One SQLite statement is the entire compare-and-consume transaction.
export function redeem(db, codeDigest, client, verifiedKey, now) {
  return db.prepare(`UPDATE device_grant_probe SET state = 'redeemed'
    WHERE code_digest = ? AND client_id = ? AND key_thumbprint = ?
      AND expires_at > ? AND state = 'approved'
    RETURNING owner`).get(codeDigest, client, verifiedKey, now) ?? null;
}
