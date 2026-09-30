// Optional Node operation adapter. The product does not enable MDS implicitly.
import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';

export type Profile = 'mds3.1.1' | 'mds3.0';
export type Input = {
  profile: Profile;
  jwt: string;
  anchor_spki: string;
  now: number;
  crls: string[];
};
export type Verified = {
  number: number;
  issued_at: number | null;
  next_update: number | null;
  profile: Profile;
  entries: unknown[];
};
export type Config = {
  url: string;
  profile: Profile;
  anchor_spki: string;
  allowed_hosts: string[];
  max_age_seconds: number;
};
export type Verifier = {
  verify(input: Input): Verified;
  crlUrls(jwt: string, profile: Profile): string[];
};
type Snapshot = { input: Input; verified: Verified; first_seen: number; validated_at: number };
const hash = (s: string) => createHash('sha256').update(s).digest('hex');
const integer = (n: number) => Number.isSafeInteger(n) && n >= 0;
function destination(value: string, hosts: string[]) {
  const u = new URL(value);
  if (
    u.protocol !== 'https:' ||
    u.username ||
    u.password ||
    u.hash ||
    (u.port && u.port !== '443') ||
    !hosts.includes(u.hostname)
  )
    throw Error('mds_destination');
  return u;
}
export async function download(
  url: string,
  hosts: string[],
  limit: number,
  fetcher = fetch,
): Promise<Buffer> {
  // One deadline includes redirects and streaming, rather than only HTTP headers.
  const signal = AbortSignal.timeout(20000);
  for (let redirect = 0; redirect <= 3; redirect++) {
    const u = destination(url, hosts);
    const r = await fetcher(u, { redirect: 'manual', signal });
    if ([301, 302, 303, 307, 308].includes(r.status)) {
      const location = r.headers.get('location');
      await r.body?.cancel();
      if (!location) throw Error('mds_redirect');
      url = new URL(location, u).href;
      continue;
    }
    if (!r.ok || !r.body) {
      await r.body?.cancel();
      throw Error(`mds_http_${r.status}`);
    }
    const reader = r.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        signal.throwIfAborted();
        const { value, done } = await reader.read();
        if (done) return Buffer.concat(chunks);
        size += value.byteLength;
        if (size > limit) throw Error('mds_size');
        chunks.push(value);
      }
    } catch (error) {
      await reader.cancel();
      throw error;
    }
  }
  throw Error('mds_redirect_limit');
}

export class MdsStore {
  private db: DatabaseSync;
  private config: Config;
  private verifier: Verifier;
  constructor(path: string, config: Config, verifier: Verifier) {
    if (
      !['mds3.0', 'mds3.1.1'].includes(config.profile) ||
      !integer(config.max_age_seconds) ||
      config.max_age_seconds < 3600 ||
      config.max_age_seconds > 31 * 86400 ||
      !config.anchor_spki ||
      config.anchor_spki.length > 4096 ||
      !config.allowed_hosts.length ||
      config.allowed_hosts.length > 32
    )
      throw Error('mds_config');
    destination(config.url, config.allowed_hosts);
    this.config = structuredClone(config);
    this.verifier = verifier;
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS mds_state(id INTEGER PRIMARY KEY CHECK(id=1), channel TEXT NOT NULL,
      snapshot TEXT, last_attempt INTEGER, failure TEXT);
      INSERT OR IGNORE INTO mds_state(id,channel) VALUES(1,'');`);
    const channel = hash(
      JSON.stringify({
        url: config.url,
        profile: config.profile,
        anchor: config.anchor_spki,
        hosts: [...config.allowed_hosts].sort(),
        max_age: config.max_age_seconds,
      }),
    );
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const old = this.db.prepare('SELECT channel FROM mds_state WHERE id=1').get()!;
      if (old.channel && old.channel !== channel) throw Error('mds_channel_changed');
      this.db.prepare('UPDATE mds_state SET channel=? WHERE id=1').run(channel);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      this.db.close();
      throw error;
    }
  }
  close() {
    this.db.close();
  }
  private saved(): Snapshot | undefined {
    const row = this.db.prepare('SELECT snapshot FROM mds_state WHERE id=1').get()!;
    return row.snapshot ? JSON.parse(String(row.snapshot)) : undefined;
  }
  private validate(input: Input, firstSeen: number): Verified {
    if (
      !integer(input.now) ||
      input.profile !== this.config.profile ||
      input.anchor_spki !== this.config.anchor_spki
    )
      throw Error('mds_input');
    const v = this.verifier.verify(input);
    if (
      !integer(v.number) ||
      v.profile !== this.config.profile ||
      !Array.isArray(v.entries) ||
      v.entries.length > 10000 ||
      (v.issued_at !== null && !integer(v.issued_at))
    )
      throw Error('mds_verified');
    const issued = v.issued_at ?? firstSeen;
    if (
      (this.config.profile === 'mds3.1.1' && v.issued_at === null) ||
      issued > input.now + 300 ||
      firstSeen > input.now + 300 ||
      input.now - issued > this.config.max_age_seconds ||
      input.now - firstSeen > this.config.max_age_seconds
    )
      throw Error('mds_stale');
    if (
      this.config.profile === 'mds3.0' &&
      (v.next_update === null || !integer(v.next_update) || input.now > v.next_update)
    )
      throw Error('mds_stale');
    return v;
  }
  accept(input: Input): Verified {
    // Validate before the transaction; repeat the serial comparison under the writer lock.
    const v = this.validate(input, input.now);
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const previous = this.saved();
      if (
        previous &&
        (v.number < previous.verified.number ||
          (v.number === previous.verified.number && hash(input.jwt) !== hash(previous.input.jwt)))
      )
        throw Error('mds_rollback');
      const first_seen = previous?.verified.number === v.number ? previous.first_seen : input.now;
      this.validate(input, first_seen);
      const snapshot: Snapshot = { input, verified: v, first_seen, validated_at: input.now };
      this.db
        .prepare('UPDATE mds_state SET snapshot=?,last_attempt=?,failure=NULL WHERE id=1')
        .run(JSON.stringify(snapshot), input.now);
      this.db.exec('COMMIT');
      return v;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }
  forRegistration(now = Math.floor(Date.now() / 1000)): Verified {
    const snapshot = this.saved();
    if (!snapshot) throw Error('mds_unavailable');
    // Includes CRL and certificate validity at usage time. Cache alone is insufficient.
    return this.validate({ ...snapshot.input, now }, snapshot.first_seen);
  }
  status(now = Math.floor(Date.now() / 1000)) {
    const snapshot = this.saved();
    const row = this.db.prepare('SELECT last_attempt,failure FROM mds_state WHERE id=1').get()!;
    let usable = false;
    try {
      this.forRegistration(now);
      usable = true;
    } catch {
      /* status only */
    }
    return {
      profile: this.config.profile,
      number: snapshot?.verified.number ?? null,
      issued_at: snapshot?.verified.issued_at ?? null,
      first_seen: snapshot?.first_seen ?? null,
      validated_at: snapshot?.validated_at ?? null,
      entries: snapshot?.verified.entries.length ?? 0,
      age_seconds: snapshot ? now - snapshot.first_seen : null,
      usable,
      last_attempt: row.last_attempt,
      failure: row.failure,
    };
  }
  async refresh(now = Math.floor(Date.now() / 1000), fetcher = fetch): Promise<Verified> {
    try {
      const jwt = (
        await download(this.config.url, this.config.allowed_hosts, 4194304, fetcher)
      ).toString('utf8');
      const urls = this.verifier.crlUrls(jwt, this.config.profile);
      if (!urls.length || urls.length > 12) throw Error('mds_crls');
      const crls: string[] = [];
      for (const url of [...new Set(urls)])
        crls.push(
          (await download(url, this.config.allowed_hosts, 1048576, fetcher)).toString('base64url'),
        );
      return this.accept({
        profile: this.config.profile,
        jwt,
        anchor_spki: this.config.anchor_spki,
        now,
        crls,
      });
    } catch (error) {
      // Do not log attacker-controlled URLs/JWTs or erase the last accepted state.
      const reason =
        error instanceof Error && /^mds_[a-z0-9_]+$/.test(error.message)
          ? error.message
          : 'mds_verification_or_transport';
      this.db.prepare('UPDATE mds_state SET last_attempt=?,failure=? WHERE id=1').run(now, reason);
      throw Error(reason);
    }
  }
}
