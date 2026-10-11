/** Trusted local Git copy core. No network, tokens, authority ledger or grants. */
import { createHash } from 'node:crypto';
import { inspectGitSource, localGit } from './work-git-disclosure.ts';
import { objectInventory, verifyGitReadback } from './work-artifacts-git.ts';

const MAX_PACK_BYTES = 64 * 1024 * 1024;
const oid = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{40}$/.test(v);
const hash = (v: Buffer | string) => createHash('sha256').update(v).digest('hex');
const packet = (v: string) => {
  const bytes = Buffer.from(v);
  return Buffer.concat([Buffer.from((bytes.length + 4).toString(16).padStart(4, '0')), bytes]);
};
export type CopySource = { gitDir: string; commit: string; tree: string };
export type CopyManifest = Readonly<{
  format_version: 1;
  role: 'task' | 'snapshot';
  ref: 'refs/heads/work' | 'refs/heads/snapshot';
  commit: string;
  tree: string;
  objects: number;
  object_bytes: number;
  inventory_sha256: string;
  pack_bytes: number;
  pack_sha256: string;
  request_sha256: string;
}>;

/** Fixed create-only ref update plus the complete selected object graph.
 * The caller must separately admit a remote operation before sending the bytes.
 */
export class PreparedGitCopy {
  readonly manifest: CopyManifest;
  #source: CopySource;
  #body: Buffer;
  #inventory: string[];
  private constructor(
    source: CopySource,
    manifest: CopyManifest,
    body: Buffer,
    inventory: string[],
  ) {
    this.#source = { ...source };
    this.manifest = Object.freeze(manifest);
    this.#body = body;
    this.#inventory = inventory;
    Object.freeze(this);
  }
  static async prepare(source: CopySource, role: 'task' | 'snapshot') {
    if (
      !source ||
      Object.keys(source).sort().join(',') !== 'commit,gitDir,tree' ||
      typeof source.gitDir !== 'string' ||
      !oid(source.commit) ||
      !oid(source.tree) ||
      !['task', 'snapshot'].includes(role)
    )
      throw new Error('copy_invalid');
    source = { ...source };
    const inspected = await inspectGitSource({
      repository: 'copy',
      gitDir: source.gitDir,
      commit: source.commit,
    });
    source.gitDir = inspected.dir;
    if (inspected.tree !== source.tree) throw new Error('copy_source_mismatch');
    const expected = objectInventory(source.gitDir, source.commit);
    if (
      role === 'snapshot' &&
      /^parent /m.test(localGit(source.gitDir, ['cat-file', 'commit', source.commit]).toString())
    )
      throw new Error('copy_snapshot_history');
    // Explicit independently hashed objects, no --all/revision expansion,
    // automatic tags, thin pack, borrowed delta bases or unrelated branch data.
    const pack = localGit(
      source.gitDir,
      ['pack-objects', '--stdout', '--no-reuse-object', '--window=0', '--threads=1'],
      expected.objects.join('\n') + '\n',
      {},
      MAX_PACK_BYTES,
    );
    if (
      pack.length < 32 ||
      pack.length > MAX_PACK_BYTES ||
      pack.subarray(0, 4).toString() !== 'PACK' ||
      pack.readUInt32BE(4) !== 2 ||
      pack.readUInt32BE(8) !== expected.objects.length ||
      !createHash('sha1').update(pack.subarray(0, -20)).digest().equals(pack.subarray(-20))
    )
      throw new Error('copy_pack_invalid');
    const ref = role === 'task' ? 'refs/heads/work' : 'refs/heads/snapshot';
    const body = Buffer.concat([
      packet(`${'0'.repeat(40)} ${source.commit} ${ref}\0report-status\n`),
      Buffer.from('0000'),
      pack,
    ]);
    return new PreparedGitCopy(
      source,
      {
        format_version: 1,
        role,
        ref,
        commit: source.commit,
        tree: source.tree,
        objects: expected.objects.length,
        object_bytes: expected.bytes,
        inventory_sha256: expected.sha256,
        pack_bytes: pack.length,
        pack_sha256: hash(pack),
        request_sha256: hash(body),
      },
      body,
      expected.inventory,
    );
  }
  /** A fresh byte copy prevents later caller mutation of the committed payload. */
  uploadBody() {
    return Buffer.from(this.#body);
  }
  /** Strict protocol-v1 report-status only. HTTP success alone is insufficient.
   * Even a valid acknowledgement is not readback, Native verification or release.
   */
  acknowledge(response: Uint8Array) {
    const body = Buffer.from(response);
    if (body.length > 65536) throw new Error('copy_ack_unknown');
    const lines: Buffer[] = [];
    let offset = 0,
      flushed = false;
    while (offset + 4 <= body.length) {
      const header = body.subarray(offset, offset + 4).toString('ascii');
      if (!/^[0-9a-f]{4}$/.test(header)) throw new Error('copy_ack_unknown');
      const length = Number.parseInt(header, 16);
      offset += 4;
      if (length === 0) {
        flushed = true;
        break;
      }
      if (length < 5 || length > 65520 || offset + length - 4 > body.length || lines.length >= 2)
        throw new Error('copy_ack_unknown');
      lines.push(body.subarray(offset, offset + length - 4));
      offset += length - 4;
    }
    if (
      !flushed ||
      offset !== body.length ||
      lines.length !== 2 ||
      !lines[0]!.equals(Buffer.from('unpack ok\n')) ||
      !lines[1]!.equals(Buffer.from(`ok ${this.manifest.ref}\n`))
    )
      throw new Error('copy_ack_unknown');
    return { stage: 'uploaded_unverified' as const, request_sha256: this.manifest.request_sha256 };
  }
  /** Independently fetched, fresh bare repository supplied by the transport.
   * Compare every physical object too, including unsolicited unreachable data.
   */
  async verifyReadback(gitDir: string) {
    const inspected = await inspectGitSource({
      repository: 'readback',
      gitDir,
      commit: this.manifest.commit,
    });
    gitDir = inspected.dir;
    const facts = verifyGitReadback(
      gitDir,
      this.#source.gitDir,
      this.manifest.commit,
      this.manifest.tree,
      this.manifest.role === 'task' ? 'work' : 'snapshot',
    );
    const physical = localGit(gitDir, [
      'cat-file',
      '--batch-all-objects',
      '--batch-check=%(objectname) %(objecttype) %(objectsize)',
    ])
      .toString()
      .trim()
      .split('\n')
      .sort();
    if (
      physical.join('\n') !== this.#inventory.join('\n') ||
      facts.inventory_sha256 !== this.manifest.inventory_sha256
    )
      throw new Error('copy_readback_extra_objects');
    const payload_receipt = hash(
      JSON.stringify(['mikaki-git-copy-readback-v1', this.manifest, facts]),
    );
    return { stage: 'readback_verified' as const, payload_receipt, ...facts };
  }
}
