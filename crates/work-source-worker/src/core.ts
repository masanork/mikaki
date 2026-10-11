/** Data reader only: the OP authorizes source access before and after this call. */
import { z } from 'zod';
z.config({ jitless: true });
const oid = z.string().regex(/^[a-f0-9]{40}$/),
  digest = z.string().regex(/^[a-f0-9]{64}$/);
const path = z
  .string()
  .min(1)
  .refine(
    (p) =>
      new TextEncoder().encode(p).length <= 256 &&
      !/[\u0000-\u001f\u007f\\]/.test(p) &&
      p
        .split('/')
        .every((x) => x && x !== '.' && x !== '..' && !x.toLowerCase().startsWith('.git')),
  );
const file = z.strictObject({
  path,
  blob: oid,
  mode: z.enum(['100644', '100755']),
  bytes: z.number().int().min(0).max(16384),
  sha256: digest,
});
export const registeredReadSchema = z
  .strictObject({
    format_version: z.literal(1),
    source_id: z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
    source_revision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
    repo_name: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/),
    commit: oid,
    tree: oid,
    files: z.array(file).min(1).max(32),
  })
  .superRefine((v, c) => {
    if (
      v.files.reduce((n, f) => n + f.bytes, 0) > 131072 ||
      !v.files.every((f, i) => i === 0 || comparePaths(v.files[i - 1]!.path, f.path) < 0)
    )
      c.addIssue({ code: 'custom', message: 'invalid selection' });
  });
function comparePaths(a: string, b: string): number {
  const aa = new TextEncoder().encode(a),
    bb = new TextEncoder().encode(b);
  for (let i = 0; i < Math.min(aa.length, bb.length); i++) {
    if (aa[i] !== bb[i]) return aa[i]! - bb[i]!;
  }
  return aa.length - bb.length;
}
// Narrow injectable data capability, rather than an Env definition or token API.
export interface ReadableArtifacts {
  get(name: string): Promise<{
    readCommit(hash: string): Promise<{ hash: string; treeHash: string } | null>;
    readBlob(hash: string): Promise<Blob | null>;
    readFile(args: { ref: string; path: string }): Promise<Blob | null>;
    [Symbol.dispose](): void;
  }>;
}
const hex = (b: ArrayBuffer) =>
  Array.from(new Uint8Array(b), (v) => v.toString(16).padStart(2, '0')).join('');
export async function readRegisteredSource(
  artifacts: ReadableArtifacts,
  input: string,
): Promise<string> {
  if (new TextEncoder().encode(input).length > 32768) throw new Error('source_unavailable');
  const i = registeredReadSchema.parse(JSON.parse(input));
  using repo = await artifacts.get(i.repo_name);
  const commit = await repo.readCommit(i.commit);
  if (commit?.hash !== i.commit || commit.treeHash !== i.tree)
    throw new Error('source_unavailable');
  const files = [];
  for (const f of i.files) {
    const blob = await repo.readBlob(f.blob);
    if (!blob || blob.size !== f.bytes || blob.size > 16384) throw new Error('source_unavailable');
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const prefix = new TextEncoder().encode(`blob ${bytes.length}\0`),
      git = new Uint8Array(prefix.length + bytes.length);
    git.set(prefix);
    git.set(bytes, prefix.length);
    if (
      hex(await crypto.subtle.digest('SHA-1', git)) !== f.blob ||
      hex(await crypto.subtle.digest('SHA-256', bytes)) !== f.sha256
    )
      throw new Error('source_unavailable');
    // A valid blob need not belong to this commit or selected path.
    const selected = await repo.readFile({ ref: i.commit, path: f.path });
    if (!selected || selected.size !== f.bytes || selected.size > 16384)
      throw new Error('source_unavailable');
    if (hex(await crypto.subtle.digest('SHA-256', await selected.arrayBuffer())) !== f.sha256)
      throw new Error('source_unavailable');
    const content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    if (
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(content) ||
      content.startsWith('version https://git-lfs.github.com/spec/v1\n')
    )
      throw new Error('source_unavailable');
    files.push({ path: f.path, blob: f.blob, content });
  }
  return JSON.stringify({
    format_version: 1,
    source_id: i.source_id,
    source_revision: i.source_revision,
    commit: i.commit,
    tree: i.tree,
    files,
  });
}
