/** Fixed productive Git metadata. No credentials, provider handles or grants. */
import { closed, hex, integer, mintPlan, mintObservation } from './protocol.ts';
import type { Checkpoint, MintPlan, MintObservation } from './protocol.ts';
export const MAX_GIT_BYTES = 8 * 1024 * 1024;
export type CopyManifest = {
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
};
export type GitPlan = {
  format_version: 1;
  effect: 'git.copy';
  mint: MintPlan;
  observation: MintObservation;
  manifest: CopyManifest;
  checkpoint: Checkpoint;
  digest: string;
  request_sha256: string;
};
export type GitRecord = { plan: GitPlan; consumed: boolean };
export function copyManifest(v: unknown): asserts v is CopyManifest {
  if (
    !closed(v, [
      'format_version',
      'role',
      'ref',
      'commit',
      'tree',
      'objects',
      'object_bytes',
      'inventory_sha256',
      'pack_bytes',
      'pack_sha256',
      'request_sha256',
    ]) ||
    v.format_version !== 1 ||
    !['task', 'snapshot'].includes(String(v.role)) ||
    v.ref !== (v.role === 'task' ? 'refs/heads/work' : 'refs/heads/snapshot') ||
    typeof v.commit !== 'string' ||
    !/^[a-f0-9]{40}$/.test(v.commit) ||
    typeof v.tree !== 'string' ||
    !/^[a-f0-9]{40}$/.test(v.tree) ||
    !integer(v.objects) ||
    v.objects < 1 ||
    v.objects > 65536 ||
    !integer(v.object_bytes) ||
    v.object_bytes > 67108864 ||
    !integer(v.pack_bytes) ||
    v.pack_bytes < 32 ||
    v.pack_bytes > MAX_GIT_BYTES - 256 ||
    !hex(v.inventory_sha256) ||
    !hex(v.pack_sha256) ||
    !hex(v.request_sha256)
  )
    throw new Error('git_invalid');
}
export function gitPlan(v: unknown): asserts v is GitPlan {
  if (
    !closed(v, [
      'format_version',
      'effect',
      'mint',
      'observation',
      'manifest',
      'checkpoint',
      'digest',
      'request_sha256',
    ]) ||
    v.format_version !== 1 ||
    v.effect !== 'git.copy' ||
    !hex(v.digest) ||
    !hex(v.request_sha256)
  )
    throw new Error('git_invalid');
  if (
    !closed(v.checkpoint, ['authority', 'epoch', 'sequence', 'tip']) ||
    !hex(v.checkpoint.epoch) ||
    !hex(v.checkpoint.tip) ||
    !integer(v.checkpoint.sequence)
  )
    throw new Error('git_invalid');
  mintPlan(v.mint);
  if (v.checkpoint.authority !== v.mint.checkpoint.authority) throw new Error('git_invalid');
  mintObservation(v.observation);
  copyManifest(v.manifest);
  if (
    v.manifest.role !== v.mint.role ||
    v.observation.repo_id !== v.mint.repo_id ||
    v.observation.scope !== v.mint.scope ||
    v.observation.expires_at > v.mint.expires_at
  )
    throw new Error('git_invalid');
}
const encoder = new TextEncoder();
export const packet = (s: string) =>
  (encoder.encode(s).length + 4).toString(16).padStart(4, '0') + s;
export const uploadPrefix = (m: CopyManifest) =>
  encoder.encode(packet(`${'0'.repeat(40)} ${m.commit} ${m.ref}\0report-status\n`) + '0000');
export const readbackBody = (m: CopyManifest) =>
  encoder.encode(packet(`want ${m.commit}\n`) + '0000' + packet('done\n'));
export async function sha256(bytes: Uint8Array) {
  return Array.from(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes))),
    (b) => b.toString(16).padStart(2, '0'),
  ).join('');
}
export async function boundedBody(response: Request | Response, max = MAX_GIT_BYTES) {
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader(),
    chunks: Uint8Array[] = [];
  let n = 0;
  try {
    for (;;) {
      const r = await reader.read();
      if (r.done) break;
      n += r.value.length;
      if (n > max) throw new Error('git_capacity');
      chunks.push(r.value);
    }
  } catch {
    await reader.cancel().catch(() => {});
    throw new Error('git_capacity');
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(n);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes;
}
export async function fixedBody(p: GitPlan, body: Uint8Array) {
  const prefix = p.mint.purpose === 'upload' ? uploadPrefix(p.manifest) : readbackBody(p.manifest);
  if ((await sha256(body)) !== p.request_sha256 || !prefix.every((b, i) => body[i] === b))
    throw new Error('git_payload_mismatch');
  if (p.mint.purpose === 'readback') {
    if (body.length !== prefix.length) throw new Error('git_payload_mismatch');
    return;
  }
  const pack = body.subarray(prefix.length);
  if (
    pack.length !== p.manifest.pack_bytes ||
    (await sha256(pack)) !== p.manifest.pack_sha256 ||
    new TextDecoder().decode(pack.subarray(0, 4)) !== 'PACK' ||
    new DataView(pack.buffer, pack.byteOffset, 12).getUint32(4) !== 2 ||
    new DataView(pack.buffer, pack.byteOffset, 12).getUint32(8) !== p.manifest.objects
  )
    throw new Error('git_payload_mismatch');
  const trailer = new Uint8Array(
    await crypto.subtle.digest('SHA-1', new Uint8Array(pack.subarray(0, -20))),
  );
  if (!trailer.every((b, i) => pack[pack.length - 20 + i] === b))
    throw new Error('git_payload_mismatch');
}
/** Exact smart HTTP v1 advertisement, including complete visible refs. */
export function advertisement(bytes: Uint8Array, p: GitPlan) {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let offset = 0;
  const next = () => {
    const h = text.slice(offset, offset + 4);
    if (!/^[0-9a-f]{4}$/.test(h)) throw new Error('git_advertisement');
    const n = parseInt(h, 16);
    offset += 4;
    if (n === 0) return null;
    if (n < 5 || offset + n - 4 > text.length) throw new Error('git_advertisement');
    const s = text.slice(offset, offset + n - 4);
    offset += n - 4;
    return s;
  };
  const service = p.mint.purpose === 'upload' ? 'git-receive-pack' : 'git-upload-pack';
  if (next() !== `# service=${service}\n` || next() !== null) throw new Error('git_advertisement');
  const refs = new Map<string, string>();
  let caps: string[] = [];
  for (let i = 0; ; i++) {
    const line = next();
    if (line === null) break;
    if (i > 512) throw new Error('git_advertisement');
    const match = /^([a-f0-9]{40}) ([^\x00\s]+)(?:\x00([^\n]*))?\n$/.exec(line);
    if (!match || (i !== 0 && match[3] !== undefined) || refs.has(match[2]!))
      throw new Error('git_advertisement');
    if (i === 0) {
      if (match[3] === undefined) throw new Error('git_advertisement');
      caps = match[3].split(' ');
    }
    refs.set(match[2]!, match[1]!);
  }
  if (
    offset !== text.length ||
    caps.some((c) => c.startsWith('object-format=') && c !== 'object-format=sha1')
  )
    throw new Error('git_advertisement');
  if (p.mint.purpose === 'upload') {
    if (
      refs.size !== 1 ||
      refs.get('capabilities^{}') !== '0'.repeat(40) ||
      !caps.includes('report-status')
    )
      throw new Error('git_destination_not_empty');
  } else {
    if (refs.get('HEAD') === p.manifest.commit && caps.includes(`symref=HEAD:${p.manifest.ref}`))
      refs.delete('HEAD');
    if (refs.size !== 1 || refs.get(p.manifest.ref) !== p.manifest.commit)
      throw new Error('git_refs_mismatch');
  }
}
export async function responsePayload(bytes: Uint8Array, p: GitPlan) {
  if (p.mint.purpose === 'upload') {
    const expected = encoder.encode(
      packet('unpack ok\n') + packet(`ok ${p.manifest.ref}\n`) + '0000',
    );
    if (bytes.length !== expected.length || !expected.every((b, i) => bytes[i] === b))
      throw new Error('git_ack_unknown');
    return expected;
  }
  const nak = encoder.encode(packet('NAK\n'));
  if (!nak.every((b, i) => bytes[i] === b)) throw new Error('git_pack_unknown');
  const pack = bytes.subarray(nak.length);
  if (
    pack.length < 32 ||
    new TextDecoder().decode(pack.subarray(0, 4)) !== 'PACK' ||
    new DataView(pack.buffer, pack.byteOffset, 12).getUint32(4) !== 2 ||
    new DataView(pack.buffer, pack.byteOffset, 12).getUint32(8) !== p.manifest.objects
  )
    throw new Error('git_pack_unknown');
  const trailer = new Uint8Array(
    await crypto.subtle.digest('SHA-1', new Uint8Array(pack.subarray(0, -20))),
  );
  if (!trailer.every((b, i) => pack[pack.length - 20 + i] === b))
    throw new Error('git_pack_unknown');
  return pack;
}

/** JSON member order cannot change an immutable metadata association. */
export function sameMetadata(a: unknown, b: unknown): boolean {
  const canonical = (v: unknown): string => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? '';
    if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
    const r = v as Record<string, unknown>;
    return (
      '{' +
      Object.keys(r)
        .sort()
        .map((k) => JSON.stringify(k) + ':' + canonical(r[k]))
        .join(',') +
      '}'
    );
  };
  return canonical(a) === canonical(b);
}
