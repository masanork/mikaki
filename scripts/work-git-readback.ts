/** Validate pack bounds before Git inflation; Git verifies deltas and hashes. */
import { createHash } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { localGit } from './work-git-disclosure.ts';
import { packets, packet } from './work-git-upload.ts';
import type { GitHttp } from './work-git-upload.ts';
import type { GitPlan } from '../crates/work-effect-worker/protocol.ts';
function inflateEntry(bytes: Buffer, size: number) {
  // The installed Node declarations type convenience functions as Buffer even
  // with info:true. Validate the documented runtime result without a cast.
  const value: unknown = inflateSync(bytes, { maxOutputLength: Math.max(size, 1), info: true });
  if (
    !value ||
    typeof value !== 'object' ||
    !('buffer' in value) ||
    !Buffer.isBuffer(value.buffer) ||
    !('engine' in value) ||
    !value.engine ||
    typeof value.engine !== 'object' ||
    !('bytesWritten' in value.engine) ||
    typeof value.engine.bytesWritten !== 'number' ||
    !Number.isSafeInteger(value.engine.bytesWritten) ||
    value.engine.bytesWritten < 1
  )
    throw new Error('git_pack_invalid');
  return { buffer: value.buffer, consumed: value.engine.bytesWritten };
}
export function boundedGitPack(pack: Buffer) {
  if (
    pack.length < 32 ||
    pack.length > 70 * 1024 * 1024 ||
    pack.subarray(0, 4).toString() !== 'PACK' ||
    ![2, 3].includes(pack.readUInt32BE(4)) ||
    !createHash('sha1').update(pack.subarray(0, -20)).digest().equals(pack.subarray(-20))
  )
    throw new Error('git_pack_invalid');
  const count = pack.readUInt32BE(8);
  if (count < 1 || count > 65536) throw new Error('git_pack_capacity');
  let offset = 12,
    decoded = 0,
    restored = 0;
  function byte() {
    if (offset >= pack.length - 20) throw new Error('git_pack_invalid');
    return pack[offset++]!;
  }
  for (let i = 0; i < count; i++) {
    const start = offset;
    let c = byte(),
      type = (c >> 4) & 7,
      size = c & 15,
      multiplier = 16,
      n = 0;
    while (c & 128) {
      c = byte();
      size += (c & 127) * multiplier;
      multiplier *= 128;
      if (++n > 7 || !Number.isSafeInteger(size) || size > 67108864)
        throw new Error('git_pack_capacity');
    }
    if (![1, 2, 3, 4, 6, 7].includes(type) || decoded + size > 67108864)
      throw new Error('git_pack_capacity');
    decoded += size;
    if (type === 6) {
      c = byte();
      let distance = c & 127;
      while (c & 128) {
        c = byte();
        distance = (distance + 1) * 128 + (c & 127);
        if (!Number.isSafeInteger(distance) || distance > start - 12)
          throw new Error('git_pack_invalid');
      }
      if (distance < 1 || distance > start - 12) throw new Error('git_pack_invalid');
    }
    if (type === 7) {
      offset += 20;
      if (offset >= pack.length - 20) throw new Error('git_pack_invalid');
    }
    const inflated = inflateEntry(pack.subarray(offset, -20), size);
    if (inflated.buffer.length !== size) throw new Error('git_pack_invalid');
    offset += inflated.consumed;
    let target = size;
    if (type === 6 || type === 7) {
      let pos = 0;
      const number = () => {
        let value = 0,
          mult = 1,
          c = 0,
          n = 0;
        do {
          if (pos >= inflated.buffer.length) throw new Error('git_pack_invalid');
          c = inflated.buffer[pos++]!;
          value += (c & 127) * mult;
          mult *= 128;
          if (++n > 7 || value > 67108864) throw new Error('git_pack_capacity');
        } while (c & 128);
        return value;
      };
      number();
      target = number();
    }
    restored += target;
    if (restored > 67108864) throw new Error('git_pack_capacity');
  }
  if (offset !== pack.length - 20) throw new Error('git_pack_invalid');
  return count;
}
async function refs(p: GitPlan, token: string, http: GitHttp) {
  const ad = packets(await http(p, token, 'info/refs?service=git-upload-pack'));
  if (ad[0] !== '# service=git-upload-pack\n' || ad[1] !== null || ad.at(-1) !== null)
    throw new Error('git_readback_mismatch');
  const rows = ad.slice(2, -1).map((line) => {
    if (typeof line !== 'string') throw new Error('git_readback_mismatch');
    const match = /^([a-f0-9]{40}) (HEAD|refs\/[^\x00-\x20]+)(?:\0[^\n]*)?\n?$/.exec(line);
    if (!match || match[1] !== p.commit) throw new Error('git_readback_mismatch');
    return match[2];
  });
  if (
    rows.filter((r) => r !== 'HEAD').join('\n') !== `refs/heads/${p.branch}` ||
    rows.filter((r) => r === 'HEAD').length > 1
  )
    throw new Error('git_readback_mismatch');
}
export async function readbackGitPack(p: GitPlan, token: string, dir: string, http: GitHttp) {
  await refs(p, token, http);
  const response = await http(
    p,
    token,
    'git-upload-pack',
    Buffer.concat([packet(`want ${p.commit}\n`), Buffer.from('0000'), packet('done\n')]),
  );
  const nak = packet('NAK\n');
  if (!response.subarray(0, nak.length).equals(nak)) throw new Error('git_readback_mismatch');
  const pack = response.subarray(nak.length),
    objects = boundedGitPack(pack);
  localGit(dir, ['index-pack', '--strict', '--stdin'], pack, {}, 1024 * 1024);
  localGit(dir, ['update-ref', `refs/heads/${p.branch}`, p.commit]);
  await refs(p, token, http);
  return objects;
}
