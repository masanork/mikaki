import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { boundedGitPack } from './work-git-readback.ts';
import { gitFixture } from './work-git-fixture.ts';
import { localGit } from './work-git-disclosure.ts';
function seal(bytes: Buffer) {
  return Buffer.concat([bytes, createHash('sha1').update(bytes).digest()]);
}
function pack(entry: Buffer, count = 1) {
  const header = Buffer.alloc(12);
  header.write('PACK');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(count, 8);
  return seal(Buffer.concat([header, entry]));
}
test('pack preflight rejects invalid types, bounds, compression, counts, checksums and trailing bytes', () => {
  const valid = pack(Buffer.concat([Buffer.from([0x33]), deflateSync('abc')]));
  assert.equal(boundedGitPack(valid), 1);
  const bad = Buffer.from(valid);
  bad[bad.length - 1] ^= 1;
  const cases = [
    bad,
    pack(Buffer.from([0])),
    pack(Buffer.from([0x33, 0, 0])),
    pack(Buffer.concat([Buffer.from([0x32]), deflateSync('abc')])),
    pack(Buffer.concat([Buffer.from([0x31]), deflateSync(Buffer.alloc(1024 * 1024))])),
    pack(Buffer.from([0xb0, 0xff, 0xff, 0xff, 0x7f])),
    pack(Buffer.concat([Buffer.from([0x33]), deflateSync('abc')]), 65537),
    pack(Buffer.concat([Buffer.from([0x33]), deflateSync('abc')]), 2),
    seal(Buffer.concat([valid.subarray(0, -20), Buffer.from([0])])),
    pack(Buffer.from([0x60, 0])),
    pack(
      Buffer.concat([
        Buffer.from([0x74]),
        Buffer.alloc(20),
        deflateSync(Buffer.from([0xff, 0xff, 0xff, 0xff, 0x7f])),
      ]),
    ),
  ];
  for (const candidate of cases) assert.throws(() => boundedGitPack(candidate));
});
for (const offset of [false, true])
  test(`${offset ? 'OFS' : 'REF'} delta packs pass preflight and real Git strict indexing`, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'mikaki-git-pack-'));
    try {
      const shared = 'Synthetic repeated context line\n'.repeat(1000);
      const source = await gitFixture(
        dir,
        'source',
        { 'README.md': shared + 'current\n' },
        shared + 'previous\n',
      );
      const bytes = localGit(
        source.dir,
        [
          'pack-objects',
          '--stdout',
          '--revs',
          '--window=10',
          '--depth=10',
          ...(offset ? ['--delta-base-offset'] : []),
        ],
        `${source.commit}\n`,
      );
      assert.equal(boundedGitPack(bytes), 6);
      const target = join(dir, 'readback');
      localGit(target, ['init', '--bare', '--quiet', '--template=']);
      const indexed = localGit(target, ['index-pack', '--strict', '--stdin'], bytes)
        .toString()
        .trim()
        .split(/\s+/)
        .at(-1)!;
      assert.match(
        localGit(target, [
          'verify-pack',
          '-v',
          join(target, 'objects/pack', `pack-${indexed}.idx`),
        ]).toString(),
        /[a-f0-9]{40} blob\s+\d+ \d+ \d+ \d+ [a-f0-9]{40}/,
      );
      localGit(target, ['update-ref', 'refs/heads/work', source.commit]);
      localGit(target, ['fsck', '--full', '--strict', '--no-reflogs']);
      assert.equal(
        localGit(target, ['rev-parse', `${source.commit}^{tree}`])
          .toString()
          .trim(),
        source.tree,
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
