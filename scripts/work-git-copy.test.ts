import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { PreparedGitCopy } from './work-git-copy.ts';
import { localGit, prepareGitDisclosure } from './work-git-disclosure.ts';
import { gitFixture } from './work-git-fixture.ts';

async function empty(parent: string) {
  const dir = await mkdtemp(join(parent, 'bare-'));
  localGit(dir, ['init', '--bare', '--quiet', '--template=']);
  return dir;
}
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-copy-'));
  const code = await gitFixture(
    directory,
    'code',
    { 'README.md': 'Current code\n' },
    'Required code history\n',
  );
  const context = await gitFixture(
    directory,
    'context',
    { 'keep.md': 'Selected context\n', 'omit.md': 'Unselected context\n' },
    'Never copied history\n',
  );
  const disclosure = await prepareGitDisclosure(
    { repository: 'code', gitDir: code.dir, commit: code.commit },
    [{ repository: 'context', gitDir: context.dir, commit: context.commit, paths: ['keep.md'] }],
    directory,
    'snapshot',
  );
  return {
    directory,
    code,
    context,
    disclosure,
    async close() {
      await rm(directory, { recursive: true, force: true });
    },
  };
}
function pkt(value: string) {
  const b = Buffer.from(value);
  return Buffer.concat([Buffer.from((b.length + 4).toString(16).padStart(4, '0')), b]);
}
async function readback(parent: string, remote: string) {
  const dir = await empty(parent);
  // Local qualification only: actual Git fetch into a fresh independent ODB.
  localGit(dir, [
    '-c',
    'protocol.file.allow=always',
    'fetch',
    '--quiet',
    '--no-tags',
    '--no-write-fetch-head',
    '--no-auto-maintenance',
    remote,
    '+refs/*:refs/*',
  ]);
  return dir;
}
for (const role of ['task', 'snapshot'] as const) {
  test(`${role}: actual Git receive-pack and independent fresh fetch preserve exactly the selected graph`, async () => {
    const f = await fixture();
    try {
      const selected = role === 'task' ? f.disclosure.input.code : f.disclosure.input.snapshot;
      const sourceDir = role === 'task' ? f.code.dir : f.disclosure.gitDir;
      const copy = await PreparedGitCopy.prepare(
        { gitDir: sourceDir, commit: selected.commit, tree: selected.tree },
        role,
      );
      const remote = await empty(f.directory);
      const ack = localGit(remote, ['receive-pack', '--stateless-rpc', remote], copy.uploadBody());
      assert.equal(copy.acknowledge(ack).stage, 'uploaded_unverified');
      const fetched = await readback(f.directory, remote);
      const facts = await copy.verifyReadback(fetched);
      assert.equal(facts.stage, 'readback_verified');
      assert.match(facts.payload_receipt, /^[a-f0-9]{64}$/);
      assert.equal(facts.commits, role === 'task' ? 2 : 1);
      assert.equal(facts.objects, copy.manifest.objects);
      if (role === 'task') {
        assert.equal(
          localGit(fetched, ['cat-file', 'blob', f.code.historicalBlob!]).toString(),
          'Required code history\n',
        );
      } else {
        for (const oid of [f.context.historicalBlob!, f.context.blobs.get('omit.md')!])
          assert.throws(() => localGit(fetched, ['cat-file', '-e', oid]));
      }
      assert.throws(() => Object.assign(copy.manifest, { ref: 'refs/heads/widened' }), TypeError);
      assert.throws(() => Object.assign(copy, { manifest: {} }), TypeError);
      const bytes = copy.uploadBody();
      bytes.fill(0);
      assert.notEqual(copy.uploadBody().subarray(0, 4).toString(), '\0\0\0\0');
    } finally {
      await f.close();
    }
  });
}
test('an unrelated source ref and unreachable blob are excluded from the code pack', async () => {
  const f = await fixture();
  try {
    const extra = localGit(
      f.code.dir,
      ['hash-object', '-w', '--stdin'],
      'Unrelated private content\n',
    )
      .toString()
      .trim();
    localGit(f.code.dir, ['update-ref', 'refs/tags/unrelated', extra]);
    const copy = await PreparedGitCopy.prepare(
      { gitDir: f.code.dir, commit: f.code.commit, tree: f.code.tree },
      'task',
    );
    const remote = await empty(f.directory);
    copy.acknowledge(
      localGit(remote, ['receive-pack', '--stateless-rpc', remote], copy.uploadBody()),
    );
    const facts = await copy.verifyReadback(remote);
    assert.equal(facts.refs.length, 1);
    assert.throws(() => localGit(remote, ['cat-file', '-e', extra]));
  } finally {
    await f.close();
  }
});
test('create-only ref command refuses an existing destination and cannot silently overwrite it', async () => {
  const f = await fixture();
  try {
    const remote = await empty(f.directory);
    const copy = await PreparedGitCopy.prepare(
      { gitDir: f.code.dir, commit: f.code.commit, tree: f.code.tree },
      'task',
    );
    copy.acknowledge(
      localGit(remote, ['receive-pack', '--stateless-rpc', remote], copy.uploadBody()),
    );
    assert.throws(
      () =>
        copy.acknowledge(
          localGit(remote, ['receive-pack', '--stateless-rpc', remote], copy.uploadBody()),
        ),
      /copy_ack_unknown/,
    );
    assert.equal(
      localGit(remote, ['rev-parse', 'refs/heads/work']).toString().trim(),
      f.code.commit,
    );
  } finally {
    await f.close();
  }
});
test('snapshot ancestry, mismatched tree and caller-selected branch are rejected before transfer', async () => {
  const f = await fixture();
  try {
    const source = { gitDir: f.code.dir, commit: f.code.commit, tree: f.code.tree };
    await assert.rejects(
      () => PreparedGitCopy.prepare(source, 'snapshot'),
      /copy_snapshot_history/,
    );
    await assert.rejects(
      () => PreparedGitCopy.prepare({ ...source, tree: 'a'.repeat(40) }, 'task'),
      /copy_source_mismatch/,
    );
    await assert.rejects(
      () => PreparedGitCopy.prepare({ ...source, branch: 'main' } as typeof source, 'task'),
      /copy_invalid/,
    );
    await assert.rejects(
      () => PreparedGitCopy.prepare({ ...source, commit: 'HEAD' }, 'task'),
      /copy_invalid/,
    );
  } finally {
    await f.close();
  }
});
for (const extra of ['ref', 'unreachable-object']) {
  test(`readback rejects unexpected ${extra} even when the selected branch matches`, async () => {
    const f = await fixture();
    try {
      const copy = await PreparedGitCopy.prepare(
        { gitDir: f.code.dir, commit: f.code.commit, tree: f.code.tree },
        'task',
      );
      const remote = await empty(f.directory);
      copy.acknowledge(
        localGit(remote, ['receive-pack', '--stateless-rpc', remote], copy.uploadBody()),
      );
      if (extra === 'ref') localGit(remote, ['update-ref', 'refs/heads/extra', f.code.commit]);
      else localGit(remote, ['hash-object', '-w', '--stdin'], 'Unexpected retained object\n');
      await assert.rejects(
        () => copy.verifyReadback(remote),
        /probe_readback_mismatch|copy_readback_extra_objects/,
      );
    } finally {
      await f.close();
    }
  });
}
for (const fault of [
  'empty',
  'truncated',
  'unpack-error',
  'wrong-ref',
  'extra-status',
  'trailing-bytes',
]) {
  test(`upload ${fault} response cannot become an acknowledgement`, async () => {
    const f = await fixture();
    try {
      const copy = await PreparedGitCopy.prepare(
        { gitDir: f.code.dir, commit: f.code.commit, tree: f.code.tree },
        'task',
      );
      let ack = Buffer.concat([
        pkt('unpack ok\n'),
        pkt('ok refs/heads/work\n'),
        Buffer.from('0000'),
      ]);
      if (fault === 'empty') ack = Buffer.alloc(0);
      if (fault === 'truncated') ack = ack.subarray(0, -1);
      if (fault === 'unpack-error')
        ack = Buffer.concat([
          pkt('unpack failed\n'),
          pkt('ok refs/heads/work\n'),
          Buffer.from('0000'),
        ]);
      if (fault === 'wrong-ref')
        ack = Buffer.concat([
          pkt('unpack ok\n'),
          pkt('ok refs/heads/other\n'),
          Buffer.from('0000'),
        ]);
      if (fault === 'extra-status')
        ack = Buffer.concat([
          pkt('unpack ok\n'),
          pkt('ok refs/heads/work\n'),
          pkt('ok refs/heads/other\n'),
          Buffer.from('0000'),
        ]);
      if (fault === 'trailing-bytes') ack = Buffer.concat([ack, Buffer.from('trailing')]);
      assert.throws(() => copy.acknowledge(ack), /copy_ack_unknown/);
    } finally {
      await f.close();
    }
  });
}

for (const restricted of ['shallow', 'grafts', 'alternates', 'promisor']) {
  test(`copy refuses ${restricted} source before exposing upload bytes`, async () => {
    const f = await fixture();
    try {
      const file =
        restricted === 'shallow'
          ? 'shallow'
          : restricted === 'grafts'
            ? 'info/grafts'
            : restricted === 'alternates'
              ? 'objects/info/alternates'
              : 'objects/pack/pack-synthetic.promisor';
      await mkdir(dirname(join(f.code.dir, file)), { recursive: true });
      await writeFile(
        join(f.code.dir, file),
        restricted === 'alternates' ? join(f.context.dir, 'objects') + '\n' : f.code.commit + '\n',
      );
      await assert.rejects(
        PreparedGitCopy.prepare(
          { gitDir: f.code.dir, commit: f.code.commit, tree: f.code.tree },
          'task',
        ),
        /unsupported_git_source/,
      );
    } finally {
      await f.close();
    }
  });
}
