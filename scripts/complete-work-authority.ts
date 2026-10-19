/** Fixed operator transport for the audited DLQ and the one unattempted Queue. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { constants } from 'node:fs';
import { mkdir, mkdtemp, open, realpath } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import {
  AUTHORITY_ACCOUNT,
  AUTHORITY_TARGET,
  digest,
  packetFile,
  packetJson,
} from './work-authority-packet.ts';
import {
  allocationRecordWriter,
  authorityAllocationReadAllowed,
  authorityResourceInventory,
} from './allocate-work-authority.ts';
import type { AllocationAPI } from './allocate-work-authority.ts';
import {
  inspectOriginalAuthorityAllocation,
  readOriginalAuthorityAllocation,
  readAuthorityAllocation,
  inspectAuthorityAllocation,
} from './work-authority-deployment.ts';
import {
  COMPLETION_DIRECTORY,
  DLQ_AUDIT_ID,
  DLQ_RECEIPT_SHA,
  ORIGINAL_RESERVATION_SHA,
  auditProofSchema,
  completionIdentity,
  completeAuthorityAllocation,
} from './work-authority-completion.ts';
import type { CompletionIdentity, CompletionIO } from './work-authority-completion.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const base = `/accounts/${AUTHORITY_ACCOUNT}`;
const queueSchema = z.object({
  queue_id: z.string().regex(/^[a-f0-9]{32}$/),
  queue_name: z.string().max(128),
  created_on: z
    .string()
    .max(40)
    .refine((s) => Number.isFinite(Date.parse(s))),
  consumers_total_count: z.number().int().nonnegative().optional(),
  producers_total_count: z.number().int().nonnegative().optional(),
  consumers: z.array(z.unknown()).max(128).nullable().optional(),
  producers: z.array(z.unknown()).max(128).nullable().optional(),
});
function selectedSource(requireClean: boolean) {
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  assert.match(commit, /^[a-f0-9]{40}$/);
  if (requireClean)
    assert.equal(
      execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim(),
      '',
      'completion_requires_clean_source',
    );
  return commit;
}
function matches(v: unknown, key: string, value: string, depth = 0): boolean {
  if (depth > 4) return false;
  if (typeof v === 'string' && v.length <= 16384) {
    try {
      return matches(JSON.parse(v), key, value, depth + 1);
    } catch {
      return false;
    }
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const object = v as Record<string, unknown>;
  return (
    object[key] === value ||
    ['result', 'body', 'data', 'payload'].some((k) => matches(object[k], key, value, depth + 1))
  );
}
async function boundedJSON(response: Response) {
  const reader = response.body?.getReader();
  assert.ok(reader, 'completion_body_absent');
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const r = await reader.read();
      if (r.done) break;
      size += r.value.length;
      assert.ok(size <= 256 * 1024, 'completion_body_too_large');
      chunks.push(r.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } finally {
    await reader.cancel();
  }
}
function apiSuccess(response: Awaited<ReturnType<AllocationAPI>>) {
  const e = z
    .object({
      success: z.boolean().optional(),
      errors: z.array(z.unknown()).max(16).nullable().optional(),
      result: z.unknown().optional(),
    })
    .parse(response.value);
  assert.ok(
    response.status >= 200 && response.status < 300 && e.success !== false && !e.errors?.length,
    'completion_api_refused',
  );
  return e.result;
}
async function preserved(retained: string) {
  const seal = await packetFile(
    join(retained, 'local/generated/work-authority-allocation/partial-allocation.json'),
  );
  assert.equal(
    digest(seal).sha256,
    '496e39a4d6abf9970890ae1a63ee00c0fa4aa3b1c040400bb6a2f0bbc702ea4f',
  );
  const parsed = z
    .object({
      original_journal: z.literal('local/generated/work-authority-allocation/allocate-kHIGYa'),
      members: z
        .array(
          z.object({
            path: z.string().regex(/^\d{4}\.json$/),
            bytes: z.number(),
            sha256: z.string(),
          }),
        )
        .length(236),
    })
    .parse(JSON.parse(seal.toString()));
  for (const member of parsed.members)
    assert.deepEqual(
      digest(await packetFile(join(retained, parsed.original_journal, member.path))),
      { bytes: member.bytes, sha256: member.sha256 },
    );
  for (const [directory, pin] of [
    ['probe-09Ae4P', 'e943c005794b4688a50c2f458e892245613cb1924354b951bb2654a6aaff2246'],
    ['probe-jYdl3a', '080a5860dbb81219d4f6f4da835353a1a9c8bcc67bcd69415c692f3edb261aaa'],
    ['probe-zgwc8e', '77933508c30a07cd3dd74259e68a70f887c56d329bfed814471aebca8ad34f48'],
  ])
    assert.equal(
      digest(
        await packetFile(
          join(retained, 'local/generated/work-artifacts-effect', directory!, 'journal.json'),
        ),
      ).sha256,
      pin,
    );
  const evidence = await readOriginalAuthorityAllocation(retained);
  assert.equal(digest(Buffer.from(evidence.reservation)).sha256, ORIGINAL_RESERVATION_SHA);
  return inspectOriginalAuthorityAllocation(evidence);
}
export async function runAuthorityCompletion(mode: 'inspect' | 'complete') {
  const source = selectedSource(mode === 'complete');
  const common = execFileSync('git', ['rev-parse', '--git-common-dir'], {
    cwd: root,
    encoding: 'utf8',
  }).trim();
  const retained = dirname(await realpath(resolve(root, common)));
  const receiptPath = join(
    retained,
    'local/generated/work-authority-allocation/recheck-wn8aMy/result.json',
  );
  const receiptBytes = await packetFile(receiptPath, 65536);
  assert.equal(digest(receiptBytes).sha256, DLQ_RECEIPT_SHA, 'completion_audit_review_changed');
  const reviewed = auditProofSchema.parse(JSON.parse(receiptBytes.toString()).creation_observation);
  const output = join(retained, 'local/generated/work-authority-completion');
  execFileSync('git', ['check-ignore', '--quiet', output], { cwd: retained, stdio: 'pipe' });
  await mkdir(output, { recursive: true, mode: 0o700 });
  assert.equal(await realpath(output), output);
  const receiptDirectory = await mkdtemp(join(output, `${mode}-`));
  const readerWriter = await allocationRecordWriter(receiptDirectory);
  let completionWriter: Awaited<ReturnType<typeof allocationRecordWriter>> | undefined;
  const token = process.env.CLOUDFLARE_API_TOKEN;
  assert.ok(token, 'completion_auth_unavailable');
  const queueIds = new Set([reviewed.resource_id]);
  let createSpent = false;
  const api: AllocationAPI = async (method, path, body) => {
    if (method === 'POST') {
      assert.ok(
        mode === 'complete' &&
          completionWriter &&
          path === `${base}/queues` &&
          JSON.stringify(body) === JSON.stringify({ queue_name: AUTHORITY_TARGET.logout_queue }),
        'completion_mutation_denied',
      );
      assert.equal(createSpent, false, 'completion_create_slot_spent');
      createSpent = true;
    } else
      assert.ok(
        authorityAllocationReadAllowed(path) ||
          path === `${base}/audit_logs?id=${DLQ_AUDIT_ID}` ||
          path === `${base}/d1/database/b2d340cd-bcc2-4a96-94a2-83edb93ff627` ||
          path === `${base}/r2/buckets/${AUTHORITY_TARGET.vault}` ||
          [...queueIds].some((id) => path === `${base}/queues/${id}`),
        'completion_read_denied',
      );
    await readerWriter.record({ event: 'request_intent', method, path });
    const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
      method,
      redirect: 'error',
      signal: AbortSignal.timeout(30000),
      headers: {
        Authorization: `Bearer ${token}`,
        ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
    });
    await readerWriter.record({ event: 'http_status', method, path, status: response.status });
    return { status: response.status, value: await boundedJSON(response) };
  };
  const io: CompletionIO = {
    original: () => preserved(retained),
    snapshot: async () => {
      const a = await authorityResourceInventory(api);
      assert.deepEqual(await authorityResourceInventory(api), a, 'completion_inventory_unstable');
      return a;
    },
    audit: async () => {
      const events = z
        .array(
          z.object({
            id: z.literal(DLQ_AUDIT_ID),
            owner: z.object({ id: z.literal(AUTHORITY_ACCOUNT) }),
            resource: z.object({ id: z.literal(reviewed.resource_id), type: z.literal('queue') }),
            action: z.object({ type: z.literal('create_queue'), result: z.literal(true) }),
            when: z.literal(reviewed.occurred_at),
            metadata: z.unknown(),
          }),
        )
        .length(1)
        .parse(apiSuccess(await api('GET', `${base}/audit_logs?id=${DLQ_AUDIT_ID}`)));
      assert.ok(
        matches(events[0]!.metadata, 'queue_name', reviewed.queue_name) ||
          matches(events[0]!.metadata, 'name', reviewed.queue_name),
        'completion_audit_name_changed',
      );
      return reviewed;
    },
    read: async (identity) => {
      const path =
        identity.resource === 'database'
          ? `${base}/d1/database/${identity.id}`
          : identity.resource === 'vault'
            ? `${base}/r2/buckets/${identity.id}`
            : `${base}/queues/${identity.id}`;
      const value = apiSuccess(await api('GET', path));
      let actual: CompletionIdentity;
      if (identity.resource.startsWith('logout_')) {
        const q = queueSchema.parse(value);
        assert.equal(q.producers_total_count, 0, 'completion_queue_attached');
        assert.equal(q.consumers_total_count, 0, 'completion_queue_attached');
        assert.deepEqual(q.producers ?? [], []);
        assert.deepEqual(q.consumers ?? [], []);
        actual = {
          resource: identity.resource,
          id: q.queue_id,
          name: q.queue_name,
          created_at: q.created_on,
        };
      } else if (identity.resource === 'database') {
        const d = z
          .object({ uuid: z.string(), name: z.string(), created_at: z.string() })
          .parse(value);
        actual = { resource: 'database', id: d.uuid, name: d.name, created_at: d.created_at };
      } else {
        const b = z
          .object({ name: z.literal(AUTHORITY_TARGET.vault), creation_date: z.string() })
          .parse(value);
        actual = { resource: 'vault', id: b.name, name: b.name, created_at: b.creation_date };
      }
      return completionIdentity(actual);
    },
    create: async () => {
      const q = queueSchema.parse(
        apiSuccess(
          await api('POST', `${base}/queues`, { queue_name: AUTHORITY_TARGET.logout_queue }),
        ),
      );
      const identity = completionIdentity({
        resource: 'logout_queue',
        id: q.queue_id,
        name: q.queue_name,
        created_at: q.created_on,
      });
      queueIds.add(identity.id);
      return identity;
    },
    reserve: async () => {
      assert.equal(selectedSource(true), source, 'completion_source_changed');
      const directory = join(retained, COMPLETION_DIRECTORY);
      await mkdir(directory, { mode: 0o700 }); // Existing or partial reservation is never replaced.
      const parent = await open(
        dirname(directory),
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
      completionWriter = await allocationRecordWriter(directory);
    },
    record: async (value) => {
      assert.ok(completionWriter);
      await completionWriter.record(value);
    },
  };
  try {
    await readerWriter.record({
      event: 'selected',
      mode,
      source_commit: source,
      audit_receipt_sha256: DLQ_RECEIPT_SHA,
    });
    const report =
      mode === 'complete'
        ? await completeAuthorityAllocation(io, {
            source_commit: source,
            completer_sha256: digest(await packetFile(fileURLToPath(import.meta.url))).sha256,
          })
        : {
            original: await io.original(),
            snapshot: await io.snapshot(),
            audit: await io.audit(),
            provider_creates: 0,
          };
    if (mode === 'complete')
      assert.equal(
        inspectAuthorityAllocation(await readAuthorityAllocation(retained)).complete,
        true,
      );
    await readerWriter.record({ event: 'report', report });
    await packetJson(join(receiptDirectory, 'result.json'), {
      mode,
      source_commit: source,
      report,
      artifacts_mutations: 0,
      production_mutations: 0,
    });
    return { directory: receiptDirectory, mode, report };
  } catch {
    await readerWriter.record({ event: 'stopped', recovery: 'inspect-same-identities-no-replay' });
    throw new Error(`authority_completion_stopped; retained=${receiptDirectory}`);
  } finally {
    await completionWriter?.close();
    await readerWriter.close();
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [mode, ...rest] = process.argv.slice(2);
  if (!rest.length && (mode === 'inspect' || mode === 'complete')) {
    try {
      const value = await runAuthorityCompletion(mode);
      process.stdout.write(JSON.stringify(value, null, 2) + '\n');
    } catch (error) {
      process.stderr.write(
        error instanceof Error ? error.message + '\n' : 'authority_completion_failed\n',
      );
      process.exitCode = 1;
    }
  } else {
    process.stderr.write('usage: complete-work-authority.ts inspect|complete\n');
    process.exitCode = 1;
  }
}
