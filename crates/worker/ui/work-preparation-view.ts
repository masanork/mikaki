/** Native owner projections are display evidence, never permission. */
import { z } from 'zod';
import {
  sourceSchema,
  SourceError,
  sourceHttpPort,
  type SourceRead,
  type OwnedSource,
} from './work-source-view.ts';
z.config({ jitless: true });
const id = z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const git = z.string().regex(/^[a-f0-9]{40}$/);
const time = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const revision = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const destination = z
  .object({
    namespace: z.string().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/),
    name: z.string().regex(/^wk-[a-f0-9]{32}-(?:code|snapshot)$/),
    repository_id: id.nullable(),
  })
  .strict();
export const workPreparationSchema = z
  .object({
    id,
    digest,
    disclosure_digest: digest,
    destination_digest: digest.nullable(),
    task_repository: id,
    snapshot_repository: id,
    state: z.enum(['reserved', 'dispatched', 'verified', 'cleanup_pending', 'cleaned']),
    revision: z.number().int().min(1).max(5),
    expires_at: time,
    current_authority: z.boolean(),
    materialized: z.boolean(),
    task: destination,
    snapshot: destination,
  })
  .strict()
  .superRefine((p, ctx) => {
    const known = p.task.repository_id !== null && p.snapshot.repository_id !== null;
    if (
      (p.task.repository_id === null) !== (p.snapshot.repository_id === null) ||
      (p.destination_digest !== null) !== known ||
      (known && p.task.repository_id === p.snapshot.repository_id) ||
      (known && ['reserved', 'dispatched'].includes(p.state)) ||
      (p.state === 'verified' && !known) ||
      (p.materialized && !known) ||
      (p.current_authority && (p.state !== 'verified' || !p.materialized || !known))
    ) {
      ctx.addIssue({ code: 'custom', message: 'Invalid preparation projection' });
    }
  });
export type WorkPreparation = z.infer<typeof workPreparationSchema>;

const contextSchema = z.strictObject({
  repository: id,
  commit: git,
  tree: git,
  files: z
    .array(
      sourceSchema.shape.files.element.safeExtend({ snapshot_path: z.string().min(1).max(512) }),
    )
    .min(1)
    .max(32),
});
export const disclosureSchema = z
  .strictObject({
    format_version: z.literal(2),
    owner: id,
    owner_epoch: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    policy_revision: revision,
    policy_projection: digest,
    recipient: id,
    workload: id,
    expires_at: time,
    code: sourceSchema.shape.code.unwrap().safeExtend({ repository: id, commit: git, tree: git }),
    contexts: z.array(contextSchema).max(4),
    snapshot: z.strictObject({ repository: id, commit: git, tree: git }),
    selected_bytes: z.number().int().nonnegative().max(131072),
    registered_sources: z
      .array(
        z.strictObject({
          source_id: id,
          source_revision: revision,
          access_revision: revision,
          role: z.enum(['code', 'personal', 'project']),
        }),
      )
      .min(1)
      .max(5),
  })
  .superRefine((d, ctx) => {
    const ids = [d.code.repository, ...d.contexts.map((c) => c.repository)];
    const files = d.contexts.flatMap((c) => c.files);
    if (
      ids.length !== d.registered_sources.length ||
      new Set(ids).size !== ids.length ||
      d.registered_sources.some(
        (s, i) => s.source_id !== ids[i] || (i === 0 ? s.role !== 'code' : s.role === 'code'),
      ) ||
      files.length > 32 ||
      files.reduce((n, f) => n + f.bytes, 0) !== d.selected_bytes ||
      new Set(files.map((f) => f.snapshot_path)).size !== files.length ||
      d.contexts.some((c) => new Set(c.files.map((f) => f.path)).size !== c.files.length)
    ) {
      ctx.addIssue({ code: 'custom', message: 'Invalid disclosure projection' });
    }
  });
export type WorkDisclosure = z.infer<typeof disclosureSchema>;
export type WorkDisclosureRecord = {
  kind: 'disclosure';
  digest: string;
  manifest: WorkDisclosure;
  current_sources: true;
};
const envelope = <S extends z.ZodType>(record: S) =>
  z.strictObject({ format_version: z.literal(1), checked_at: time, record });
const copySchema = z.strictObject({
  review_digest: digest,
  subject: z.strictObject({
    format_version: z.literal(1),
    purpose: z.literal('private-preparation-copy'),
    preparation_id: id,
    preparation_digest: digest,
    preparation_revision: z.literal(1),
    disclosure_digest: digest,
    operator: z.literal('Cloudflare Artifacts'),
    artifacts_account: z.string().regex(/^[a-f0-9]{32}$/),
    expires_at: time,
  }),
  status: z.enum(['unconfirmed', 'approved', 'withdrawn']),
  current: z.boolean(),
  can_approve: z.boolean(),
});
export type CopyReview = z.infer<typeof copySchema>;
function copyMatches(p: WorkPreparation, c: CopyReview) {
  if (
    c.subject.preparation_id !== p.id ||
    c.subject.preparation_digest !== p.digest ||
    c.subject.disclosure_digest !== p.disclosure_digest ||
    c.subject.expires_at !== p.expires_at ||
    (c.can_approve && (c.status !== 'unconfirmed' || p.state !== 'reserved')) ||
    (c.current && c.status !== 'approved')
  )
    throw new SourceError('invalid');
  return c;
}
const pageSchema = z.strictObject({
  format_version: z.literal(1),
  checked_at: time,
  preparations: z.array(workPreparationSchema).max(20),
  next_after: id.nullable(),
});

// Bound response bytes before parsing, including a missing/false Content-Length.
async function checked<S extends z.ZodType>(
  response: Response,
  schema: S,
  signal: AbortSignal,
): Promise<z.infer<S>> {
  if (!response.ok)
    throw new SourceError(
      response.status === 401
        ? 'session'
        : [404, 409].includes(response.status)
          ? 'stale'
          : 'unavailable',
    );
  if (response.headers.get('Content-Type')?.split(';')[0] !== 'application/json' || !response.body)
    throw new SourceError('invalid');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (signal.aborted) throw new SourceError('session');
      if (part.done) break;
      bytes += part.value.length;
      if (bytes > 65536) throw new SourceError('invalid');
      chunks.push(part.value);
    }
    const data = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) {
      data.set(chunk, offset);
      offset += chunk.length;
    }
    const parsed = schema.safeParse(
      JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)),
    );
    if (!parsed.success) throw new SourceError('invalid');
    return parsed.data;
  } catch (e) {
    if (e instanceof SourceError) throw e;
    throw new SourceError('invalid');
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
export function preparationHttpPort(transport: typeof fetch = fetch) {
  const get = <S extends z.ZodType>(path: string, schema: S, signal: AbortSignal) =>
    transport(path, { signal, credentials: 'same-origin', cache: 'no-store' }).then((r) =>
      checked(r, schema, signal),
    );
  return {
    async copyReview(p: WorkPreparation, signal: AbortSignal) {
      const result = await get(
        '/work/preparations/' + encodeURIComponent(id.parse(p.id)) + '/copy-consent',
        envelope(copySchema),
        signal,
      );
      return copyMatches(p, result.record);
    },
    async copyDecision(
      p: WorkPreparation,
      c: CopyReview,
      method: 'POST' | 'DELETE',
      signal: AbortSignal,
    ) {
      copyMatches(p, c);
      const r = await transport(
        '/work/preparations/' + encodeURIComponent(id.parse(p.id)) + '/copy-consent',
        {
          method,
          signal,
          credentials: 'same-origin',
          cache: 'no-store',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ format_version: 1, review_digest: c.review_digest }),
        },
      );
      const result = await checked(r, envelope(copySchema), signal);
      if (
        result.record.review_digest !== c.review_digest ||
        result.record.status !== (method === 'POST' ? 'approved' : 'withdrawn')
      )
        throw new SourceError('invalid');
      return copyMatches(p, result.record);
    },
    async list(after: string | null, signal: AbortSignal) {
      const page = await get(
        '/work/preparations' + (after ? '?after=' + encodeURIComponent(id.parse(after)) : ''),
        pageSchema,
        signal,
      );
      if (
        page.preparations.some(
          (p, i) => p.id <= (i === 0 ? (after ?? '') : page.preparations[i - 1]!.id),
        ) ||
        (page.next_after !== null &&
          (page.preparations.length !== 20 || page.next_after !== page.preparations.at(-1)!.id))
      )
        throw new SourceError('invalid');
      return page;
    },
    async review(preparationId: string, signal: AbortSignal) {
      const p = await get(
        '/work/preparations/' + encodeURIComponent(id.parse(preparationId)),
        envelope(
          z.strictObject({ kind: z.literal('preparation'), preparation: workPreparationSchema }),
        ),
        signal,
      );
      if (p.record.preparation.id !== preparationId) throw new SourceError('invalid');
      const preparation = p.record.preparation;
      const d = await get(
        '/work/disclosures/' + preparation.disclosure_digest,
        envelope(
          z.strictObject({
            kind: z.literal('disclosure'),
            digest,
            manifest: disclosureSchema,
            current_sources: z.boolean(),
          }),
        ),
        signal,
      );
      if (
        d.record.digest !== preparation.disclosure_digest ||
        d.record.manifest.expires_at !== preparation.expires_at ||
        d.record.manifest.snapshot.repository !== preparation.snapshot_repository
      )
        throw new SourceError('invalid');
      return {
        preparation,
        disclosure: d.record.manifest,
        currentSources: d.record.current_sources,
        checkedAt: Math.min(p.checked_at, d.checked_at),
      };
    },
  };
}
export type PreparationReview = Awaited<
  ReturnType<ReturnType<typeof preparationHttpPort>['review']>
>;

/** Inspect only the exact registered versions and selected paths in the manifest.
 * The Native source reader repeats current access checks around its private I/O. */
export async function inspectDisclosure(
  port: ReturnType<typeof sourceHttpPort>,
  d: WorkDisclosure,
  signal: AbortSignal,
): Promise<SourceRead[]> {
  const sources: OwnedSource[] = [];
  let after: string | null = null;
  for (let i = 0; i < 20; i++) {
    const page = await port.list(after, signal);
    sources.push(...page.sources);
    after = page.next_after;
    if (
      d.registered_sources.every((s) => sources.some((found) => found.source_id === s.source_id)) ||
      after === null
    )
      break;
  }
  for (const [i, binding] of d.registered_sources.entries()) {
    const source = sources.find((s) => s.source_id === binding.source_id);
    const pinned = i === 0 ? d.code : d.contexts[i - 1]!;
    if (
      !source ||
      source.source_revision !== binding.source_revision ||
      source.access_revision !== binding.access_revision ||
      source.role !== binding.role ||
      source.commit !== pinned.commit ||
      source.tree !== pinned.tree
    )
      throw new SourceError('stale');
    if (
      i === 0 &&
      (!source.code ||
        Object.entries(d.code).some(
          ([k, v]) => k in source.code! && source.code![k as keyof typeof source.code] !== v,
        ))
    )
      throw new SourceError('stale');
    if (
      i > 0 &&
      d.contexts[i - 1]!.files.some(
        (f) =>
          !source.files.some(
            (s) =>
              s.path === f.path &&
              s.blob === f.blob &&
              s.mode === f.mode &&
              s.bytes === f.bytes &&
              s.sha256 === f.sha256,
          ),
      )
    )
      throw new SourceError('stale');
  }
  const reads: SourceRead[] = [];
  for (const c of d.contexts) {
    const source = sources.find((s) => s.source_id === c.repository)!;
    reads.push(
      await port.read(
        source,
        c.files.map((f) => f.path),
        signal,
      ),
    );
  }
  return reads;
}
