import { z } from 'zod';
z.config({ jitless: true });
const id = z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
  revision = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);
const git = z.string().regex(/^[a-f0-9]{40}$/),
  digest = z.string().regex(/^[a-f0-9]{64}$/);
function comparePaths(a: string, b: string) {
  const aa = new TextEncoder().encode(a),
    bb = new TextEncoder().encode(b);
  for (let i = 0; i < Math.min(aa.length, bb.length); i++) {
    if (aa[i] !== bb[i]) return aa[i]! - bb[i]!;
  }
  return aa.length - bb.length;
}
const file = z.strictObject({
  path: z
    .string()
    .min(1)
    .max(256)
    .refine(
      (p) =>
        new TextEncoder().encode(p).length <= 256 &&
        !/[\\\x00-\x1f\x7f]/u.test(p) &&
        p
          .split('/')
          .every(
            (s) => s.length > 0 && s !== '.' && s !== '..' && !s.toLowerCase().startsWith('.git'),
          ),
    ),
  blob: git,
  mode: z.enum(['100644', '100755']),
  bytes: z.number().int().min(0).max(16384),
  sha256: digest,
});
const code = z.strictObject({
  commits: z.number().int().min(1).max(4096),
  history_digest: digest,
  objects: z.number().int().min(1).max(65536),
  object_bytes: z.number().int().min(0).max(67108864),
  head_files: z.number().int().min(0).max(8192),
});
export const sourceSchema = z
  .strictObject({
    source_id: id,
    source_revision: revision,
    role: z.enum(['code', 'personal', 'project']),
    label: z.string().min(1).max(160),
    commit: git,
    tree: git,
    files: z.array(file).max(64),
    code: code.nullable(),
  })
  .superRefine((s, ctx) => {
    if (
      (s.role === 'code' ? !s.code || s.files.length !== 0 : s.code !== null || !s.files.length) ||
      s.files.some((f, i) => i > 0 && comparePaths(s.files[i - 1]!.path, f.path) >= 0) ||
      (s.code && s.code.objects < s.code.commits)
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid source metadata' });
  });
export const ownedSourceSchema = sourceSchema.safeExtend({ access_revision: revision });
export type OwnedSource = z.infer<typeof ownedSourceSchema>;
const pageSchema = z.strictObject({
  format_version: z.literal(1),
  checked_at: z.number().int().min(1),
  record: z.strictObject({
    sources: z.array(ownedSourceSchema).max(10),
    next_after: id.nullable(),
  }),
});
const readSchema = z.strictObject({
  format_version: z.literal(1),
  checked_at: z.number().int().min(1),
  record: z.strictObject({
    source: sourceSchema,
    access_revision: revision,
    files: z.array(file.extend({ content: z.string().max(16384) })).max(32),
  }),
});
export type SourceRead = z.infer<typeof readSchema>['record'];
export class SourceError extends Error {
  readonly reason: 'stale' | 'session' | 'unavailable' | 'invalid';
  constructor(reason: SourceError['reason']) {
    super(reason);
    this.reason = reason;
  }
}
async function checked(response: Response): Promise<unknown> {
  if (!response.ok)
    throw new SourceError(
      response.status === 401
        ? 'session'
        : [404, 409].includes(response.status)
          ? 'stale'
          : 'unavailable',
    );
  try {
    return await response.json();
  } catch {
    throw new SourceError('unavailable');
  }
}
export function sourceHttpPort(transport: typeof fetch = (...args) => fetch(...args)) {
  return {
    async list(after: string | null = null, signal?: AbortSignal) {
      try {
        return pageSchema.parse(
          await checked(
            await transport(
              '/work/sources' + (after ? '?after=' + encodeURIComponent(after) : ''),
              {
                credentials: 'same-origin',
                cache: 'no-store',
                ...(signal ? { signal } : {}),
              },
            ),
          ),
        ).record;
      } catch (e) {
        if (e instanceof SourceError) throw e;
        throw new SourceError('unavailable');
      }
    },
    async read(source: OwnedSource, paths: string[], signal?: AbortSignal): Promise<SourceRead> {
      const sorted = [...paths];
      // Native ordering is UTF-8 byte order, equivalent to scalar order for valid paths.
      sorted.sort(comparePaths);
      try {
        const result = readSchema.parse(
          await checked(
            await transport('/work/sources/read', {
              method: 'POST',
              credentials: 'same-origin',
              cache: 'no-store',
              ...(signal ? { signal } : {}),
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                format_version: 1,
                source_id: source.source_id,
                source_revision: source.source_revision,
                access_revision: source.access_revision,
                paths: sorted,
              }),
            }),
          ),
        ).record;
        const { access_revision, ...metadata } = source;
        if (
          result.access_revision !== access_revision ||
          JSON.stringify(result.source) !== JSON.stringify(sourceSchema.parse(metadata)) ||
          result.files.length !== sorted.length ||
          result.files.some(
            (f, i) =>
              f.path !== sorted[i] ||
              !source.files.some(
                (expected) =>
                  expected.path === f.path &&
                  expected.blob === f.blob &&
                  expected.mode === f.mode &&
                  expected.sha256 === f.sha256 &&
                  expected.bytes === f.bytes,
              ),
          )
        )
          throw new SourceError('stale');
        for (const file of result.files) {
          const bytes = new TextEncoder().encode(file.content);
          const actual = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes.buffer))]
            .map((v) => v.toString(16).padStart(2, '0'))
            .join('');
          if (bytes.length !== file.bytes || actual !== file.sha256) throw new SourceError('stale');
        }
        if (signal?.aborted) throw new SourceError('unavailable');
        return result;
      } catch (e) {
        if (e instanceof SourceError) throw e;
        throw new SourceError('unavailable');
      }
    },
  };
}
