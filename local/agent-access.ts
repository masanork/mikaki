/** Owner-prepared plaintext export. This is not a Vault unlock or remote credential. */
import { createHash } from 'node:crypto';
import { open, appendFile } from 'node:fs/promises';
import { z } from 'zod';
import {
  vaultRecordSourceInfo,
  recordSelection,
  unknownSource,
} from '../crates/agent-worker/tool-results.ts';
import {
  parseVaultRecordSource,
  equalVaultSource,
} from '../crates/worker/ui/vault-record-source.ts';
import { decodeOwnerNote } from '../crates/worker/ui/vault-note.ts';

const id = z.string().regex(/^[A-Za-z0-9_-]{1,80}$/);
const label = z.string().min(1).max(160);
const operation = z.enum(['list', 'search', 'read']);
export type Operation = z.infer<typeof operation>;
const unspecifiedSourceSchema = z.strictObject({
  kind: z.literal('unspecified'),
  attribute: z.null(),
  revision: z.null(),
  provenance: z.literal('unspecified'),
  confirmed_at: z.null(),
});
const genericGrantSchema = z.strictObject({
  version: z.literal(1),
  id,
  owner: id,
  delegate: id,
  service: label,
  collection: id,
  export_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  document_ids: z.array(id).min(1).max(100),
  operations: z.array(operation).min(1).max(3),
  not_before: z.number().int().nonnegative(),
  expires_at: z.number().int().nonnegative(),
  revoked: z.boolean(),
});
const genericExportSchema = z.strictObject({
  version: z.literal(1),
  owner: id,
  collection: id,
  documents: z
    .array(
      z.strictObject({
        id,
        title: label,
        source: label,
        source_info: unspecifiedSourceSchema.optional(),
        text: z.string().refine((value) => Buffer.byteLength(value) <= 16384),
      }),
    )
    .max(100),
});
const recordExportSchema = z.strictObject({
  version: z.literal(2),
  owner: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  collection: z.literal('vault-records'),
  documents: z
    .array(
      z.strictObject({
        id: z.enum(['name', 'owner_note']),
        title: label,
        source: label,
        source_info: vaultRecordSourceInfo,
        text: z.string().refine((value) => Buffer.byteLength(value) <= 16384),
      }),
    )
    .min(1)
    .max(2),
});
const recordGrantSchema = genericGrantSchema.extend({
  version: z.literal(2),
  id,
  owner: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
  delegate: id,
  service: label,
  collection: z.literal('vault-records'),
  export_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  document_ids: z
    .array(z.enum(['name', 'owner_note']))
    .min(1)
    .max(2),
  operations: z.array(operation).min(1).max(3),
  not_before: z.number().int().nonnegative(),
  expires_at: z.number().int().nonnegative(),
  revoked: z.boolean(),
  sources: z.array(recordSelection).min(1).max(2),
});
const exportSchema = z.discriminatedUnion('version', [genericExportSchema, recordExportSchema]);
const grantSchema = z.discriminatedUnion('version', [genericGrantSchema, recordGrantSchema]);

async function boundedFile(path: string, limit: number): Promise<Buffer> {
  const file = await open(path, 'r');
  try {
    if (!(await file.stat()).isFile()) throw new Error('Invalid file');
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length > limit) throw new Error('File too large');
    return buffer.subarray(0, length);
  } finally {
    await file.close();
  }
}

export class AgentAccess {
  private readonly grantPath: string;
  private readonly auditPath: string;
  private readonly delegate: string;
  private readonly bundle: z.infer<typeof exportSchema>;
  private readonly digest: string;
  private readonly grantId: string;
  private readonly service: string;
  private readonly clock: () => number;
  private constructor(
    grantPath: string,
    auditPath: string,
    delegate: string,
    bundle: z.infer<typeof exportSchema>,
    digest: string,
    grantId: string,
    service: string,
    clock: () => number,
  ) {
    this.grantPath = grantPath;
    this.auditPath = auditPath;
    this.delegate = delegate;
    this.bundle = bundle;
    this.digest = digest;
    this.grantId = grantId;
    this.service = service;
    this.clock = clock;
  }

  static async create(options: {
    grantPath: string;
    exportPath: string;
    auditPath: string;
    delegate: string;
    clock?: () => number;
  }): Promise<AgentAccess> {
    const bytes = await boundedFile(options.exportPath, 1024 * 1024);
    const bundle = exportSchema.parse(JSON.parse(bytes.toString('utf8')));
    if (bundle.version === 2) {
      for (const doc of bundle.documents) {
        const source = parseVaultRecordSource(doc.source_info.source);
        if (source.owner_id !== bundle.owner || source.record_id !== doc.id)
          throw new Error('Invalid record source binding');
        if (doc.id === 'owner_note') decodeOwnerNote(new TextEncoder().encode(doc.text));
        else if (!doc.text.length || doc.text.length > 256) throw new Error('Invalid saved name');
      }
    }
    if (new Set(bundle.documents.map((doc) => doc.id)).size !== bundle.documents.length)
      throw new Error('Duplicate document ID');
    const grant = grantSchema.parse(
      JSON.parse((await boundedFile(options.grantPath, 32768)).toString('utf8')),
    );
    const access = new AgentAccess(
      options.grantPath,
      options.auditPath,
      options.delegate,
      bundle,
      createHash('sha256').update(bytes).digest('hex'),
      grant.id,
      grant.service,
      options.clock ?? (() => Math.floor(Date.now() / 1000)),
    );
    await access.grant();
    return access;
  }

  private async grant() {
    const grant = grantSchema.parse(
      JSON.parse((await boundedFile(this.grantPath, 32768)).toString('utf8')),
    );
    const now = this.clock();
    if (
      grant.revoked ||
      grant.version !== this.bundle.version ||
      now < grant.not_before ||
      now >= grant.expires_at ||
      grant.not_before >= grant.expires_at ||
      grant.expires_at - grant.not_before > 86400 ||
      grant.delegate !== this.delegate ||
      grant.id !== this.grantId ||
      grant.service !== this.service ||
      grant.owner !== this.bundle.owner ||
      grant.collection !== this.bundle.collection ||
      grant.export_sha256 !== this.digest ||
      new Set(grant.document_ids).size !== grant.document_ids.length ||
      new Set(grant.operations).size !== grant.operations.length ||
      grant.document_ids.some((target) => !this.bundle.documents.some((doc) => doc.id === target))
    )
      throw new Error('Access denied');
    if (grant.version === 2) {
      if (this.bundle.version !== 2 || grant.sources.length !== grant.document_ids.length)
        throw new Error('Access denied');
      const selected = this.bundle.documents.filter((doc) =>
        grant.document_ids.some((target) => target === doc.id),
      );
      const sourceIds = grant.sources.map((item) => item.source.record_id);
      if (
        new Set(sourceIds).size !== sourceIds.length ||
        selected.some((doc) => {
          const actual = grant.sources.find((item) => item.source.record_id === doc.id);
          return (
            !actual ||
            !equalVaultSource(actual.source, doc.source_info.source) ||
            actual.authority.key_generation !== doc.source_info.authority.key_generation ||
            actual.authority.owner_key_revision !== doc.source_info.authority.owner_key_revision
          );
        })
      )
        throw new Error('Access denied');
    }
    return { value: grant, checkedAt: now };
  }

  async call(op: Operation, args: unknown): Promise<unknown> {
    let target: string | undefined;
    try {
      const { value: grant } = await this.grant();
      if (!grant.operations.includes(op)) throw new Error('Access denied');
      const visible = this.bundle.documents.filter((doc) =>
        grant.document_ids.some((target) => target === doc.id),
      );
      let result: Record<string, unknown>;
      if (op === 'read') {
        const input = z.strictObject({ id }).parse(args);
        const document = visible.find((doc) => doc.id === input.id);
        if (!document) throw new Error('Access denied');
        target = document.id;
        result = {
          ...document,
          source_info: document.source_info ?? unknownSource(),
          untrusted_content: true,
        };
      } else {
        const page = { offset: z.number().int().min(0).max(100).default(0) };
        const input =
          op === 'search'
            ? z.strictObject({ ...page, query: z.string().trim().min(1).max(200) }).parse(args)
            : z.strictObject(page).parse(args);
        const query =
          'query' in input && typeof input.query === 'string'
            ? input.query.toLowerCase()
            : undefined;
        const matches =
          query === undefined
            ? visible
            : visible.filter(
                (doc) =>
                  doc.title.toLowerCase().includes(query) || doc.text.toLowerCase().includes(query),
              );
        const documents = matches
          .slice(input.offset, input.offset + 10)
          .map(({ id, title, source, source_info }) => ({
            id,
            title,
            source,
            source_info: source_info ?? unknownSource(),
          }));
        result = {
          documents,
          next_offset: input.offset + 10 < matches.length ? input.offset + 10 : null,
          untrusted_content: true,
        };
      }
      // Audit must succeed before disclosure. Re-read after I/O to catch expiry/revocation.
      await this.audit(op, 'allowed', target);
      const fresh = await this.grant();
      if (JSON.stringify(fresh.value) !== JSON.stringify(grant)) throw new Error('Access denied');
      return {
        ...result,
        result_version: 1,
        access: {
          mode: 'local-export',
          source_check: 'not-checked',
          checked_at: fresh.checkedAt,
          grant_expires_at: grant.expires_at,
        },
      };
    } catch {
      await this.audit(op, 'denied');
      throw new Error('Access denied or unavailable');
    }
  }

  private async audit(op: Operation, outcome: string, target?: string) {
    await appendFile(
      this.auditPath,
      JSON.stringify({
        time: this.clock(),
        grant: this.grantId,
        delegate: this.delegate,
        service: this.service,
        operation: op,
        ...(target ? { target } : {}),
        outcome,
      }) + '\n',
      { mode: 0o600 },
    );
  }
}
