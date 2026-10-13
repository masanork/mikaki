/** Verify display bytes against Native's disclosure v2 encoding; no authority is issued. */
import { createHash } from 'node:crypto';
import { disclosureSchema } from '../crates/worker/ui/work-preparation-view.ts';

export function disclosureProjectionDigest(input: unknown) {
  const d = disclosureSchema.parse(input);
  // crates/auth/src/work/{mod,disclosure}.rs: length-prefixed fields and BE u64s.
  const hash = createHash('sha256');
  const number = (value: number) => {
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64BE(BigInt(value));
    hash.update(bytes);
  };
  const bytes = (value: Buffer) => {
    number(value.length);
    hash.update(value);
  };
  const text = (value: string) => bytes(Buffer.from(value, 'utf8'));
  const digest = (value: string) => bytes(Buffer.from(value, 'hex'));
  text('mikaki.work-disclosure.v2');
  text(d.owner);
  number(d.owner_epoch);
  number(d.policy_revision);
  text(d.recipient);
  text(d.workload);
  number(d.expires_at);
  text(d.code.repository);
  text(d.code.commit);
  text(d.code.tree);
  number(d.code.commits);
  digest(d.code.history_digest);
  number(d.code.objects);
  number(d.code.object_bytes);
  number(d.code.head_files);
  number(d.contexts.length);
  for (const context of d.contexts) {
    text(context.repository);
    text(context.commit);
    text(context.tree);
    number(context.files.length);
    for (const file of context.files) {
      text(file.path);
      text(file.snapshot_path);
      text(file.blob);
      text(file.mode);
      number(file.bytes);
      digest(file.sha256);
    }
  }
  text(d.snapshot.repository);
  text(d.snapshot.commit);
  text(d.snapshot.tree);
  number(d.selected_bytes);
  number(d.registered_sources.length);
  for (const source of d.registered_sources) {
    text(source.source_id);
    number(source.source_revision);
    number(source.access_revision);
    text(source.role);
  }
  digest(d.policy_projection);
  return hash.digest('hex');
}
