/** Cloudflare's uncompressed limit applies independently to each complete Worker bundle. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const WORKER_BUNDLE_MAX_BYTES = 64 * 1024 * 1024;

/** Count every uploaded module except separately uploaded source maps. */
export function workerBundleBytes(
  files: { name: string; bytes: number; type: string }[],
  entry: string,
): number {
  assert.match(entry, /^[a-zA-Z0-9_.-]+\.js$/);
  assert.ok(
    files.some((file) => file.name === entry && file.bytes > 0),
    'Missing Worker bundle entry',
  );
  assert.equal(new Set(files.map((file) => file.name)).size, files.length, 'Duplicate bundle file');
  let total = 0;
  for (const file of files) {
    assert.ok(Number.isSafeInteger(file.bytes) && file.bytes >= 0, 'Invalid bundle file size');
    if (file.type !== 'application/source-map') total += file.bytes;
  }
  assert.ok(Number.isSafeInteger(total));
  return total;
}

/** Read the multipart Worker upload emitted by Wrangler's --dry-run --outfile. */
export async function measureWorkerUpload(bytes: Uint8Array<ArrayBuffer>) {
  const lineEnd = bytes.indexOf(10);
  assert.ok(lineEnd > 2 && lineEnd < 200, 'Invalid Worker upload boundary');
  const first = new TextDecoder().decode(bytes.subarray(0, lineEnd)).trimEnd();
  assert.match(first, /^--[a-zA-Z0-9_-]+$/, 'Invalid Worker upload boundary');
  const data = await new Response(bytes, {
    headers: {
      'Content-Type': `multipart/form-data; boundary=${first.slice(2)}`,
    },
  }).formData();
  const metadata = data.get('metadata');
  assert.ok(typeof metadata === 'string', 'Missing Worker upload metadata');
  const { main_module: entry } = JSON.parse(metadata) as { main_module?: string };
  assert.ok(typeof entry === 'string' && entry.length > 0, 'Missing Worker upload entry');
  const modules = [];
  for (const [name, value] of data) {
    if (typeof value === 'string') continue;
    modules.push({
      name,
      type: value.type,
      bytes: value.size,
      sha256: createHash('sha256')
        .update(new Uint8Array(await value.arrayBuffer()))
        .digest('hex'),
    });
  }
  return { entry, modules, raw: workerBundleBytes(modules, entry) };
}

/** gzip and individual module sizes do not determine deployment eligibility. */
export function checkWorkerBundle(worker: string, raw: number): string[] {
  assert.ok(Number.isSafeInteger(raw) && raw > 0, 'Invalid Worker bundle size');
  return raw > WORKER_BUNDLE_MAX_BYTES
    ? [`${worker}: uncompressed bundle ${raw} > ${WORKER_BUNDLE_MAX_BYTES} bytes`]
    : [];
}
