/** Extract installed FIDO tool metadata into ignored, disposable test storage. */
import { open, mkdir, writeFile, type FileHandle } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_ASAR =
  '/Applications/FIDO Alliance - Certification Conformance Testing Tools.app/Contents/Resources/app.asar';
const TARGET = fileURLToPath(new URL('../../target/fido-metadata/', import.meta.url));

type AsarEntry = { size?: number; offset?: string; files?: Record<string, AsarEntry> };

async function readFully(stream: FileHandle, length: number, position: number) {
  const data = Buffer.alloc(length);
  let received = 0;
  while (received < length) {
    const result = await stream.read(data, received, length - received, position + received);
    if (!result.bytesRead) throw new Error('Truncated ASAR archive');
    received += result.bytesRead;
  }
  return data;
}

export async function extractMetadata(source = process.env.FIDO_ASAR ?? DEFAULT_ASAR) {
  await mkdir(TARGET, { recursive: true });
  const stream = await open(source, 'r');
  try {
    const prefix = await readFully(stream, 16, 0);
    if (prefix.readUInt32LE(0) !== 4) throw new Error('Unexpected ASAR header');
    const size = prefix.readUInt32LE(12);
    if (size > 16_777_216) throw new Error('ASAR header too large');
    const header = await readFully(stream, size, 16);
    let tree = JSON.parse(header.toString('utf8')) as AsarEntry;
    const base = 16 + size + (-size & 3);
    for (const name of ['modules', 'fido2-server-conformance-module', 'metadata']) {
      const next = tree.files?.[name];
      if (!next) throw new Error(`ASAR entry missing: ${name}`);
      tree = next;
    }
    let count = 0;
    for (const [name, entry] of Object.entries(tree.files ?? {})) {
      if (!name.endsWith('.json') || basename(name) !== name || entry.files) continue;
      if (entry.size === undefined || entry.offset === undefined)
        throw new Error('Incomplete ASAR entry');
      if (entry.size > 1_048_576) throw new Error('Metadata statement too large');
      const data = await readFully(stream, entry.size, base + Number(entry.offset));
      await writeFile(join(TARGET, name), data);
      count++;
    }
    if (!count) throw new Error('No FIDO metadata found');
    return count;
  } finally {
    await stream.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const count = await extractMetadata();
  console.log(`Extracted ${count} test metadata statements to ${TARGET}`);
}
