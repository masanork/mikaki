// The first typed owner attribute. This schema carries assertions, never identity proof.
export const NOTE_ATTRIBUTE = 'owner_note';
export const NOTE_TYPE = 'mikaki.owner-note';
export const NOTE_MAX_TITLE_BYTES = 256;
export const NOTE_MAX_TEXT_BYTES = 4096;
export const NOTE_MAX_DOCUMENT_BYTES = 16 * 1024;

export type OwnerNote = {
  type: typeof NOTE_TYPE;
  version: 1;
  title: string;
  text: string;
  provenance: { kind: 'self-asserted' };
};

function exact(value: unknown, keys: string[]): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new Error('Invalid note document');
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key)))
    throw new Error('Invalid note fields');
}

function text(value: unknown, limit: number, multiline: boolean): asserts value is string {
  if (typeof value !== 'string' || value.trim().length === 0) throw new Error('Invalid note text');
  // Reject lone UTF-16 surrogates instead of silently encoding a replacement character.
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('Invalid note Unicode');
    } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error('Invalid note Unicode');
  }
  const forbidden = multiline
    ? /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/
    : /[\u0000-\u001f\u007f]/;
  if (forbidden.test(value) || new TextEncoder().encode(value).length > limit)
    throw new Error('Invalid note text');
}

export function parseOwnerNote(value: unknown): OwnerNote {
  exact(value, ['type', 'version', 'title', 'text', 'provenance']);
  if (value['type'] !== NOTE_TYPE || value['version'] !== 1)
    throw new Error('Unsupported note type or version');
  text(value['title'], NOTE_MAX_TITLE_BYTES, false);
  text(value['text'], NOTE_MAX_TEXT_BYTES, true);
  exact(value['provenance'], ['kind']);
  if (value['provenance']['kind'] !== 'self-asserted')
    throw new Error('Unsupported note provenance');
  return {
    type: NOTE_TYPE,
    version: 1,
    title: value['title'],
    text: value['text'],
    provenance: { kind: 'self-asserted' },
  };
}

export function newOwnerNote(title: string, body: string): OwnerNote {
  return parseOwnerNote({
    type: NOTE_TYPE,
    version: 1,
    title,
    text: body,
    provenance: { kind: 'self-asserted' },
  });
}

export function encodeOwnerNote(value: unknown): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new TextEncoder().encode(JSON.stringify(parseOwnerNote(value))));
  if (bytes.length > NOTE_MAX_DOCUMENT_BYTES) throw new Error('Note document too large');
  return bytes;
}

export function decodeOwnerNote(bytes: Uint8Array<ArrayBuffer>): OwnerNote {
  if (bytes.length > NOTE_MAX_DOCUMENT_BYTES) throw new Error('Note document too large');
  const json = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
  const note = parseOwnerNote(JSON.parse(json) as unknown);
  // The published format is exactly our deterministic UTF-8 JSON encoding.
  // This rejects duplicate keys, BOMs and ambiguous/noncanonical representations.
  const canonical = encodeOwnerNote(note);
  if (bytes.length !== canonical.length || bytes.some((byte, index) => byte !== canonical[index]))
    throw new Error('Noncanonical note document');
  return note;
}
