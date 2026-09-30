import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  newOwnerNote,
  encodeOwnerNote,
  decodeOwnerNote,
  parseOwnerNote,
} from '../../crates/worker/ui/vault-note.ts';

test('note v1 preserves Unicode and self-asserted provenance within UTF-8 limits', () => {
  const note = newOwnerNote('旅行 🗾', '本人のメモ\n\t次の予定');
  assert.deepEqual(decodeOwnerNote(encodeOwnerNote(note)), note);
  assert.equal(newOwnerNote('a'.repeat(256), 'a'.repeat(4096)).version, 1);
  assert.throws(() => newOwnerNote('あ'.repeat(86), 'text'));
  assert.throws(() => newOwnerNote('title', 'あ'.repeat(1366)));
  for (const title of ['', ' ', 'a\n', '\ud800', '\udfff'])
    assert.throws(() => newOwnerNote(title, 'text'));
  for (const body of ['', ' ', '\u0000', '\u007f', '\ud800'])
    assert.throws(() => newOwnerNote('title', body));
});

test('incompatible, ambiguous and misleading note input is rejected without fallback', () => {
  const note = newOwnerNote('Title', 'Body');
  for (const value of [
    { ...note, version: 2 },
    { ...note, type: 'other' },
    { ...note, issuer: 'trusted' },
    { ...note, title: 7 },
    { ...note, provenance: { kind: 'issuer-verified' } },
    { ...note, provenance: { kind: 'self-asserted', issuer: 'trusted' } },
    null,
    [],
    { title: 'old untyped value' },
  ])
    assert.throws(() => parseOwnerNote(value));
  const json = new TextDecoder().decode(encodeOwnerNote(note));
  for (const value of [
    'legacy plain text',
    json + '\n',
    '\ufeff' + json,
    json.replace('"version":1', '"version":1,"version":1'),
    JSON.stringify({
      title: note.title,
      type: note.type,
      version: note.version,
      text: note.text,
      provenance: note.provenance,
    }),
    json.replace('Title', '\\u0054itle'),
  ])
    assert.throws(() => decodeOwnerNote(new TextEncoder().encode(value)));
  assert.throws(() => decodeOwnerNote(new Uint8Array([0xff])));
  assert.throws(() => decodeOwnerNote(new Uint8Array(16385)));
  assert.deepEqual(decodeOwnerNote(encodeOwnerNote(note)), note);
});
