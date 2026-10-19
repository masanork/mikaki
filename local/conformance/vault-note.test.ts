import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  newOwnerNote,
  ownerNoteInputError,
  encodeOwnerNote,
  decodeOwnerNote,
  parseOwnerNote,
} from '../../crates/worker/ui/vault-note.ts';

test('note v1 preserves Unicode and self-asserted provenance within UTF-8 limits', () => {
  const note = newOwnerNote('旅行 🗾', '本人のメモ\n\t次の予定');
  assert.deepEqual(decodeOwnerNote(encodeOwnerNote(note)), note);
  assert.equal(newOwnerNote('a'.repeat(256), 'a'.repeat(4096)).version, 1);
  assert.equal(ownerNoteInputError('あ'.repeat(85), 'あ'.repeat(1365)), null);
  assert.equal(ownerNoteInputError('あ'.repeat(86), 'text'), 'title');
  assert.equal(ownerNoteInputError('title', 'あ'.repeat(1366)), 'text');
  assert.throws(() => newOwnerNote('あ'.repeat(86), 'text'));
  assert.throws(() => newOwnerNote('title', 'あ'.repeat(1366)));
  // Construct malformed UTF-16 at runtime; literal values break Sonar's UTF-8 AST transport.
  for (const title of ['', ' ', 'a\n', String.fromCharCode(0xd800), String.fromCharCode(0xdfff)]) {
    assert.throws(() => newOwnerNote(title, 'text'));
    assert.equal(ownerNoteInputError(title, 'text'), 'title');
  }
  for (const body of ['', ' ', '\u0000', '\u007f', String.fromCharCode(0xd800)]) {
    assert.throws(() => newOwnerNote('title', body));
    assert.equal(ownerNoteInputError('title', body), 'text');
  }
});

test('note Unicode validation accepts surrogate pairs and rejects every lone surrogate', () => {
  for (const high of [0xd800, 0xdbff]) {
    for (const low of [0xdc00, 0xdfff]) {
      const value = String.fromCharCode(high, low);
      const note = newOwnerNote(value, value);
      assert.deepEqual(decodeOwnerNote(encodeOwnerNote(note)), note);
      assert.equal(ownerNoteInputError(value, value), null);
    }
  }
  for (let unit = 0xd800; unit <= 0xdfff; unit++) {
    const value = String.fromCharCode(unit);
    assert.throws(() => newOwnerNote(value + 'a', 'text'), /Invalid note Unicode/);
    assert.throws(() => newOwnerNote('title', 'a' + value), /Invalid note Unicode/);
  }
  for (const units of [
    [0xd800, 0xd800],
    [0xdc00, 0xd800],
    [0xd800, 0xdc00, 0xd800],
    [0xd800, 0xdc00, 0xdc00],
  ])
    assert.throws(() => newOwnerNote('title', String.fromCharCode(...units)));
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
