import assert from 'node:assert/strict';
import { test } from 'node:test';
import { threadSearchExcerpt } from '../../crates/worker/ui/vault-thread-search-excerpt.ts';
import { normalizeThreadSearchText as normalize } from '../../crates/worker/ui/vault-thread-search-query.ts';

test('long-message excerpts contain the match, preserve original spelling and bound Unicode safely', () => {
  const cases: [string, string, string][] = [
    ['前置き'.repeat(300) + '住所変更の申請' + '後の説明'.repeat(300), '住所変更', '住所変更'],
    ['🐈'.repeat(300) + 'ＡＢＣ' + '🐈'.repeat(300), 'abc', 'ＡＢＣ'],
    ['前'.repeat(300) + 'e\u0301clair' + '後'.repeat(300), 'éclair', 'e\u0301clair'],
    ['前'.repeat(300) + 'ｶﾞｲﾄﾞ' + '後'.repeat(300), 'ガイド', 'ｶﾞｲﾄﾞ'],
    ['前'.repeat(300) + '👨‍👩‍👧‍👦' + '後'.repeat(300), '👨‍👩‍👧‍👦', '👨‍👩‍👧‍👦'],
    ['前'.repeat(300) + '<script>alert(1)</script>', '<script>', '<script>'],
  ];
  for (const [body, query, original] of cases) {
    const excerpt = threadSearchExcerpt(body, [query]);
    assert.ok(excerpt.includes(original));
    assert.ok([...excerpt].length <= 240);
    assert.equal(/[\uD800-\uDFFF]/u.test(excerpt), false);
    assert.ok(excerpt.startsWith('…'));
  }
  assert.equal(threadSearchExcerpt('Alice says Hello', ['alice']), 'Alice says Hello');
  const speakerOnly = threadSearchExcerpt('body '.repeat(300), ['speaker']);
  assert.ok(speakerOnly.startsWith('body '));
  assert.ok(speakerOnly.endsWith('…'));
});

test('context-sensitive normalization and oversized graphemes use a bounded derived window', () => {
  for (const body of ['ΟΣ '.repeat(300) + 'Needle', 'e' + '\u0301'.repeat(400) + 'needle']) {
    const excerpt = threadSearchExcerpt(body, ['needle']);
    assert.ok(normalize(excerpt).includes('needle'));
    assert.ok([...excerpt].length <= 240);
    assert.equal(/[\uD800-\uDFFF]/u.test(excerpt), false);
  }
});
