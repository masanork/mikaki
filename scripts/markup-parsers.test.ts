import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { htmlElements, headingText } from './html-markup.ts';
import { markdownReferences } from './markdown-links.ts';
import { sqlParts } from '../local/sql-parts.ts';

test('Markdown links follow GFM syntax and preserve source lines without treating code as links', () => {
  const source = [
    '# A **heading** &amp; `code`',
    '',
    '[balanced](guide_(one).md#part "Title") and ![image](<image with spaces.png>)',
    '[reference][Guide]',
    '',
    '[Guide]: guide.md#reference',
    '`[inline code](not-a-link.md)`',
    '',
    '   ````ts',
    '[fenced](not-a-link.md)',
    '   `````',
    '',
    '    [indented](not-a-link.md)',
    '',
    '| GFM | table |',
    '| --- | --- |',
    '| [table](table.md) | ~~text~~ |',
    '',
    '~~~',
    '[unclosed fence](not-a-link.md)',
  ].join('\n');
  const parsed = markdownReferences(source);
  assert.deepEqual(parsed.destinations, [
    { url: 'guide_(one).md#part', line: 3 },
    { url: 'image with spaces.png', line: 3 },
    { url: 'guide.md#reference', line: 6 },
    { url: 'table.md', line: 17 },
  ]);
  assert.deepEqual([...parsed.anchors], ['a-heading--code']);
});

test('Markdown anchors retain Unicode, duplicates, Setext headings and real HTML IDs', () => {
  const parsed = markdownReferences(
    [
      '# 日本語 [guide](guide.md) ~~old~~ ![picture](image.png)',
      '# 日本語 [guide](guide.md) ~~old~~ ![picture](image.png)',
      'Setext heading',
      '==============',
      '<a name="legacy&amp;name"></a><span id=custom>text</span>',
      '<!-- <a id="comment-only"></a> -->',
      '<input name="not-an-anchor">',
      '',
      '```html',
      '<a id="code-only"></a>',
      '```',
    ].join('\n'),
  );
  assert.deepEqual(
    [...parsed.anchors],
    [
      '日本語-guide-old-picture',
      '日本語-guide-old-picture-1',
      'setext-heading',
      'legacy&name',
      'custom',
    ],
  );
});

test('HTML inspection follows browser attribute and raw-text parsing, including duplicate attributes', () => {
  const elements = htmlElements(`<!doctype html><html><head>
    <META name='description' content='A &amp; B &#x3c; C'>
    <script>const fake = '<a href="/fake">';</script>
    <!-- <link rel="canonical" href="/comment"> -->
    </head><body id=main><a href='/bad' href='/good' title="greater > and &quot;quote&quot;">link</a></body></html>`);
  assert.deepEqual(elements.find(({ tag }) => tag === 'meta')?.attributes, {
    name: 'description',
    content: 'A & B < C',
  });
  assert.deepEqual(
    elements.filter(({ tag }) => tag === 'a').map(({ attributes }) => attributes.href),
    ['/bad'],
  );
  assert.equal(
    elements.some(({ tag }) => tag === 'link'),
    false,
  );
  assert.equal(elements.find(({ tag }) => tag === 'body')?.attributes.id, 'main');
  assert.equal(elements.find(({ tag }) => tag === 'a')?.attributes.title, 'greater > and "quote"');
});

test('heading labels decode entities once and omit only generated permalink text', () => {
  assert.equal(
    headingText('A &amp; <em>B</em><a class="other heading-anchor" href="#x"><span>¶</span></a>'),
    'A & B',
  );
  assert.equal(
    headingText('<a href="/guide">Guide</a> &lt;img src=x onerror=alert(1)&gt;'),
    'Guide <img src=x onerror=alert(1)>',
  );
  assert.equal(headingText('less <unfinished'), 'less ');
  assert.equal(headingText('less &lt;unfinished'), 'less <unfinished');
});

test('local SQL fixture splitting removes full-line comments and preserves token separation', () => {
  assert.deepEqual(
    sqlParts(
      "\n -- one; comment\r\n\t-- two\nSELECT\n-- between tokens\n1;\n\nSELECT '--literal';;",
    ),
    ['SELECT\n1', "SELECT '--literal'"],
  );
  assert.deepEqual(sqlParts(' \n'.repeat(10000) + 'SELECT 1;'), ['SELECT 1']);
  assert.deepEqual(sqlParts('-- only a comment'), []);
});

test('long unterminated markup and whitespace complete in a bounded child process', () => {
  // A process timeout can interrupt a synchronous parser regression. It avoids a
  // machine-speed microbenchmark while preventing backtracking from hanging CI.
  const script = `
    import { htmlElements, headingText } from ${JSON.stringify(new URL('./html-markup.ts', import.meta.url).href)};
    import { markdownReferences } from ${JSON.stringify(new URL('./markdown-links.ts', import.meta.url).href)};
    import { sqlParts } from ${JSON.stringify(new URL('../local/sql-parts.ts', import.meta.url).href)};
    import assert from 'node:assert/strict';
    assert.equal(headingText('<'.repeat(200000)).length, 200000);
    assert.equal(htmlElements('<meta ' + 'x'.repeat(200000) + '>').filter(({tag}) => tag === 'meta').length, 1);
    assert.equal(markdownReferences('['.repeat(50000)).destinations.length, 0);
    assert.equal(markdownReferences('\x60'.repeat(4000) + '\\n' + '[not a link](missing)\\n'.repeat(1000)).destinations.length, 0);
    assert.deepEqual(sqlParts(' \\n'.repeat(50000) + 'SELECT 1;'), ['SELECT 1']);
    console.log('completed');
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '--eval', script], {
    encoding: 'utf8',
    timeout: 15000,
  });
  assert.equal(child.error, undefined);
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout.trim(), 'completed');
});
