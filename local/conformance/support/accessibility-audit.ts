import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import type { Page } from '@playwright/test';

// Disposable local fixtures only. This checks browser semantics, not audible screen-reader output.
export async function auditAccessibility(page: Page, label: string) {
  assert.match(label, /^[a-z0-9-]+$/);
  const problems = await page.evaluate(() => {
    const counts = new Map<string, number>();
    for (const node of document.querySelectorAll('[id]'))
      counts.set(node.id, (counts.get(node.id) ?? 0) + 1);
    const errors = [...counts]
      .filter(([, count]) => count > 1)
      .map(([id]) => `duplicate id: ${id}`);
    for (const node of document.querySelectorAll('[aria-labelledby], [aria-describedby]')) {
      for (const attribute of ['aria-labelledby', 'aria-describedby']) {
        for (const id of (node.getAttribute(attribute) ?? '').trim().split(/\s+/).filter(Boolean))
          if (!document.getElementById(id)) errors.push(`missing ${attribute}: ${id}`);
      }
    }
    return errors;
  });
  assert.deepEqual(problems, [], label);
  const client = await page.context().newCDPSession(page);
  try {
    const { nodes } = await client.send('Accessibility.getFullAXTree');
    const semantics = nodes
      .filter((node) => !node.ignored)
      .map((node) => ({
        role: String(node.role?.value ?? ''),
        name: String(node.name?.value ?? ''),
        properties: node.properties?.filter((property) =>
          ['live', 'atomic', 'focused', 'disabled', 'invalid'].includes(property.name),
        ),
      }));
    const named = new Set([
      'button',
      'link',
      'textbox',
      'combobox',
      'checkbox',
      'heading',
      'DisclosureTriangle',
    ]);
    assert.deepEqual(
      semantics.filter((node) => named.has(node.role) && !node.name.trim()),
      [],
      `${label}: interactive controls/headings need accessible names`,
    );
    assert.equal(
      semantics.filter((node) => node.role === 'main').length,
      1,
      `${label}: one active main`,
    );
    await mkdir('artifacts/accessibility', { recursive: true });
    await writeFile(
      `artifacts/accessibility/${label}.json`,
      JSON.stringify(semantics, null, 2) + '\n',
    );
    return semantics;
  } finally {
    await client.detach();
  }
}
