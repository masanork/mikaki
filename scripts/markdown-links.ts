/** Repository Markdown references, using the same GFM grammar as the site renderer. */
import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkGfm from 'remark-gfm';
import type { Nodes } from 'mdast';
import { htmlElements } from './html-markup.ts';

const markdown = unified().use(remarkParse).use(remarkGfm);
export type MarkdownReferences = Readonly<{
  anchors: Set<string>;
  destinations: { url: string; line: number }[];
}>;

function* markdownNodes(root: Nodes): Generator<Nodes> {
  const pending = [root];
  while (pending.length) {
    const node = pending.pop()!;
    yield node;
    if ('children' in node)
      for (let index = node.children.length - 1; index >= 0; index--)
        pending.push(node.children[index]);
  }
}

function headingSlug(heading: Nodes): string {
  const text: string[] = [];
  for (const node of markdownNodes(heading)) {
    if (node.type === 'text' || node.type === 'inlineCode') text.push(node.value);
    if (node.type === 'image' || node.type === 'imageReference') text.push(node.alt ?? '');
  }
  // Preserve the repository's Unicode slug and duplicate suffix rules.
  return text
    .join('')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}_\s-]/gu, '')
    .replace(/\s/g, '-');
}

function htmlAnchors(anchors: Set<string>, source: string): void {
  for (const { tag, attributes } of htmlElements(source)) {
    if (attributes.id) anchors.add(attributes.id);
    if (tag === 'a' && attributes.name) anchors.add(attributes.name);
  }
}

export function markdownReferences(source: string): MarkdownReferences {
  const anchors = new Set<string>();
  const duplicates = new Map<string, number>();
  const destinations: { url: string; line: number }[] = [];
  for (const node of markdownNodes(markdown.parse(source))) {
    if (node.type === 'heading') {
      const slug = headingSlug(node);
      const duplicate = duplicates.get(slug) ?? 0;
      duplicates.set(slug, duplicate + 1);
      anchors.add(duplicate ? `${slug}-${duplicate}` : slug);
    }
    if (node.type === 'html') htmlAnchors(anchors, node.value);
    if (node.type === 'link' || node.type === 'image' || node.type === 'definition')
      destinations.push({ url: node.url, line: node.position?.start.line ?? 1 });
  }
  return { anchors, destinations };
}
