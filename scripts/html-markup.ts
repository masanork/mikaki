/** Build/audit helpers: parse HTML as markup, without executing or fetching it. */
import { parse, parseFragment, type DefaultTreeAdapterTypes as Html } from 'parse5';

export type HtmlElement = Readonly<{
  tag: string;
  attributes: Readonly<Record<string, string>>;
}>;

function isHeadingAnchor(node: Html.Node): boolean {
  return (
    'tagName' in node &&
    node.tagName === 'a' &&
    node.attrs.some(
      ({ name, value }) => name === 'class' && value.split(/\s+/).includes('heading-anchor'),
    )
  );
}

function* htmlNodes(root: Html.Node, omitPermalinks = false): Generator<Html.Node> {
  const pending = [root];
  while (pending.length) {
    const node = pending.pop()!;
    if (omitPermalinks && isHeadingAnchor(node)) continue;
    yield node;
    if ('childNodes' in node)
      for (let index = node.childNodes.length - 1; index >= 0; index--)
        pending.push(node.childNodes[index]);
  }
}

export function htmlElements(source: string): HtmlElement[] {
  const elements: HtmlElement[] = [];
  for (const node of htmlNodes(parse(source)))
    if ('tagName' in node)
      elements.push({
        tag: node.tagName,
        attributes: Object.fromEntries(node.attrs.map(({ name, value }) => [name, value])),
      });
  return elements;
}

/** Decoded heading text, excluding the generated permalink's accessible label. */
export function headingText(source: string): string {
  const text: string[] = [];
  for (const node of htmlNodes(parseFragment(source), true))
    if (node.nodeName === '#text' && 'value' in node) text.push(node.value);
  return text.join('');
}
