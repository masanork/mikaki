import { normalizeThreadSearchText as normalize } from './vault-thread-search-query.ts';

const segmenter = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
const earliest = (text: string, terms: string[]) =>
  Math.min(...terms.map((term) => text.indexOf(term)).filter((offset) => offset >= 0));

// Display only: the authoritative original message and revision remain separate.
// At most 240 Unicode scalar values, including omission markers; no raw HTML.
export function threadSearchExcerpt(body: string, terms: string[]): string {
  if ([...body].length <= 238) return body;
  const normalized = normalize(body);
  const offset = earliest(normalized, terms);
  const units = [...segmenter.segment(body)].map(({ segment }) => ({
    text: segment,
    normalized: normalize(segment),
    size: [...segment].length,
  }));
  // Normalization/case conversion is context-sensitive. Use original offsets only
  // when the reconstructed normalized graphemes exactly match the whole message.
  if (units.map((unit) => unit.normalized).join('') === normalized) {
    let center = 0,
      position = 0;
    if (Number.isFinite(offset)) {
      while (center < units.length - 1 && position + units[center]!.normalized.length <= offset) {
        position += units[center++]!.normalized.length;
      }
    }
    let start = center,
      before = 0;
    while (start > 0 && before + units[start - 1]!.size <= 40) before += units[--start]!.size;
    let end = start,
      size = 0;
    while (end < units.length && size + units[end]!.size <= 238) size += units[end++]!.size;
    if (end > center)
      return (
        (start ? '…' : '') +
        units
          .slice(start, end)
          .map((unit) => unit.text)
          .join('') +
        (end < units.length ? '…' : '')
      );
  }
  // A context-sensitive mapping or exceptionally large grapheme cannot be safely
  // mapped into a bounded original window. Show derived normalized text instead.
  const points = [...normalized];
  const center = Number.isFinite(offset) ? [...normalized.slice(0, offset)].length : 0;
  const start = Math.max(0, center - 40),
    end = Math.min(points.length, start + 238);
  return (start ? '…' : '') + points.slice(start, end).join('') + (end < points.length ? '…' : '');
}
