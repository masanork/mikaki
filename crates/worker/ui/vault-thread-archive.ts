// Imported archive, not proof of delivery or an official application/approval receipt.
export type ThreadArchive = {
  format_version: 1;
  title: string;
  messages: { speaker: string; actor: 'human' | 'ai'; text: string; timestamp: string }[];
};
export function parseThreadArchive(value: unknown): ThreadArchive {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid archive');
  const v = value as Record<string, unknown>;
  if (
    Object.keys(v).some((key) => !['format_version', 'title', 'messages'].includes(key)) ||
    v['format_version'] !== 1 ||
    typeof v['title'] !== 'string' ||
    !v['title'].trim() ||
    v['title'].length > 256 ||
    !Array.isArray(v['messages']) ||
    v['messages'].length < 1 ||
    v['messages'].length > 200
  )
    throw new Error('invalid archive');
  const messages = v['messages'].map((entry: unknown): ThreadArchive['messages'][number] => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry))
      throw new Error('invalid message');
    const m = entry as Record<string, unknown>;
    if (
      Object.keys(m).some((key) => !['speaker', 'actor', 'text', 'timestamp'].includes(key)) ||
      typeof m['speaker'] !== 'string' ||
      !m['speaker'].trim() ||
      m['speaker'].length > 128 ||
      (m['actor'] !== 'human' && m['actor'] !== 'ai') ||
      typeof m['text'] !== 'string' ||
      !m['text'] ||
      typeof m['timestamp'] !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T.*Z$/.test(m['timestamp']) ||
      !Number.isFinite(Date.parse(m['timestamp'])) ||
      new Date(m['timestamp']).toISOString() !== m['timestamp']
    )
      throw new Error('invalid message');
    return { speaker: m['speaker'], actor: m['actor'], text: m['text'], timestamp: m['timestamp'] };
  });
  return { format_version: 1, title: v['title'], messages };
}
