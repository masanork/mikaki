// Imported archive, not proof of delivery or an official application/approval receipt.
type ArchiveMessage = { speaker: string; actor: 'human' | 'ai'; text: string; timestamp: string };
export type AppArchiveSource = {
  app: 'cloudflare-os';
  origin: string;
  workspace_id: string;
  chat_id: number;
  first_sequence: number;
  last_sequence: number;
  scope: 'text-segment';
};
export type AppThreadArchive = {
  format_version: 2;
  source: AppArchiveSource;
  title: string;
  messages: (ArchiveMessage & { source_id: string })[];
};
export type ThreadArchive =
  | AppThreadArchive
  | {
      format_version: 1;
      title: string;
      messages: ArchiveMessage[];
    };
export function archiveAppOrigin(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return (
      url.origin === value &&
      !url.username &&
      !url.password &&
      (url.protocol === 'https:' ||
        (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))
    );
  } catch {
    return false;
  }
}
export function parseThreadArchive(value: unknown): ThreadArchive {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid archive');
  const v = value as Record<string, unknown>;
  const app = v['format_version'] === 2;
  let source: AppArchiveSource | undefined;
  if (app) {
    const raw = v['source'];
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('invalid source');
    const s = raw as Record<string, unknown>;
    const sequence = (value: unknown): value is number =>
      typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
    if (
      Object.keys(s).length !== 7 ||
      Object.keys(s).some(
        (key) =>
          ![
            'app',
            'origin',
            'workspace_id',
            'chat_id',
            'first_sequence',
            'last_sequence',
            'scope',
          ].includes(key),
      ) ||
      s['app'] !== 'cloudflare-os' ||
      !archiveAppOrigin(s['origin']) ||
      typeof s['workspace_id'] !== 'string' ||
      !/^[A-Za-z0-9_-]{1,256}$/.test(s['workspace_id']) ||
      !sequence(s['chat_id']) ||
      !sequence(s['first_sequence']) ||
      !sequence(s['last_sequence']) ||
      s['first_sequence'] > s['last_sequence'] ||
      s['scope'] !== 'text-segment'
    )
      throw new Error('invalid source');
    source = {
      app: 'cloudflare-os',
      origin: s['origin'],
      workspace_id: s['workspace_id'],
      chat_id: s['chat_id'],
      first_sequence: s['first_sequence'],
      last_sequence: s['last_sequence'],
      scope: 'text-segment',
    };
  }
  if (
    Object.keys(v).some(
      (key) => !['format_version', 'title', 'messages', ...(app ? ['source'] : [])].includes(key),
    ) ||
    (!app && v['format_version'] !== 1) ||
    typeof v['title'] !== 'string' ||
    !v['title'].trim() ||
    v['title'].length > 256 ||
    !Array.isArray(v['messages']) ||
    v['messages'].length < 1 ||
    v['messages'].length > 200
  )
    throw new Error('invalid archive');
  let previousSequence = -1;
  const messages = v['messages'].map((entry: unknown) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry))
      throw new Error('invalid message');
    const m = entry as Record<string, unknown>;
    if (
      Object.keys(m).some(
        (key) =>
          !['speaker', 'actor', 'text', 'timestamp', ...(app ? ['source_id'] : [])].includes(key),
      ) ||
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
    const message: ArchiveMessage = {
      speaker: m['speaker'],
      actor: m['actor'],
      text: m['text'],
      timestamp: m['timestamp'],
    };
    if (!source) return message;
    const id = m['source_id'];
    const sequence = typeof id === 'string' && /^(0|[1-9]\d*)$/.test(id) ? Number(id) : Number.NaN;
    if (
      !Number.isSafeInteger(sequence) ||
      sequence <= previousSequence ||
      sequence < source.first_sequence ||
      sequence > source.last_sequence
    )
      throw new Error('invalid source message');
    previousSequence = sequence;
    return { ...message, source_id: id as string };
  });
  if (source)
    return {
      format_version: 2,
      source,
      title: v['title'],
      messages: messages as AppThreadArchive['messages'],
    };
  return { format_version: 1, title: v['title'], messages };
}
