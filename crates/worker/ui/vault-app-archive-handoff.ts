import {
  archiveAppOrigin,
  parseThreadArchive,
  type AppThreadArchive,
} from './vault-thread-archive.ts';

export const ARCHIVE_HANDOFF_PROTOCOL = 'mikaki-archive-v1';
const channelId = (value: unknown): value is string =>
  typeof value === 'string' &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
type Peer = { postMessage(value: unknown, origin: string): void };
type Offer = { channel: string; origin: string; expires: number };

// A browser handoff authenticates the sending window/origin, not individual speakers.
// Nothing in this class writes a record or returns a Vault credential to the source app.
export class AppArchiveHandoff {
  private offer: Offer | null = null;
  private received = false;
  private disposed = false;
  private readonly opener: Peer | null;
  private readonly now: () => number;
  constructor(opener: Peer | null, now: () => number = Date.now) {
    this.opener = opener;
    this.now = now;
  }

  receive(event: { source: unknown; origin: string; data: unknown }): AppThreadArchive | null {
    if (
      this.disposed ||
      !this.opener ||
      event.source !== this.opener ||
      !archiveAppOrigin(event.origin)
    )
      return null;
    const data = event.data;
    if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
    const v = data as Record<string, unknown>;
    if (v['protocol'] !== ARCHIVE_HANDOFF_PROTOCOL || !channelId(v['channel'])) return null;
    if (this.offer && this.now() >= this.offer.expires) {
      this.dispose();
      return null;
    }
    if (v['type'] === 'offer' && !this.offer) {
      this.offer = { channel: v['channel'], origin: event.origin, expires: this.now() + 300_000 };
      this.opener.postMessage(
        { protocol: ARCHIVE_HANDOFF_PROTOCOL, type: 'request', channel: v['channel'] },
        event.origin,
      );
      return null;
    }
    if (
      v['type'] !== 'archive' ||
      !this.offer ||
      this.received ||
      v['channel'] !== this.offer.channel ||
      event.origin !== this.offer.origin
    )
      return null;
    if (
      typeof v['archive'] !== 'string' ||
      v['archive'].length > 24000 ||
      new TextEncoder().encode(v['archive']).length > 24000
    )
      throw new Error('invalid archive size');
    const archive = parseThreadArchive(JSON.parse(v['archive']));
    if (archive.format_version !== 2 || archive.source.origin !== event.origin)
      throw new Error('archive source mismatch');
    this.received = true;
    return archive;
  }
  saved(): void {
    if (!this.disposed && this.offer && this.received)
      this.opener?.postMessage(
        { protocol: ARCHIVE_HANDOFF_PROTOCOL, type: 'saved', channel: this.offer.channel },
        this.offer.origin,
      );
  }
  authorizeSave(): void {
    if (this.disposed || !this.offer || !this.received || this.now() >= this.offer.expires)
      throw new Error('archive handoff expired');
  }
  dispose(): void {
    this.disposed = true;
    this.offer = null;
  }
}
