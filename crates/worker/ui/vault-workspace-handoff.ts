import { archiveAppOrigin } from './vault-thread-archive.ts';
import { parseWorkspaceSnapshot } from './vault-workspace-snapshot.ts';
export const WORKSPACE_PROTOCOL = 'mikaki-workspace-v1';
type Peer = { postMessage(value: unknown, origin: string): void };
type Offer = Readonly<{
  channel: string;
  origin: string;
  mode: 'save' | 'restore';
  expires: number;
}>;
export class WorkspaceHandoff {
  private current: Offer | null = null;
  private received = false;
  private sent = false;
  private disposed = false;
  private readonly opener: Peer | null;
  private readonly now: () => number;
  constructor(opener: Peer | null, now = Date.now) {
    this.opener = opener;
    this.now = now;
  }
  get offer(): Offer | null {
    return this.current;
  }
  receive(event: {
    source: unknown;
    origin: string;
    data: unknown;
  }): { text?: string; restored?: boolean } | null {
    if (
      this.disposed ||
      !this.opener ||
      event.source !== this.opener ||
      !archiveAppOrigin(event.origin)
    )
      return null;
    const v = event.data as Record<string, unknown> | null;
    if (
      !v ||
      typeof v !== 'object' ||
      v['protocol'] !== WORKSPACE_PROTOCOL ||
      typeof v['channel'] !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v['channel'])
    )
      return null;
    if (this.current && this.now() >= this.current.expires) {
      this.dispose();
      throw new Error('handoff expired');
    }
    if (
      v['type'] === 'offer' &&
      !this.current &&
      (v['mode'] === 'save' || v['mode'] === 'restore')
    ) {
      this.current = {
        channel: v['channel'],
        origin: event.origin,
        mode: v['mode'],
        expires: this.now() + 300_000,
      };
      if (v['mode'] === 'save') this.post('request');
      return {};
    }
    if (
      !this.current ||
      v['channel'] !== this.current.channel ||
      event.origin !== this.current.origin
    )
      return null;
    if (v['type'] === 'snapshot' && this.current.mode === 'save' && !this.received) {
      if (
        typeof v['snapshot'] !== 'string' ||
        parseWorkspaceSnapshot(v['snapshot']).source.origin !== event.origin
      )
        throw new Error('snapshot source mismatch');
      this.received = true;
      return { text: v['snapshot'] };
    }
    if (v['type'] === 'restored' && this.current.mode === 'restore' && this.sent)
      return { restored: true };
    return null;
  }
  authorize(mode: 'save' | 'restore'): void {
    if (
      this.disposed ||
      !this.current ||
      this.current.mode !== mode ||
      this.now() >= this.current.expires ||
      (mode === 'save' && !this.received)
    )
      throw new Error('handoff expired');
  }
  saved(): void {
    if (!this.disposed && this.current?.mode === 'save' && this.received) this.post('saved');
  }
  restore(text: string): void {
    this.authorize('restore');
    if (this.sent || parseWorkspaceSnapshot(text).source.origin !== this.current!.origin)
      throw new Error('restore source mismatch');
    this.sent = true;
    this.post('snapshot', { snapshot: text });
  }
  private post(type: string, extra: Record<string, unknown> = {}): void {
    if (this.current)
      this.opener?.postMessage(
        { protocol: WORKSPACE_PROTOCOL, type, channel: this.current.channel, ...extra },
        this.current.origin,
      );
  }
  dispose(): void {
    this.disposed = true;
    this.current = null;
  }
}
