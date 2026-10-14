<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import * as m from './paraglide/messages.js';
  import type { OwnerVaultController } from './vault-owner-controller.ts';
  import { OwnerWorkspaceStore, type PreparedOwnerWrite } from './vault-owner-workspace-store.ts';
  import {
    parseWorkspaceSnapshot,
    WORKSPACE_COLLECTION,
    WORKSPACE_KIND,
    type WorkspaceSnapshot,
  } from './vault-workspace-snapshot.ts';
  import { WorkspaceHandoff } from './vault-workspace-handoff.ts';
  import { vaultContext } from './vault-context.ts';
  let {
    owner,
    disabled,
    onbusy,
  }: { owner: OwnerVaultController; disabled: boolean; onbusy: (value: boolean) => void } =
    $props();
  const context = vaultContext();
  const store = untrack(() => new OwnerWorkspaceStore(owner));
  const handoff = new WorkspaceHandoff(window.opener);
  let offer = $state(handoff.offer);
  let text = $state<string | null>(null),
    preview = $state<WorkspaceSnapshot | null>(null);
  let pending = $state<PreparedOwnerWrite | null>(null),
    busy = $state(false),
    status = $state(''),
    sent = $state(false);
  let entries: {
    id: string;
    revision: number;
    title: string;
    origin: string;
    capturedAt: string;
  }[] = $state([]);
  let cursor = $state(0);
  async function authority() {
    const token = owner.checkpoint();
    await owner.verifyAuthority();
    owner.assertCurrent(token);
    return token;
  }
  async function load() {
    if (disabled || busy) return;
    busy = true;
    onbusy(true);
    try {
      const token = await authority();
      const heads = (await store.list(WORKSPACE_COLLECTION)).filter(
        (h) => !h.deleted && h.kind === WORKSPACE_KIND,
      );
      const batch = heads.slice(cursor, cursor + 8);
      const found: typeof entries = [];
      for (const head of batch) {
        const record = await store.read(WORKSPACE_COLLECTION, head.record_id, WORKSPACE_KIND);
        if (!record.plaintext) continue;
        try {
          const snapshot = parseWorkspaceSnapshot(
            new TextDecoder('utf-8', { fatal: true }).decode(record.plaintext),
          );
          owner.assertCurrent(token);
          found.push({
            id: head.record_id,
            revision: record.revision,
            title: snapshot.title,
            ...snapshot.source,
          });
        } finally {
          record.plaintext.fill(0);
        }
      }
      owner.assertCurrent(token);
      entries = found;
      cursor = cursor + batch.length >= heads.length ? 0 : cursor + batch.length;
      status = entries.length ? '' : m.workspaceSnapshotEmpty();
    } catch {
      if (!owner.scope.signal.aborted) status = m.workspaceSnapshotReadFailed();
    } finally {
      busy = false;
      onbusy(false);
    }
  }
  async function choose(id: string, revision: number) {
    if (disabled || busy || sent) return;
    busy = true;
    onbusy(true);
    try {
      const token = await authority(),
        record = await store.read(WORKSPACE_COLLECTION, id, WORKSPACE_KIND);
      if (!record.plaintext) throw new Error('missing snapshot');
      try {
        if (record.revision !== revision) throw new Error('snapshot changed');
        const candidate = new TextDecoder('utf-8', { fatal: true }).decode(record.plaintext);
        const snapshot = parseWorkspaceSnapshot(candidate);
        owner.assertCurrent(token);
        text = candidate;
        preview = snapshot;
        status = '';
      } finally {
        record.plaintext.fill(0);
      }
    } catch {
      if (!owner.scope.signal.aborted) status = m.workspaceSnapshotReadFailed();
    } finally {
      busy = false;
      onbusy(false);
    }
  }
  async function save() {
    if (!text || disabled || busy) return;
    busy = true;
    onbusy(true);
    try {
      const token = await authority();
      if (!pending) {
        handoff.authorize('save');
        const bytes = new TextEncoder().encode(text);
        try {
          pending = await store.prepare(
            WORKSPACE_COLLECTION,
            crypto.randomUUID(),
            WORKSPACE_KIND,
            0,
            bytes,
          );
        } finally {
          bytes.fill(0);
        }
      }
      await store.commit(pending);
      owner.assertCurrent(token);
      pending = null;
      text = null;
      preview = null;
      handoff.saved();
      status = m.workspaceSnapshotSaved();
    } catch {
      if (!owner.scope.signal.aborted) status = m.appArchiveSaveFailed();
    } finally {
      busy = false;
      onbusy(false);
    }
  }
  async function restore() {
    if (!text || disabled || busy || sent) return;
    busy = true;
    onbusy(true);
    try {
      const token = await authority();
      owner.assertCurrent(token);
      handoff.restore(text);
      sent = true;
      text = null;
      preview = null;
      status = m.workspaceSnapshotSent();
    } catch {
      if (!owner.scope.signal.aborted) status = m.workspaceSnapshotInvalid();
    } finally {
      busy = false;
      onbusy(false);
    }
  }
  onMount(() => {
    const unregister = context.registerDraft(() => text !== null || pending !== null || busy);
    const receive = (event: MessageEvent) => {
      try {
        if (owner.scope.signal.aborted) return;
        owner.checkpoint();
        const result = handoff.receive(event);
        if (!result) return;
        offer = handoff.offer;
        if (result.text) {
          text = result.text;
          preview = parseWorkspaceSnapshot(text);
          status = '';
        }
        if (result.restored) status = m.workspaceSnapshotRestored();
      } catch {
        status = m.workspaceSnapshotInvalid();
      }
    };
    const clear = () => {
      handoff.dispose();
      text = null;
      preview = null;
      pending = null;
      entries = [];
      offer = null;
      status = '';
    };
    window.addEventListener('message', receive);
    owner.scope.signal.addEventListener('abort', clear, { once: true });
    return () => {
      clear();
      unregister();
      window.removeEventListener('message', receive);
      owner.scope.signal.removeEventListener('abort', clear);
    };
  });
</script>

<section aria-labelledby="workspace-snapshots-heading" aria-busy={busy}>
  <h2 id="workspace-snapshots-heading">{m.workspaceSnapshotHeading()}</h2>
  <p>{m.workspaceSnapshotBoundary()}</p>
  {#if offer?.mode === 'restore'}<p>
      {m.workspaceSnapshotDestination({ origin: offer.origin })}
    </p>{/if}
  {#if offer?.mode !== 'save' && !sent}
    <button id="workspace-snapshot-list" disabled={disabled || busy} onclick={load}
      >{m.workspaceSnapshotList()}</button
    >
    {#each entries as entry}<p>
        <button disabled={disabled || busy} onclick={() => choose(entry.id, entry.revision)}
          >{entry.title} — {entry.capturedAt}</button
        >
      </p>{/each}
  {/if}
  {#if preview}
    <h3>{preview.title}</h3>
    <p>{preview.source.origin} — {preview.source.capturedAt}</p>
    <p>
      {m.workspaceSnapshotPreview({
        gadgets: preview.gadgets.length,
        records: preview.records.length,
      })}
    </p>
    {#if offer?.mode === 'save'}
      <button id="workspace-snapshot-save" disabled={disabled || busy} onclick={save}
        >{pending ? m.ownerVaultRetrySave() : m.appArchiveSave()}</button
      >
    {:else if offer?.mode === 'restore' && preview.source.origin === offer.origin}
      <p>{m.workspaceSnapshotRestoreBoundary()}</p>
      <button id="workspace-snapshot-restore" disabled={disabled || busy || sent} onclick={restore}
        >{m.workspaceSnapshotRestore()}</button
      >
    {:else if offer?.mode === 'restore'}<p>{m.workspaceSnapshotWrongOrigin()}</p>{/if}
    {#if !pending}<button
        disabled={disabled || busy}
        onclick={() => {
          text = null;
          preview = null;
        }}>{m.workspaceSnapshotDismiss()}</button
      >{/if}
  {/if}
  {#if status}<p role="status">{status}</p>{/if}
</section>
