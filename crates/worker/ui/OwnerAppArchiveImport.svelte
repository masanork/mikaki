<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import * as m from './paraglide/messages.js';
  import type { OwnerVaultController } from './vault-owner-controller.ts';
  import { OwnerWorkspaceStore, type PreparedOwnerWrite } from './vault-owner-workspace-store.ts';
  import { AppArchiveHandoff } from './vault-app-archive-handoff.ts';
  import type { AppThreadArchive } from './vault-thread-archive.ts';
  import { vaultContext } from './vault-context.ts';
  const context = vaultContext();
  let {
    owner,
    disabled,
    onbusy,
    onchanged,
  }: {
    owner: OwnerVaultController;
    disabled: boolean;
    onbusy: (value: boolean) => void;
    onchanged: () => Promise<void>;
  } = $props();
  const handoff = new AppArchiveHandoff(window.opener);
  const store = untrack(() => new OwnerWorkspaceStore(owner));
  let archive: AppThreadArchive | null = $state(null);
  let pending: PreparedOwnerWrite | null = $state(null);
  let saving = $state(false),
    status = $state('');
  async function save() {
    if (!archive || disabled || saving) return;
    saving = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.verifyAuthority();
      owner.assertCurrent(token);
      if (!pending) {
        handoff.authorizeSave();
        const bytes = new TextEncoder().encode(JSON.stringify(archive));
        try {
          pending = await store.prepare('threads', crypto.randomUUID(), 'thread-archive', 0, bytes);
        } finally {
          bytes.fill(0);
        }
      }
      await store.commit(pending);
      owner.assertCurrent(token);
      pending = null;
      archive = null;
      handoff.saved();
      status = m.ownerWorkspaceSaved();
      try {
        await onchanged();
      } catch {
        status = m.appArchiveSavedReloadFailed();
      }
    } catch {
      if (!owner.scope.signal.aborted) status = m.appArchiveSaveFailed();
    } finally {
      saving = false;
      onbusy(false);
    }
  }
  onMount(() => {
    const unregister = context.registerDraft(() => archive !== null || pending !== null || saving);
    const receive = (event: MessageEvent) => {
      try {
        if (owner.scope.signal.aborted) return;
        owner.checkpoint();
        const candidate = handoff.receive(event);
        if (candidate) {
          archive = candidate;
          status = '';
        }
      } catch {
        status = m.appArchiveInvalid();
      }
    };
    const clear = () => {
      handoff.dispose();
      archive = null;
      pending = null;
      status = '';
    };
    window.addEventListener('message', receive);
    owner.scope.signal.addEventListener('abort', clear, { once: true });
    return () => {
      clear();
      window.removeEventListener('message', receive);
      unregister();
      owner.scope.signal.removeEventListener('abort', clear);
    };
  });
</script>

{#if archive}
  <section aria-labelledby="app-archive-title" aria-busy={saving}>
    <h3 id="app-archive-title">{m.appArchiveHeading()}</h3>
    <p>{archive.source.origin}</p>
    <p>{m.appArchiveBoundary()}</p>
    <h4>{archive.title}</h4>
    <details>
      <summary>{m.appArchivePreview({ count: archive.messages.length })}</summary>
      {#each archive.messages as message}<p>
          <strong>{message.speaker}</strong>: {message.text}
        </p>{/each}
    </details>
    <button id="app-archive-save" disabled={disabled || saving} onclick={save}>
      {pending ? m.ownerVaultRetrySave() : m.appArchiveSave()}
    </button>
  </section>
{/if}
{#if status}<p role="status">{status}</p>{/if}
