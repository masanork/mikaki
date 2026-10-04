<script lang="ts">
  import { onMount, setContext, tick } from 'svelte';
  import { restoreActionFocus } from './action-focus.js';
  import { vaultContext, OWNER_VAULT_CONTEXT, type OwnerVaultContext } from './vault-context.js';
  import ProductHeader from './ProductHeader.svelte';
  import * as m from './paraglide/messages.js';
  import type { Locale } from './paraglide/runtime.js';
  import { OwnerVaultController } from './vault-owner-controller.ts';
  import { OWNER_NOTE } from './vault-owner-record-store.ts';
  import OwnerRecordEditor from './OwnerRecordEditor.svelte';
  import { OwnerWorkspaceStore, type PreparedOwnerWrite } from './vault-owner-workspace-store.ts';
  import { encodeBase64Url } from './vault-crypto.ts';
  import { parseThreadArchive, type ThreadArchive } from './vault-thread-archive.ts';
  import ThreadSearch from './ThreadSearch.svelte';
  import type { SearchHit } from './vault-thread-search.ts';
  let { locale }: { locale: Locale } = $props();
  const context = vaultContext(),
    scope = context.current();
  let owner: OwnerVaultController | null = $state(null);
  let store: OwnerWorkspaceStore | null = null;
  setContext<OwnerVaultContext>(OWNER_VAULT_CONTEXT, {
    current: () => {
      if (!owner) throw new Error('owner_key_locked');
      return owner;
    },
    registerDraft: context.registerDraft,
    lock: context.lock,
  });
  let opened = $state(false),
    busy = $state(false),
    status = $state('');
  let name = $state(''),
    savedName = $state(''),
    profileRevision = $state(0);
  let pending: PreparedOwnerWrite | null = $state(null);
  let query = $state('');
  let threads: { id: string; revision: number; archive: ThreadArchive }[] = $state([]);
  let selected = $state('');
  const dirty = $derived(pending !== null || name !== savedName);
  const visibleThreads = $derived(query.trim() ? [] : threads);
  const active = $derived(threads.find((t) => t.id === selected));
  async function selectHit(hit: SearchHit) {
    try {
      if (!owner || busy) return;
      const token = owner.checkpoint();
      await owner.verifyAuthority();
      owner.assertCurrent(token);
      if (!threads.some((thread) => thread.id === hit.thread && thread.revision === hit.revision))
        return;
      selected = hit.thread;
      await tick();
      owner.assertCurrent(token);
      document
        .getElementById(hit.message < 0 ? 'thread-title' : `thread-message-${hit.message}`)
        ?.focus();
    } catch (error) {
      failure(error);
    }
  }
  async function loadRecords() {
    if (!store) throw new Error('locked');
    const profile = await store.read('personal', 'name', 'name');
    try {
      const value = profile.plaintext
        ? new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(profile.plaintext)
        : '';
      if (profile.plaintext && (!value.length || value.length > 256))
        throw new Error('invalid name');
      name = savedName = value;
      profileRevision = profile.revision;
    } finally {
      profile.plaintext?.fill(0);
    }
    const next: typeof threads = [];
    for (const head of await store.list('threads')) {
      if (head.deleted) continue;
      if (head.kind !== 'thread-archive') throw new Error('unsupported archive');
      const record = await store.read('threads', head.record_id, head.kind);
      try {
        if (!record.plaintext) continue;
        next.push({
          id: head.record_id,
          revision: record.revision,
          archive: parseThreadArchive(
            JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(record.plaintext)),
          ),
        });
      } finally {
        record.plaintext?.fill(0);
      }
    }
    scope.assert();
    threads = next;
  }
  function failure(error: unknown) {
    status =
      error instanceof DOMException && error.name === 'NotAllowedError'
        ? m.productPasskeyCancelled()
        : error instanceof Error &&
            [m.vaultUnsupported(), m.vaultWrongCredential(), m.vaultPrfUnsupported()].includes(
              error.message,
            )
          ? error.message
          : m.error();
  }
  async function unlock() {
    if (busy || opened) return;
    const previousFocus = document.activeElement;
    busy = true;
    try {
      await scope.verify();
      await scope.ensure();
      owner = new OwnerVaultController(scope, location.origin);
      await owner.open();
      store = new OwnerWorkspaceStore(owner);
      await loadRecords();
      opened = true;
      status = m.productUnlocked();
    } catch (error) {
      owner?.dispose();
      owner = null;
      store = null;
      name = savedName = '';
      threads = [];
      failure(error);
    } finally {
      busy = false;
      if (!scope.signal.aborted)
        await restoreActionFocus(previousFocus, () =>
          document.getElementById(opened ? 'name' : 'unlock'),
        );
    }
  }
  async function save() {
    if (!opened || busy || !store) return;
    if (!pending && (!name.trim() || name.length > 256)) {
      status = m.vaultInvalidName();
      return;
    }
    const previousFocus = document.activeElement;
    busy = true;
    try {
      if (!pending) {
        const bytes = new TextEncoder().encode(name);
        try {
          pending = await store.prepare('personal', 'name', 'name', profileRevision, bytes);
        } finally {
          bytes.fill(0);
        }
      }
      await store.commit(pending);
      pending = null;
      await loadRecords();
      status = m.ownerWorkspaceSaved();
    } catch (error) {
      failure(error);
    } finally {
      busy = false;
      if (!scope.signal.aborted)
        await restoreActionFocus(previousFocus, () =>
          document.getElementById(pending ? 'retry-write' : 'save'),
        );
    }
  }
  async function reload() {
    if (!store || busy || (dirty && !confirm(m.productProfileDiscard()))) return;
    const previousFocus = document.activeElement;
    busy = true;
    try {
      await loadRecords();
      pending = null;
      status = m.productUnlocked();
    } catch (error) {
      failure(error);
    } finally {
      busy = false;
      if (!scope.signal.aborted)
        await restoreActionFocus(previousFocus, () => document.getElementById('reload-profile'));
    }
  }
  async function importArchive(event: Event) {
    const input = event.currentTarget as HTMLInputElement,
      file = input.files?.[0];
    input.value = '';
    if (!file || !store || busy || pending) return;
    const previousFocus = document.activeElement;
    busy = true;
    try {
      if (file.size > 24000) throw new Error('archive too large');
      const archive = parseThreadArchive(JSON.parse(await file.text()));
      const bytes = new TextEncoder().encode(JSON.stringify(archive));
      try {
        pending = await store.prepare(
          'threads',
          encodeBase64Url(crypto.getRandomValues(new Uint8Array(24))),
          'thread-archive',
          0,
          bytes,
        );
      } finally {
        bytes.fill(0);
      }
      await store.commit(pending);
      pending = null;
      await loadRecords();
      status = m.ownerWorkspaceSaved();
    } catch (error) {
      failure(error);
    } finally {
      busy = false;
      if (!scope.signal.aborted)
        await restoreActionFocus(previousFocus, () =>
          document.getElementById(pending ? 'retry-write' : 'archive-file'),
        );
    }
  }
  async function retry() {
    if (!pending || !store || busy) return;
    const previousFocus = document.activeElement;
    busy = true;
    try {
      await store.commit(pending);
      pending = null;
      await loadRecords();
      status = m.ownerWorkspaceSaved();
    } catch (error) {
      failure(error);
    } finally {
      busy = false;
      if (!scope.signal.aborted)
        await restoreActionFocus(previousFocus, () =>
          document.getElementById(pending ? 'retry-write' : 'save'),
        );
    }
  }
  async function remove(collection: string, id: string, kind: string, revision: number) {
    if (!store || busy || pending || !confirm(m.ownerWorkspaceDeleteConfirm())) return;
    const previousFocus = document.activeElement;
    busy = true;
    try {
      pending = await store.prepare(collection, id, kind, revision, null);
      await store.commit(pending);
      pending = null;
      await loadRecords();
      selected = '';
      if (collection === 'threads') query = '';
      status = m.vaultDeleted();
    } catch (error) {
      failure(error);
    } finally {
      busy = false;
      if (!scope.signal.aborted)
        await restoreActionFocus(previousFocus, () =>
          document.getElementById(pending ? 'retry-write' : 'name'),
        );
    }
  }
  onMount(() => {
    void scope
      .verify()
      .then(async () => {
        await scope.ensure();
        if (!scope.identity) throw new Error('unconfirmed');
      })
      .catch(() => scope.end('unconfirmed'));
    const unregister = context.registerDraft(() => dirty || busy);
    const clear = () => {
      owner?.dispose();
      owner = null;
      store = null;
      opened = false;
      name = savedName = '';
      threads = [];
      query = '';
      selected = '';
      pending = null;
    };
    scope.signal.addEventListener('abort', clear, { once: true });
    const visibility = () => {
      if (document.visibilityState === 'hidden') owner?.suspend();
      else if (owner) void owner.resume().catch(() => scope.end('unconfirmed'));
    };
    document.addEventListener('visibilitychange', visibility);
    return () => {
      clear();
      unregister();
      scope.signal.removeEventListener('abort', clear);
      document.removeEventListener('visibilitychange', visibility);
    };
  });
</script>

<div class="vault-shell">
  <ProductHeader {locale} onlock={context.lock} material paused={busy} />
  <main id="product-main" tabindex="-1" class="product-main">
    <div class="product-heading">
      <h1>{m.vaultHeading()}</h1>
    </div>
    {#if !opened}
      <section class="product-result" aria-busy={busy}>
        <button id="unlock" class="product-primary" disabled={busy} onclick={unlock}
          >{m.vaultUnlock()}</button
        >
        <p role="status">{status}</p>
      </section>
    {:else}
      <div class="product-workspace">
        <nav class="product-nav" aria-label={m.vaultHeading()}>
          <a href="#profile">{m.productProfile()}</a><a href="#owner-note">{m.vaultNoteHeading()}</a
          ><a href="#threads">{m.ownerWorkspaceThreads()}</a>
        </nav>
        <div class="product-content">
          <section id="profile" aria-labelledby="profile-heading" aria-busy={busy}>
            <div class="product-section-top">
              <h2 id="profile-heading">{m.productProfile()}</h2>
              <span class="product-lock-state is-open">{m.productUnlocked()}</span>
            </div>
            <label for="name">{m.vaultName()}</label><input
              id="name"
              autocomplete="name"
              maxlength="256"
              disabled={busy || pending !== null}
              bind:value={name}
            />
            <div class="product-actions">
              <button
                id="save"
                class="product-primary"
                disabled={busy || pending !== null}
                onclick={save}>{m.vaultSave()}</button
              ><button id="reload-profile" disabled={busy} onclick={reload}
                >{m.productProfileReload()}</button
              >
            </div>
            {#if dirty}<p class="product-draft-status">
                {pending ? m.productUnfinishedOperation() : m.productUnsavedChanges()}
              </p>{/if}
            <button
              id="delete"
              class="product-danger"
              disabled={busy || pending !== null || !savedName}
              onclick={() => remove('personal', 'name', 'name', profileRevision)}
              >{m.vaultDelete()}</button
            >
          </section>
          <OwnerRecordEditor target={OWNER_NOTE} />
          <section id="threads" aria-labelledby="threads-heading" aria-busy={busy}>
            <h2 id="threads-heading">{m.ownerWorkspaceThreads()}</h2>
            <label for="archive-file">{m.ownerWorkspaceImport()}</label><input
              id="archive-file"
              type="file"
              accept="application/json,.json"
              disabled={busy || pending !== null}
              onchange={importArchive}
            />
            {#if owner}<ThreadSearch
                records={threads}
                {owner}
                disabled={busy}
                bind:query
                onselect={selectHit}
              />{/if}
            {#if threads.length === 0}<p>{m.ownerVaultEmpty()}</p>{/if}
            <div class="product-actions">
              {#each visibleThreads as thread (thread.id)}<button
                  onclick={() => (selected = thread.id)}>{thread.archive.title}</button
                >{/each}
            </div>
            {#if active}<article>
                <h3 id="thread-title" tabindex="-1">{active.archive.title}</h3>
                <button
                  class="product-danger"
                  disabled={busy || pending !== null}
                  onclick={() =>
                    active && remove('threads', active.id, 'thread-archive', active.revision)}
                  >{m.vaultDelete()}</button
                >
                {#each active.archive.messages as message, index}<div
                    class="archive-message"
                    id={`thread-message-${index}`}
                    tabindex="-1"
                  >
                    <strong>{message.speaker}{message.actor === 'ai' ? ' · AI' : ''}</strong><time
                      datetime={message.timestamp}
                      >{new Date(message.timestamp).toLocaleString(locale)}</time
                    >
                    <p>{message.text}</p>
                  </div>{/each}
              </article>{/if}
          </section>
          <p id="status" role="status" aria-live="polite">{status}</p>
          {#if pending}<button id="retry-write" disabled={busy} onclick={retry}
              >{m.ownerVaultRetrySave()}</button
            >{/if}
        </div>
      </div>
    {/if}
  </main>
</div>
