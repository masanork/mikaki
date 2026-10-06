<script lang="ts">
  import { onMount, setContext, tick } from 'svelte';
  import { restoreActionFocus } from './action-focus.js';
  import { vaultContext, OWNER_VAULT_CONTEXT, type OwnerVaultContext } from './vault-context.js';
  import ProductHeader from './ProductHeader.svelte';
  import AgentOAuth from './AgentOAuth.svelte';
  import * as m from './paraglide/messages.js';
  import type { Locale } from './paraglide/runtime.js';
  import { OwnerVaultController } from './vault-owner-controller.ts';
  import { OWNER_NOTE } from './vault-owner-record-store.ts';
  import OwnerRecordEditor from './OwnerRecordEditor.svelte';
  import OwnerPasskeys from './OwnerPasskeys.svelte';
  import OwnerNameSharing from './OwnerNameSharing.svelte';
  import OwnerNoteProposals from './OwnerNoteProposals.svelte';
  import OwnerAgentGrants from './OwnerAgentGrants.svelte';
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
    passkeysBusy = $state(false),
    wrapperUnconfirmed = $state(false),
    sharingUnconfirmed = $state(false),
    noteProposalUnconfirmed = $state(false),
    agentGrantUnconfirmed = $state(false),
    agentOAuthBusy = $state(false),
    status = $state('');
  const editingBlocked = $derived(
    busy ||
      agentOAuthBusy ||
      wrapperUnconfirmed ||
      sharingUnconfirmed ||
      noteProposalUnconfirmed ||
      agentGrantUnconfirmed,
  );
  let name = $state(''),
    savedName = $state(''),
    profileRevision = $state(0),
    noteRevision = $state(0),
    noteRefreshEpoch = $state(0),
    agentGrantRefreshEpoch = $state(0);
  let pending: PreparedOwnerWrite | null = $state(null);
  let query = $state('');
  let threads: { id: string; revision: number; archive: ThreadArchive }[] = $state([]);
  let selected = $state('');
  type AgentConnection = {
    grant_id: string;
    delegate: string;
    provider: string;
    active: number;
    operations: string;
    source_revision: number;
    storage_version: number;
    source_origin: string | null;
    resource: string;
    account_id: string;
    source_vault_id: string | null;
    source_collection_id: string | null;
    source_record_id: string | null;
    source_kind: string | null;
    source_ciphertext_sha256: string | null;
    source_key_generation: number | null;
    source_owner_key_revision: number | null;
  };
  let agentConnections: AgentConnection[] = $state([]);
  const hasAgentRequest = new URL(location.href).searchParams.has('agent_oauth_request');
  const dirty = $derived(pending !== null || name !== savedName);
  const visibleThreads = $derived(query.trim() ? [] : threads);
  const active = $derived(threads.find((t) => t.id === selected));
  async function reloadAgentConnections() {
    if (!hasAgentRequest) return;
    const response = await scope.request('/vault/agents/connections', { cache: 'no-store' });
    if (!response.ok) throw new Error('connections unavailable');
    const value: unknown = await response.json();
    if (typeof value !== 'object' || value === null || !Array.isArray(value.grants))
      throw new Error('invalid connections');
    agentConnections = value.grants as AgentConnection[];
  }
  async function agentGrantChanged() {
    agentGrantRefreshEpoch += 1;
    try {
      await reloadAgentConnections();
    } catch {
      if (!scope.signal.aborted) status = m.error();
    }
  }
  async function selectHit(hit: SearchHit) {
    try {
      if (!owner || editingBlocked) return;
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
    if (!opened || editingBlocked || !store) return;
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
    if (!store || editingBlocked || (dirty && !confirm(m.productProfileDiscard()))) return;
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
    if (!file || !store || editingBlocked || pending) return;
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
    if (!pending || !store || editingBlocked) return;
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
    if (!store || editingBlocked || pending || !confirm(m.ownerWorkspaceDeleteConfirm())) return;
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
        await reloadAgentConnections();
      })
      .catch(() => scope.end('unconfirmed'));
    const unregister = context.registerDraft(() => dirty || (busy && !passkeysBusy));
    const unregisterResume = context.registerResume(async () => {
      if (owner) await owner.resume();
    });
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
      sharingUnconfirmed = false;
      agentGrantUnconfirmed = false;
      agentConnections = [];
    };
    scope.signal.addEventListener('abort', clear, { once: true });
    const visibility = () => {
      if (document.visibilityState === 'hidden') owner?.suspend();
    };
    document.addEventListener('visibilitychange', visibility);
    return () => {
      clear();
      unregister();
      unregisterResume();
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
              disabled={editingBlocked || pending !== null}
              bind:value={name}
            />
            <div class="product-actions">
              <button
                id="save"
                class="product-primary"
                disabled={editingBlocked || pending !== null}
                onclick={save}>{m.vaultSave()}</button
              ><button id="reload-profile" disabled={editingBlocked} onclick={reload}
                >{m.productProfileReload()}</button
              >
            </div>
            {#if dirty}<p class="product-draft-status">
                {pending ? m.productUnfinishedOperation() : m.productUnsavedChanges()}
              </p>{/if}
            <button
              id="delete"
              class="product-danger"
              disabled={editingBlocked || pending !== null || !savedName}
              onclick={() => remove('personal', 'name', 'name', profileRevision)}
              >{m.vaultDelete()}</button
            >
          </section>
          <OwnerRecordEditor
            target={OWNER_NOTE}
            disabled={editingBlocked}
            refreshEpoch={noteRefreshEpoch}
            onheadchange={(revision) => (noteRevision = revision)}
          />
          {#if owner}
            <OwnerNoteProposals
              {owner}
              sourceRevision={noteRevision}
              disabled={busy ||
                agentOAuthBusy ||
                wrapperUnconfirmed ||
                sharingUnconfirmed ||
                agentGrantUnconfirmed}
              refreshEpoch={agentGrantRefreshEpoch}
              hasDrafts={() => dirty || (context.hasDrafts?.() ?? false)}
              onbusy={(value) => {
                passkeysBusy = value;
                busy = value;
              }}
              onunconfirmed={(value) => (noteProposalUnconfirmed = value)}
              onapplied={() => (noteRefreshEpoch += 1)}
            />
          {/if}
          {#if owner}
            <OwnerNameSharing
              {owner}
              sourceRevision={profileRevision}
              disabled={busy ||
                agentOAuthBusy ||
                wrapperUnconfirmed ||
                noteProposalUnconfirmed ||
                agentGrantUnconfirmed}
              hasDrafts={() => dirty || (context.hasDrafts?.() ?? false)}
              onbusy={(value) => {
                passkeysBusy = value;
                busy = value;
              }}
              onunconfirmed={(value) => (sharingUnconfirmed = value)}
            />
          {/if}
          {#if owner}
            <OwnerAgentGrants
              {owner}
              nameRevision={profileRevision}
              {noteRevision}
              disabled={busy ||
                agentOAuthBusy ||
                wrapperUnconfirmed ||
                sharingUnconfirmed ||
                noteProposalUnconfirmed}
              hasDrafts={() => dirty || (context.hasDrafts?.() ?? false)}
              onbusy={(value) => {
                passkeysBusy = value;
                busy = value;
              }}
              onunconfirmed={(value) => (agentGrantUnconfirmed = value)}
              onchanged={agentGrantChanged}
            />
          {/if}
          {#if owner}<OwnerPasskeys
              {owner}
              hasDrafts={() => context.hasDrafts?.() ?? false}
              disabled={busy ||
                agentOAuthBusy ||
                sharingUnconfirmed ||
                noteProposalUnconfirmed ||
                agentGrantUnconfirmed ||
                dirty ||
                (context.hasDrafts?.() ?? false)}
              onunconfirmed={(value) => (wrapperUnconfirmed = value)}
              onbusy={(value) => {
                passkeysBusy = value;
                busy = value;
              }}
            />{/if}
          <section id="threads" aria-labelledby="threads-heading" aria-busy={busy}>
            <h2 id="threads-heading">{m.ownerWorkspaceThreads()}</h2>
            <label for="archive-file">{m.ownerWorkspaceImport()}</label><input
              id="archive-file"
              type="file"
              accept="application/json,.json"
              disabled={editingBlocked || pending !== null}
              onchange={importArchive}
            />
            {#if owner}<ThreadSearch
                records={threads}
                {owner}
                disabled={editingBlocked}
                bind:query
                onselect={selectHit}
              />{/if}
            {#if threads.length === 0}<p>{m.ownerVaultEmpty()}</p>{/if}
            <div class="product-actions">
              {#each visibleThreads as thread (thread.id)}<button
                  disabled={editingBlocked}
                  onclick={() => (selected = thread.id)}>{thread.archive.title}</button
                >{/each}
            </div>
            {#if active}<article>
                <h3 id="thread-title" tabindex="-1">{active.archive.title}</h3>
                <button
                  class="product-danger"
                  disabled={editingBlocked || pending !== null}
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
          {#if pending}<button id="retry-write" disabled={editingBlocked} onclick={retry}
              >{m.ownerVaultRetrySave()}</button
            >{/if}
        </div>
      </div>
    {/if}
    {#if hasAgentRequest}
      <details id="connections" open>
        <summary>{m.agentOAuthHeading()}</summary>
        <AgentOAuth
          grants={agentConnections}
          disabled={busy ||
            wrapperUnconfirmed ||
            sharingUnconfirmed ||
            noteProposalUnconfirmed ||
            agentGrantUnconfirmed}
          onBusy={(value) => {
            agentOAuthBusy = value;
            passkeysBusy = value;
          }}
        />
      </details>
    {/if}
  </main>
</div>
