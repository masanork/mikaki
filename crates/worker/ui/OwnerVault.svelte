<script lang="ts">
  import { onMount } from 'svelte';
  import { restoreActionFocus } from './action-focus.js';
  import { vaultContext } from './vault-context.js';
  import ProductHeader from './ProductHeader.svelte';
  import AgentPanel from './AgentPanel.svelte';
  import * as m from './paraglide/messages.js';
  import type { Locale } from './paraglide/runtime.js';
  import { openOwnerVault } from './vault-owner-store.ts';
  import type { OwnerKeySession, OwnerPrfEvaluator } from './vault-owner-session.ts';
  import { OwnerRecordStore, type PreparedOwnerWrite } from './vault-owner-record-store.ts';
  import { encodeBase64Url, decodeBase64Url } from './vault-crypto.ts';
  import { parseThreadArchive, type ThreadArchive } from './vault-thread-archive.ts';
  let { locale }: { locale: Locale } = $props();
  const context = vaultContext(),
    scope = context.current();
  let session: OwnerKeySession | null = null,
    store: OwnerRecordStore | null = null;
  let ownerId = $state(''),
    credentialId = $state<Uint8Array<ArrayBuffer> | null>(null),
    agentBusy = $state(false);
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
  const visibleThreads = $derived(
    threads.filter((t) =>
      `${t.archive.title}\n${t.archive.messages.map((x) => x.text).join('\n')}`
        .toLocaleLowerCase()
        .includes(query.toLocaleLowerCase()),
    ),
  );
  const active = $derived(threads.find((t) => t.id === selected));
  const evaluate: OwnerPrfEvaluator = async (id, input, signal) => {
    if (!window.PublicKeyCredential || !navigator.credentials)
      throw new Error(m.vaultUnsupported());
    const credential = await navigator.credentials.get({
      signal,
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ id, type: 'public-key' }],
        userVerification: 'required',
        timeout: 120000,
        extensions: { prf: { eval: { first: input } } },
      },
    });
    if (
      !(credential instanceof PublicKeyCredential) ||
      encodeBase64Url(new Uint8Array(credential.rawId)) !== encodeBase64Url(id)
    )
      throw new Error(m.vaultWrongCredential());
    const output = credential.getClientExtensionResults().prf?.results?.first;
    if (!(output instanceof ArrayBuffer) || output.byteLength !== 32)
      throw new Error(m.vaultPrfUnsupported());
    return { credentialId: new Uint8Array(credential.rawId), output: new Uint8Array(output) };
  };
  async function loadRecords() {
    if (!store) throw new Error('locked');
    const profile = await store.read('personal', 'profile', 'profile');
    try {
      const v: unknown = profile.plaintext
        ? JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(profile.plaintext))
        : { name: '' };
      if (
        !v ||
        typeof v !== 'object' ||
        !('name' in v) ||
        typeof v.name !== 'string' ||
        v.name.length > 256
      )
        throw new Error('invalid profile');
      name = savedName = v.name;
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
          : m.ownerVaultFailed();
  }
  async function unlock() {
    if (busy || opened) return;
    const previousFocus = document.activeElement;
    busy = true;
    try {
      await scope.verify();
      await scope.ensure();
      const result = await openOwnerVault(scope, location.origin, evaluate);
      session = result.session;
      store = new OwnerRecordStore(scope, session, result.stored);
      await loadRecords();
      opened = true;
      status = m.ownerVaultReady();
    } catch (error) {
      session?.dispose();
      session = null;
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
        const bytes = new TextEncoder().encode(JSON.stringify({ name }));
        try {
          pending = await store.prepare('personal', 'profile', 'profile', profileRevision, bytes);
        } finally {
          bytes.fill(0);
        }
      }
      await store.commit(pending);
      pending = null;
      await loadRecords();
      status = m.ownerVaultSaved();
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
      status = m.ownerVaultReady();
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
      status = m.ownerVaultSaved();
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
      status = m.ownerVaultSaved();
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
    if (!store || busy || pending || !confirm(m.ownerVaultDeleteConfirm())) return;
    const previousFocus = document.activeElement;
    busy = true;
    try {
      pending = await store.prepare(collection, id, kind, revision, null);
      await store.commit(pending);
      pending = null;
      await loadRecords();
      selected = '';
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
        ownerId = scope.identity.account_id;
        credentialId = decodeBase64Url(scope.identity.credential_id);
      })
      .catch(() => scope.end('unconfirmed'));
    const unregister = context.registerDraft(() => dirty || busy || agentBusy);
    const clear = () => {
      session?.dispose();
      session = null;
      store = null;
      opened = false;
      name = savedName = '';
      threads = [];
      query = '';
      selected = '';
      pending = null;
      ownerId = '';
      credentialId = null;
    };
    scope.signal.addEventListener('abort', clear, { once: true });
    const visibility = () => {
      if (document.visibilityState === 'hidden') session?.suspend();
      else if (session) void session.resume().catch(() => scope.end('unconfirmed'));
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
      <p>{m.ownerVaultHint()}</p>
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
          <a href="#profile">{m.productProfile()}</a><a href="#threads">{m.ownerVaultThreads()}</a
          ><a href="#connections">{m.productSharing()}</a>
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
              onclick={() => remove('personal', 'profile', 'profile', profileRevision)}
              >{m.vaultDelete()}</button
            >
          </section>
          <section id="threads" aria-labelledby="threads-heading" aria-busy={busy}>
            <h2 id="threads-heading">{m.ownerVaultThreads()}</h2>
            <p>{m.ownerVaultArchiveHint()}</p>
            <label for="archive-file">{m.ownerVaultImport()}</label><input
              id="archive-file"
              type="file"
              accept="application/json,.json"
              disabled={busy || pending !== null}
              onchange={importArchive}
            />
            <label for="thread-search">{m.ownerVaultSearch()}</label><input
              id="thread-search"
              type="search"
              bind:value={query}
              disabled={busy}
            />
            {#if threads.length === 0}<p>{m.ownerVaultEmpty()}</p>{/if}
            <div class="product-actions">
              {#each visibleThreads as thread (thread.id)}<button
                  onclick={() => (selected = thread.id)}>{thread.archive.title}</button
                >{/each}
            </div>
            {#if active}<article>
                <h3>{active.archive.title}</h3>
                <button
                  class="product-danger"
                  disabled={busy || pending !== null}
                  onclick={() =>
                    active && remove('threads', active.id, 'thread-archive', active.revision)}
                  >{m.vaultDelete()}</button
                >
                {#each active.archive.messages as message}<div class="archive-message">
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
              >{m.ownerVaultRetry()}</button
            >{/if}
        </div>
      </div>
    {/if}
    <div class="product-content">
      <details
        id="connections"
        class="product-details"
        open={new URL(location.href).searchParams.has('agent_oauth_request')}
      >
        <summary>{m.productSharing()}</summary>
        <p>{m.ownerVaultSharingPending()}</p>
        <AgentPanel
          {locale}
          onBusy={(value) => {
            agentBusy = value;
          }}
          opened={false}
          sourceRevision={0}
          noteRevision={0}
          {ownerId}
          {credentialId}
          loadName={async () => {
            throw new Error('not shared');
          }}
          evaluatePrf={async (id, input) => (await evaluate(id, input, scope.signal)).output}
        />
      </details>
    </div>
  </main>
</div>
