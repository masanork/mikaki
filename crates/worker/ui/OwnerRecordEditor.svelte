<script lang="ts">
  import { onMount, tick, untrack } from 'svelte';
  import { ownerVaultContext } from './vault-context.ts';
  import { restoreActionFocus } from './action-focus.ts';
  import {
    OwnerRecordStore,
    OwnerRecordError,
    type OwnerRecordTarget,
    type OwnerRecordHead,
    type PreparedOwnerMutation,
  } from './vault-owner-record-store.ts';
  import {
    decodeOwnerNote,
    encodeOwnerNote,
    newOwnerNote,
    ownerNoteInputError,
  } from './vault-note.ts';
  import * as m from './paraglide/messages.js';
  let { target }: { target: OwnerRecordTarget } = $props();
  const context = ownerVaultContext(),
    owner = context.current();
  const store = new OwnerRecordStore(
    owner,
    untrack(() => target),
  );
  const note = untrack(() => target.kind === 'owner_note');
  const prefix = note ? 'owner-note' : 'owner-profile';
  let mounted = false;
  let requestEpoch = 0;
  let head: OwnerRecordHead | null = $state.raw(null);
  let loaded = $state(false);
  let busy = $state(true);
  let value = $state('');
  let title = $state('');
  let original = $state('');
  let pending: PreparedOwnerMutation | null = $state.raw(null);
  let status = $state(m.vaultLoading());
  let invalid = $state<'name' | 'title' | 'text' | null>(null);
  const edited = $derived(JSON.stringify([title, value]));
  const dirty = $derived(pending !== null || (loaded && edited !== original));
  function assertCurrent(epoch: number, token: number): void {
    owner.assertCurrent(token);
    if (!mounted || epoch !== requestEpoch) throw new DOMException('Stale editor', 'AbortError');
  }
  async function load(): Promise<OwnerRecordHead> {
    const epoch = ++requestEpoch,
      token = owner.checkpoint();
    loaded = false;
    head = null;
    title = '';
    value = '';
    original = JSON.stringify(['', '']);
    const next = await store.read();
    let nextTitle = '',
      nextValue = '';
    if (next.record) {
      const bytes = await store.readPlaintext(next);
      try {
        if (note) {
          const document = decodeOwnerNote(bytes);
          nextTitle = document.title;
          nextValue = document.text;
        } else {
          nextValue = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
          if (!nextValue.length || nextValue.length > 256) throw new Error('invalid name');
        }
      } finally {
        bytes.fill(0);
      }
    }
    assertCurrent(epoch, token);
    head = next;
    title = nextTitle;
    value = nextValue;
    original = JSON.stringify([title, value]);
    invalid = null;
    loaded = true;
    status = next.deleted
      ? m.ownerVaultDeletedHead()
      : next.record
        ? m.ownerVaultLoaded()
        : m.ownerVaultEmpty();
    return next;
  }
  function failure(cause: unknown): string {
    if (
      cause instanceof OwnerRecordError &&
      ['revision_conflict', 'operation_id_reused', 'record_deleted'].includes(cause.code)
    )
      return m.ownerVaultConflict();
    return m.ownerVaultRecordFailed();
  }
  async function reload(): Promise<void> {
    if (busy || (dirty && !confirm(note ? m.productNoteDiscard() : m.productProfileDiscard())))
      return;
    const previousFocus = document.activeElement;
    busy = true;
    pending = null;
    try {
      await load();
    } catch (cause) {
      if (mounted) status = failure(cause);
    } finally {
      if (mounted) {
        busy = false;
        await restoreActionFocus(previousFocus, () => document.getElementById(`${prefix}-reload`));
      }
    }
  }
  async function mutate(method: 'PUT' | 'DELETE'): Promise<void> {
    if (
      busy ||
      !loaded ||
      !head ||
      (pending && pending.method !== method) ||
      (method === 'DELETE' && !head.record)
    )
      return;
    if (!pending) {
      if (
        method === 'DELETE' &&
        !confirm(note ? m.productNoteDeleteConfirm() : m.productProfileDeleteConfirm())
      )
        return;
      if (method === 'PUT') {
        invalid = note
          ? ownerNoteInputError(title, value)
          : value.length === 0 || value.length > 256 || !value.isWellFormed()
            ? 'name'
            : null;
        if (invalid) {
          await tick();
          document
            .getElementById(
              invalid === 'title' ? 'owner-note-title' : note ? 'owner-note-text' : 'owner-name',
            )
            ?.focus();
          return;
        }
        if (head.deleted && !confirm(m.ownerVaultRecreateConfirm())) return;
      }
    }
    const previousFocus = document.activeElement;
    busy = true;
    try {
      if (!pending) {
        const bytes =
          method === 'PUT'
            ? note
              ? encodeOwnerNote(newOwnerNote(title, value))
              : new TextEncoder().encode(value)
            : undefined;
        try {
          pending = await store.prepare(method, head.revision, bytes);
        } finally {
          bytes?.fill(0);
        }
      }
      const confirmed = await store.commit(pending);
      pending = null;
      try {
        const latest = await load();
        status =
          latest.revision !== confirmed.revision
            ? m.ownerVaultNewerHead()
            : method === 'DELETE'
              ? m.ownerVaultDeleted()
              : m.ownerVaultSaved();
      } catch {
        if (mounted) status = m.ownerVaultRefreshFailed();
      }
    } catch (cause) {
      if (mounted) status = failure(cause);
    } finally {
      if (mounted) {
        busy = false;
        await restoreActionFocus(previousFocus, () =>
          document.getElementById(
            `${prefix}-${loaded ? (pending?.method === 'DELETE' ? 'delete' : 'save') : 'reload'}`,
          ),
        );
      }
    }
  }
  onMount(() => {
    mounted = true;
    const unregister = context.registerDraft(() => dirty || busy);
    void load()
      .catch((cause: unknown) => {
        if (mounted) status = failure(cause);
      })
      .finally(() => {
        if (mounted) busy = false;
      });
    return () => {
      mounted = false;
      requestEpoch++;
      pending = null;
      head = null;
      title = '';
      value = '';
      original = '';
      unregister();
    };
  });
</script>

<section id={prefix} aria-labelledby={`${prefix}-heading`} aria-busy={busy}>
  <div class="product-section-top">
    <h2 id={`${prefix}-heading`}>{note ? m.vaultNoteHeading() : m.productProfile()}</h2>
    <span class="product-lock-state is-open">{m.productUnlocked()}</span>
  </div>
  <p>{note ? m.vaultNoteExplanation() : m.vaultIntro()}</p>
  {#if head?.deleted}<p>{m.ownerVaultDeletedHead()}</p>{/if}
  {#if note}
    <label for="owner-note-title">{m.vaultNoteTitle()}</label>
    <input
      id="owner-note-title"
      type="text"
      maxlength="256"
      disabled={busy || !loaded || pending !== null}
      bind:value={title}
      aria-invalid={invalid === 'title' || undefined}
      aria-describedby={`${prefix}-status`}
    />
    <label for="owner-note-text">{m.vaultNoteText()}</label>
    <textarea
      id="owner-note-text"
      rows="5"
      maxlength="4096"
      disabled={busy || !loaded || pending !== null}
      bind:value
      aria-invalid={invalid === 'text' || undefined}
      aria-describedby={`${prefix}-status`}></textarea>
  {:else}
    <label for="owner-name">{m.vaultName()}</label>
    <input
      id="owner-name"
      type="text"
      maxlength="256"
      autocomplete="name"
      disabled={busy || !loaded || pending !== null}
      bind:value
      aria-invalid={invalid === 'name' || undefined}
      aria-describedby={`${prefix}-status`}
    />
  {/if}
  <div class="product-actions">
    <button
      id={`${prefix}-save`}
      class="product-primary"
      type="button"
      disabled={busy || !loaded || pending?.method === 'DELETE'}
      onclick={() => mutate('PUT')}
      >{pending?.method === 'PUT'
        ? m.ownerVaultRetrySave()
        : head?.deleted
          ? m.ownerVaultRecreate()
          : note
            ? m.vaultNoteSave()
            : m.vaultSave()}</button
    >
    <button
      id={`${prefix}-delete`}
      class="product-danger"
      type="button"
      disabled={busy || !loaded || !head?.record || pending?.method === 'PUT'}
      onclick={() => mutate('DELETE')}
      >{pending?.method === 'DELETE'
        ? m.ownerVaultRetryDelete()
        : note
          ? m.vaultNoteDelete()
          : m.vaultDelete()}</button
    >
    <button id={`${prefix}-reload`} type="button" disabled={busy} onclick={reload}
      >{note ? m.vaultNoteReload() : m.productProfileReload()}</button
    >
  </div>
  {#if invalid}<p role="alert">
      {invalid === 'name'
        ? m.vaultInvalidName()
        : invalid === 'title'
          ? m.vaultNoteTitleInvalid()
          : m.vaultNoteTextInvalid()}
    </p>{/if}
  <p id={`${prefix}-status`} role="status" aria-live="polite">{status}</p>
  {#if dirty}<p class="product-draft-status" aria-live="polite">
      {pending ? m.productUnfinishedOperation() : m.productUnsavedChanges()}
    </p>{/if}
</section>
