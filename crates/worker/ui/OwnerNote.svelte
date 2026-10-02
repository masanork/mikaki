<script lang="ts">
  import { vaultScope, vaultContext } from './vault-context.js';
  const context = vaultContext();
  const scope = vaultScope();
  const fetch = scope.request;
  import { onMount } from 'svelte';
  import PasskeyTransfer from './PasskeyTransfer.svelte';
  import {
    encodeBase64Url,
    newPrfInput,
    openAttribute,
    parseOwnerEnvelope,
    sealAttribute,
    type SealedAttribute,
  } from './vault-crypto.js';
  import {
    NOTE_ATTRIBUTE,
    NOTE_MAX_DOCUMENT_BYTES,
    decodeOwnerNote,
    encodeOwnerNote,
    newOwnerNote,
    type OwnerNote,
  } from './vault-note.js';
  import * as m from './paraglide/messages.js';

  let {
    credentialId,
    evaluatePrf,
    onSavedRevision = () => {},
    onBusy = () => {},
  }: {
    credentialId: Uint8Array<ArrayBuffer> | null;
    evaluatePrf: (
      credential: Uint8Array<ArrayBuffer>,
      input: Uint8Array<ArrayBuffer>,
    ) => Promise<Uint8Array<ArrayBuffer>>;
    onSavedRevision?: (revision: number) => void;
    onBusy?: (busy: boolean) => void;
  } = $props();
  type Saved = SealedAttribute & { revision: number };
  type Pending = {
    method: 'PUT' | 'DELETE';
    revision: number;
    value: string;
    id: string;
    body?: string;
  };
  let saved: Saved | null = $state(null);
  let revision = $state(0);
  let title = $state('');
  let body = $state('');
  let originalTitle = $state('');
  let originalBody = $state('');
  let opened = $state(false);
  let loaded = $state(false);
  let busy = $state(false);
  let transferBusy = $state(false);
  let transferGeneration = $state(0);
  $effect(() => {
    onBusy(busy || transferBusy);
    return () => onBusy(false);
  });
  let status = $state('');
  let disclosure = $state(false);
  let pending: Pending | null = $state(null);
  const dirty = $derived(
    pending !== null || (opened && (title !== originalTitle || body !== originalBody)),
  );
  const endpoint = `/vault/attributes/${NOTE_ATTRIBUTE}`;

  async function load() {
    onSavedRevision(0);
    loaded = false;
    opened = false;
    saved = null;
    revision = 0;
    title = '';
    body = '';
    originalTitle = '';
    originalBody = '';
    disclosure = false;
    const response = await fetch(endpoint, { cache: 'no-store' });
    const etag = response.headers.get('ETag');
    if (etag !== null) {
      const match = /^"([1-9][0-9]*)"$/.exec(etag);
      if (!match || !Number.isSafeInteger(Number(match[1])))
        throw new Error(m.vaultRevisionInvalid());
      revision = Number(match[1]);
    }
    if (response.status !== 404) {
      if (!response.ok) throw new Error(m.vaultReadFailed());
      const data: unknown = await response.json();
      if (
        typeof data !== 'object' ||
        data === null ||
        !('format_version' in data) ||
        data.format_version !== 1 ||
        !('revision' in data) ||
        data.revision !== revision ||
        !('ciphertext' in data) ||
        typeof data.ciphertext !== 'string' ||
        !('owner_envelope' in data) ||
        typeof data.owner_envelope !== 'string'
      )
        throw new Error(m.vaultRecordInvalid());
      saved = {
        format_version: 1,
        revision,
        ciphertext: data.ciphertext,
        owner_envelope: data.owner_envelope,
      };
    }
    loaded = true;
    onSavedRevision(saved ? revision : 0);
    status = saved ? m.vaultNoteLoaded() : m.vaultNoteMissing();
  }

  async function readSaved(): Promise<OwnerNote> {
    if (!saved) throw new Error(m.vaultNoteMissing());
    const snapshot = saved;
    const envelope = parseOwnerEnvelope(snapshot.owner_envelope);
    const output = await evaluatePrf(envelope.credentialId, envelope.prfInput);
    try {
      const bytes = await openAttribute(
        snapshot,
        output,
        envelope.credentialId,
        location.origin,
        NOTE_ATTRIBUTE,
        snapshot.revision,
      );
      try {
        return decodeOwnerNote(bytes);
      } finally {
        bytes.fill(0);
      }
    } finally {
      output.fill(0);
    }
  }

  async function unlock() {
    if (busy || transferBusy || !loaded || !credentialId) return;
    busy = true;
    try {
      if (saved) {
        const note = await readSaved();
        title = note.title;
        body = note.text;
      } else {
        const output = await evaluatePrf(credentialId, newPrfInput());
        output.fill(0);
      }
      originalTitle = title;
      originalBody = body;
      opened = true;
      status = m.vaultNoteReady();
    } catch {
      opened = false;
      status = m.vaultNoteInvalid();
    } finally {
      busy = false;
    }
  }

  async function mutate(method: 'PUT' | 'DELETE') {
    if (
      busy ||
      transferBusy ||
      !opened ||
      !loaded ||
      !credentialId ||
      (method === 'DELETE' && !saved)
    )
      return;
    if (method === 'DELETE' && !pending && !confirm(m.productNoteDeleteConfirm())) return;
    busy = true;
    try {
      const value =
        method === 'PUT'
          ? new TextDecoder().decode(encodeOwnerNote(newOwnerNote(title, body)))
          : '';
      if (
        pending &&
        (pending.method !== method || pending.revision !== revision || pending.value !== value)
      )
        throw new Error(m.vaultRetryChanged());
      if (!pending) {
        let encrypted: string | undefined;
        if (method === 'PUT') {
          const envelope = saved ? parseOwnerEnvelope(saved.owner_envelope) : null;
          const credential = envelope?.credentialId ?? credentialId;
          const input = envelope?.prfInput ?? newPrfInput();
          const output = await evaluatePrf(credential, input);
          const bytes = new TextEncoder().encode(value);
          try {
            encrypted = JSON.stringify(
              await sealAttribute(
                bytes,
                output,
                credential,
                input,
                location.origin,
                NOTE_ATTRIBUTE,
                revision + 1,
              ),
            );
          } finally {
            output.fill(0);
            bytes.fill(0);
          }
        }
        pending = {
          method,
          revision,
          value,
          id: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
          ...(encrypted === undefined ? {} : { body: encrypted }),
        };
      }
      const operation = pending;
      const response = await fetch(endpoint, {
        method: operation.method,
        headers: {
          'X-Operation-ID': operation.id,
          ...(operation.revision === 0
            ? { 'If-None-Match': '*' }
            : { 'If-Match': `"${operation.revision}"` }),
          ...(operation.method === 'PUT' ? { 'Content-Type': 'application/json' } : {}),
        },
        body: operation.body ?? null,
      });
      if (response.status === 409) throw new Error(m.vaultConflict());
      if (!response.ok) throw new Error(m.vaultWriteFailed());
      pending = null;
      try {
        await load();
      } catch {
        status = m.productNoteRefreshFailed();
        return;
      }
      status = method === 'PUT' ? m.vaultNoteSaved() : m.vaultNoteDeleted();
    } catch (error) {
      status =
        error instanceof Error && error.message === m.vaultRetryChanged()
          ? error.message
          : error instanceof Error && error.message === m.vaultConflict()
            ? error.message
            : method === 'DELETE'
              ? m.productDeleteFailed()
              : m.vaultNoteWriteFailed();
    } finally {
      busy = false;
    }
  }

  async function download() {
    if (busy || transferBusy || !opened || !saved || !disclosure) return;
    busy = true;
    let url: string | null = null;
    try {
      const note = await readSaved();
      const bytes = encodeOwnerNote(note);
      try {
        await scope.ensure();
        url = URL.createObjectURL(new Blob([bytes], { type: 'application/json' }));
      } finally {
        bytes.fill(0);
      }
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = 'mikaki-owner-note-v1.json';
      scope.assert();
      anchor.click();
      status = m.vaultNoteExported();
    } catch {
      status = m.vaultNoteInvalid();
    } finally {
      if (url) URL.revokeObjectURL(url);
      busy = false;
    }
  }

  async function importFile(file: File | undefined) {
    if (busy || transferBusy || !opened || pending || !file) return;
    busy = true;
    try {
      if (file.size > NOTE_MAX_DOCUMENT_BYTES) throw new Error('size');
      const bytes = new Uint8Array(await file.arrayBuffer());
      try {
        const note = decodeOwnerNote(bytes);
        title = note.title;
        body = note.text;
        status = m.vaultNoteImported();
      } finally {
        bytes.fill(0);
      }
    } catch {
      status = m.vaultNoteInvalidImport();
    } finally {
      busy = false;
    }
  }

  async function reload() {
    if (busy || transferBusy) return;
    if (dirty && !confirm(m.productNoteDiscard())) return;
    busy = true;
    pending = null;
    transferGeneration += 1;
    try {
      await load();
    } catch {
      status = m.vaultReadFailed();
    } finally {
      busy = false;
    }
  }
  onMount(() => {
    void reload();
    return context.registerDraft(() => dirty || (opened && busy));
  });
</script>

<section aria-label={m.vaultNoteHeading()}>
  <h2>{m.vaultNoteHeading()}</h2>
  <p>{m.vaultNoteExplanation()}</p>
  <button
    class="product-primary"
    type="button"
    disabled={busy || transferBusy || !loaded || opened || !credentialId}
    onclick={unlock}>{m.vaultNoteUnlock()}</button
  >
  <label
    >{m.vaultNoteTitle()}<input
      type="text"
      maxlength="256"
      disabled={busy || transferBusy || !opened || pending !== null}
      bind:value={title}
    /></label
  >
  <label
    >{m.vaultNoteText()}<textarea
      rows="5"
      maxlength="4096"
      disabled={busy || transferBusy || !opened || pending !== null}
      bind:value={body}></textarea></label
  >
  <button
    class="product-primary"
    type="button"
    disabled={busy || transferBusy || !opened || pending?.method === 'DELETE'}
    onclick={() => mutate('PUT')}>{m.vaultNoteSave()}</button
  >
  <button
    class="product-danger"
    type="button"
    disabled={busy || transferBusy || !opened || !saved || pending?.method === 'PUT'}
    onclick={() => mutate('DELETE')}>{m.vaultNoteDelete()}</button
  >
  <details class="product-details product-details-inline">
    <summary>{m.productNoteFiles()}</summary>
    <label
      >{m.vaultNoteImport()}<input
        type="file"
        accept="application/json,.json"
        disabled={busy || transferBusy || !opened || pending !== null}
        onchange={(event) => {
          void importFile(event.currentTarget.files?.[0]);
          event.currentTarget.value = '';
        }}
      /></label
    >
    <label
      ><input
        type="checkbox"
        bind:checked={disclosure}
        disabled={busy || transferBusy || !opened || !saved}
      />{m.vaultNoteDisclosure()}</label
    >
    <button
      type="button"
      disabled={busy || transferBusy || !opened || !saved || !disclosure}
      onclick={download}>{m.vaultNoteExport()}</button
    >
  </details>
  <button type="button" disabled={busy || transferBusy} onclick={reload}
    >{m.vaultNoteReload()}</button
  >
  {#if dirty}<p class="product-draft-status" data-draft-state="note" aria-live="polite">
      {pending ? m.productUnfinishedOperation() : m.productUnsavedChanges()}
    </p>{/if}
  <p role="status">{status}</p>
</section>

<details class="product-details">
  <summary>{m.productNotePasskey()}</summary>
  <div class="product-content">
    {#key transferGeneration}
      <PasskeyTransfer
        attribute="owner_note"
        {saved}
        {opened}
        {evaluatePrf}
        disabled={busy || pending !== null}
        onBusy={(value) => {
          transferBusy = value;
        }}
        changed={load}
        beforeTransfer={() => !dirty || confirm(m.productTransferDiscard())}
      />
    {/key}
  </div>
</details>
