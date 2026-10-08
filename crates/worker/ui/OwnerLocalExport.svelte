<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { restoreActionFocus } from './action-focus.ts';
  import * as m from './paraglide/messages.js';
  import type { OwnerVaultController } from './vault-owner-controller.ts';
  import {
    OwnerRecordDisclosure,
    type DisclosureRecord,
    type PreparedLocalRecordExport,
  } from './vault-owner-disclosure.ts';

  let {
    owner,
    nameRevision,
    noteRevision,
    disabled,
    hasDrafts,
    onbusy,
  }: {
    owner: OwnerVaultController;
    nameRevision: number;
    noteRevision: number;
    disabled: boolean;
    hasDrafts: () => boolean;
    onbusy: (value: boolean) => void;
  } = $props();

  const disclosure = untrack(() => new OwnerRecordDisclosure(owner));
  let expanded = $state(false);
  let loading = $state(false);
  let selection = $state<DisclosureRecord>('name');
  let delegate = $state('');
  let service = $state('');
  let lifetime = $state(86400);
  let consent = $state(false);
  let prepared = $state.raw<PreparedLocalRecordExport | null>(null);
  let status = $state('');
  let prepareGeneration = 0;
  let observedNameRevision = untrack(() => nameRevision);
  let observedNoteRevision = untrack(() => noteRevision);

  $effect(() => {
    const currentName = nameRevision;
    const currentNote = noteRevision;
    if (
      currentName === untrack(() => observedNameRevision) &&
      currentNote === untrack(() => observedNoteRevision)
    )
      return;
    observedNameRevision = currentName;
    observedNoteRevision = currentNote;
    prepareGeneration++;
    loading = false;
    onbusy(false);
    prepared = null;
    consent = false;
    status = m.ownerLocalExportSourceChanged();
  });

  const delegateValid = $derived(/^[A-Za-z0-9_-]{1,80}$/.test(delegate));
  const serviceValid = $derived(!!service.trim() && service.length <= 160);
  const canPrepare = $derived(!disabled && !loading && !prepared && delegateValid && serviceValid);

  function isCurrentPrepare(generation: number): boolean {
    const details = document.getElementById('owner-local-export');
    return (
      generation === prepareGeneration &&
      details instanceof HTMLDetailsElement &&
      details.open &&
      !owner.scope.signal.aborted
    );
  }

  function messageFor(error: unknown): string {
    if (error instanceof Error && error.message === 'owner_unsaved_changes')
      return m.productUnsavedChanges();
    if (owner.scope.signal.aborted) return '';
    return m.ownerLocalExportFailed();
  }

  async function prepare() {
    if (!canPrepare) return;
    if (hasDrafts()) {
      status = m.productUnsavedChanges();
      return;
    }
    const focus = document.activeElement;
    const generation = ++prepareGeneration;
    const selectedRecord = selection;
    const selectedDelegate = delegate;
    const selectedService = service.trim();
    const selectedLifetime = lifetime;
    loading = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.verifyAuthority();
      if (!isCurrentPrepare(generation)) return;
      owner.assertCurrent(token);
      const result = await disclosure.prepareLocalExport([selectedRecord], {
        delegate: selectedDelegate,
        service: selectedService,
        ttl: selectedLifetime,
      });
      if (!isCurrentPrepare(generation)) return;
      owner.assertCurrent(token);
      if (hasDrafts()) throw new Error('owner_unsaved_changes');
      prepared = result;
      consent = false;
      status = m.ownerLocalExportPrepared();
    } catch (error) {
      if (generation === prepareGeneration) {
        prepared = null;
        status = messageFor(error);
      }
    } finally {
      if (generation === prepareGeneration) {
        loading = false;
        onbusy(false);
      }
      if (isCurrentPrepare(generation))
        await restoreActionFocus(focus, () =>
          document.getElementById(
            prepared ? 'owner-local-export-download-bundle' : 'owner-local-export-prepare',
          ),
        );
    }
  }

  function download(kind: 'bundle' | 'grant') {
    if (!prepared || owner.scope.signal.aborted) return;
    const content = kind === 'bundle' ? prepared.bundle : prepared.grant;
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `mikaki-v2-${kind}-${prepared.id}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    status =
      kind === 'bundle'
        ? m.ownerLocalExportBundleDownloaded()
        : m.ownerLocalExportGrantDownloaded();
  }

  function clear() {
    prepareGeneration++;
    loading = false;
    onbusy(false);
    prepared = null;
    consent = false;
    status = '';
  }

  function toggle(event: Event) {
    expanded = (event.currentTarget as HTMLDetailsElement).open;
    if (!expanded) clear();
  }

  function beforeToggle(event: ToggleEvent) {
    if (event.newState === 'closed') clear();
  }

  function onSummaryClick() {
    // The native details toggle event is queued; invalidate sensitive work in
    // the activation handler so a late prepare cannot win that event race.
    clear();
  }

  onMount(() => {
    const clearOnLock = () => {
      clear();
      selection = 'name';
      delegate = '';
      service = '';
      loading = false;
      onbusy(false);
    };
    owner.scope.signal.addEventListener('abort', clearOnLock, { once: true });
    return () => {
      clearOnLock();
      owner.scope.signal.removeEventListener('abort', clearOnLock);
    };
  });
</script>

<details
  id="owner-local-export"
  aria-busy={loading}
  onbeforetoggle={beforeToggle}
  ontoggle={toggle}
>
  <summary onclick={onSummaryClick}>{m.ownerLocalExportHeading()}</summary>
  <p>{m.ownerLocalExportIntro()}</p>
  <p>{m.ownerLocalExportBoundary()}</p>
  <label for="owner-local-export-source">{m.ownerLocalExportSource()}</label>
  <select
    id="owner-local-export-source"
    bind:value={selection}
    disabled={disabled || loading || !!prepared}
  >
    <option value="name">{m.ownerAgentGrantName()}</option>
    <option value="owner_note">{m.ownerAgentGrantOwnerNote()}</option>
  </select>
  <label for="owner-local-export-delegate">{m.ownerLocalExportDelegate()}</label>
  <input
    id="owner-local-export-delegate"
    maxlength="80"
    autocomplete="off"
    bind:value={delegate}
    disabled={disabled || loading || !!prepared}
  />
  <label for="owner-local-export-service">{m.ownerLocalExportService()}</label>
  <input
    id="owner-local-export-service"
    maxlength="160"
    autocomplete="off"
    bind:value={service}
    disabled={disabled || loading || !!prepared}
  />
  <p>{m.ownerAgentGrantSelfAssertedLabel()}</p>
  <label for="owner-local-export-lifetime">{m.ownerLocalExportLifetime()}</label>
  <select
    id="owner-local-export-lifetime"
    bind:value={lifetime}
    disabled={disabled || loading || !!prepared}
  >
    <option value={3600}>{m.ownerAgentGrantOneHour()}</option>
    <option value={86400}>{m.ownerAgentGrantOneDay()}</option>
  </select>
  {#if prepared}
    {@const bundle = JSON.parse(prepared.bundle) as {
      documents: { id: DisclosureRecord; text: string }[];
    }}
    {@const document = bundle.documents[0]!}
    <section aria-labelledby="owner-local-export-review-heading">
      <h3 id="owner-local-export-review-heading">{m.ownerLocalExportReviewHeading()}</h3>
      <p>{m.ownerAgentGrantRevision({ revision: prepared.sources[0]!.source.revision })}</p>
      <p>{m.ownerLocalExportDelegateValue({ delegate })}</p>
      <p>{m.ownerLocalExportServiceValue({ service: service.trim() })}</p>
      <p>
        {m.ownerLocalExportExpires({
          expires: new Date(prepared.expires_at * 1000).toLocaleString(),
        })}
      </p>
      <p>{m.ownerLocalExportOperations()}</p>
      <pre id="owner-local-export-preview">{document.text}</pre>
      <p>{m.ownerLocalExportSourceCheck()}</p>
      <p>{m.ownerLocalExportRevokeBoundary()}</p>
      <label>
        <input
          id="owner-local-export-consent"
          type="checkbox"
          bind:checked={consent}
          disabled={disabled || loading}
        />
        {m.ownerLocalExportConsent()}
      </label>
      <div class="product-actions">
        <button
          id="owner-local-export-download-bundle"
          disabled={disabled || loading || !consent}
          onclick={() => download('bundle')}>{m.ownerLocalExportDownloadBundle()}</button
        >
        <button
          id="owner-local-export-download-grant"
          disabled={disabled || loading || !consent}
          onclick={() => download('grant')}>{m.ownerLocalExportDownloadGrant()}</button
        >
      </div>
      <button id="owner-local-export-clear" disabled={loading} onclick={clear}>
        {m.ownerLocalExportClear()}
      </button>
    </section>
  {:else}
    <button
      id="owner-local-export-prepare"
      class="product-primary"
      disabled={!canPrepare}
      onclick={prepare}>{m.ownerLocalExportPrepare()}</button
    >
  {/if}
  <p id="owner-local-export-status" role="status" aria-live="polite">{status}</p>
</details>
