<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { restoreActionFocus } from './action-focus.ts';
  import * as m from './paraglide/messages.js';
  import type { OwnerVaultController } from './vault-owner-controller.ts';
  import {
    OwnerNameSharing,
    OwnerNameSharingError,
    type OwnerNameSharingSnapshot,
    type PreparedOwnerNameOperation,
  } from './vault-owner-name-sharing.ts';

  let {
    owner,
    sourceRevision,
    disabled,
    hasDrafts,
    onbusy,
    onunconfirmed,
  }: {
    owner: OwnerVaultController;
    sourceRevision: number;
    disabled: boolean;
    hasDrafts: () => boolean;
    onbusy: (value: boolean) => void;
    onunconfirmed: (value: boolean) => void;
  } = $props();

  const checkpointStorage = {
    getItem: (key: string) => window.localStorage.getItem(key),
    setItem: (key: string, value: string) => window.localStorage.setItem(key, value),
  };
  const sharing = untrack(() => new OwnerNameSharing(owner, checkpointStorage));
  let expanded = $state(false);
  let loading = $state(false);
  // Helper snapshots and operations are identity-bound in WeakSets/WeakMaps;
  // Svelte proxies would invalidate those guards and break exact retry.
  let snapshot = $state.raw<OwnerNameSharingSnapshot | null>(null);
  let pending = $state.raw<PreparedOwnerNameOperation | null>(null);
  let submittedUnknown = false;
  let selectedClient = $state('');
  let status = $state('');
  let snapshotTime = $state(0);
  let renderClock = $state(Date.now());
  let observedSourceRevision = untrack(() => sourceRevision);
  const canPrepare = $derived(!disabled && !loading && pending === null);
  const systemActive = $derived(
    !!snapshot?.sharing.grant &&
      snapshot.sharing.grant.status === 'active' &&
      snapshot.sharing.grant.expires_at > renderClock / 1000,
  );
  const sharingCurrent = $derived(!!snapshot?.sharing.authorityCurrent && systemActive);

  $effect(() => {
    const currentRevision = sourceRevision;
    const previousRevision = untrack(() => observedSourceRevision);
    if (currentRevision === previousRevision) return;
    observedSourceRevision = currentRevision;
    const hadSnapshot = untrack(() => snapshot !== null);
    snapshot = null;
    selectedClient = '';
    if (!submittedUnknown) pending = null;
    status = hadSnapshot ? m.ownerNameSharingSourceChanged() : '';
  });

  $effect(() => {
    if (!snapshot) return;
    const deadlines = [
      snapshot.sharing.grant?.expires_at,
      ...snapshot.releases.clients.map((client) => client.expires_at),
    ].filter((value): value is number => typeof value === 'number' && value * 1000 > renderClock);
    if (!deadlines.length) return;
    const next = Math.min(...deadlines) * 1000;
    const timer = setTimeout(
      () => (renderClock = Date.now()),
      Math.max(0, Math.min(2_147_483_647, next - renderClock + 1)),
    );
    return () => clearTimeout(timer);
  });

  function messageFor(error: unknown): string {
    if (error instanceof Error && error.message === 'owner_unsaved_changes')
      return m.productUnsavedChanges();
    if (error instanceof Error && error.message === 'name_unavailable')
      return m.ownerNameSharingNoSavedName();
    if (owner.scope.signal.aborted) return '';
    return m.ownerNameSharingFailed();
  }

  async function load() {
    if (disabled || loading || pending) return;
    const focus = document.activeElement;
    loading = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.verifyAuthority();
      owner.assertCurrent(token);
      const next = await sharing.load();
      owner.assertCurrent(token);
      snapshot = next;
      snapshotTime = Date.now();
      renderClock = Date.now();
      selectedClient = next.releases.clients[0]?.client_id ?? '';
      status = '';
    } catch (error) {
      status = messageFor(error);
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () =>
          document.getElementById('owner-name-sharing-refresh'),
        );
    }
  }

  async function commit(operation: PreparedOwnerNameOperation) {
    const focus = document.activeElement;
    const retryingSubmitted = submittedUnknown;
    loading = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.scope.verify();
      owner.assertCurrent(token);
      if (hasDrafts()) {
        if (!retryingSubmitted) pending = null;
        if (!retryingSubmitted) onunconfirmed(false);
        throw new Error('owner_unsaved_changes');
      }
      // Past this point the request may reach the server. Keep this exact opaque
      // operation and block parent edits until its outcome is authoritatively read.
      submittedUnknown = true;
      onunconfirmed(true);
      snapshot = await sharing.commit(operation);
      owner.assertCurrent(token);
      snapshotTime = Date.now();
      renderClock = Date.now();
      selectedClient = snapshot.releases.clients[0]?.client_id ?? '';
      pending = null;
      submittedUnknown = false;
      onunconfirmed(false);
      status = m.ownerNameSharingUpdated();
    } catch (error) {
      if (error instanceof OwnerNameSharingError && error.definitelyRejected) {
        pending = null;
        submittedUnknown = false;
        onunconfirmed(false);
        snapshot = null;
        try {
          snapshot = await sharing.load();
          snapshotTime = Date.now();
          renderClock = Date.now();
          selectedClient = snapshot.releases.clients[0]?.client_id ?? '';
        } catch {
          snapshot = null;
        }
      }
      if (
        !submittedUnknown &&
        !(error instanceof OwnerNameSharingError && error.definitelyRejected)
      ) {
        pending = null;
        submittedUnknown = false;
        onunconfirmed(false);
      }
      status =
        error instanceof OwnerNameSharingError && error.definitelyRejected
          ? m.ownerNameSharingRejected()
          : messageFor(error);
      // Submitted retries retain their exact operation until a confirmed read.
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () => document.getElementById('owner-name-sharing-retry'));
    }
  }

  async function prepare(action: () => Promise<PreparedOwnerNameOperation>) {
    if (!snapshot || !canPrepare) return;
    if (hasDrafts()) {
      status = m.productUnsavedChanges();
      return;
    }
    const focus = document.activeElement;
    loading = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.verifyAuthority();
      owner.assertCurrent(token);
      const operation = await action();
      owner.assertCurrent(token);
      if (hasDrafts()) {
        status = m.productUnsavedChanges();
        return;
      }
      pending = operation;
      status = '';
      await commit(operation);
    } catch (error) {
      status = messageFor(error);
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () => document.getElementById('owner-name-sharing-status'));
    }
  }

  function toggle(event: Event) {
    expanded = (event.currentTarget as HTMLDetailsElement).open;
    if (expanded && !snapshot && !loading) void load();
    if (!expanded && !pending) {
      snapshot = null;
      selectedClient = '';
      status = '';
    }
  }

  onMount(() => {
    const clear = () => {
      snapshot = null;
      pending = null;
      selectedClient = '';
      status = '';
      loading = false;
      onunconfirmed(false);
    };
    owner.scope.signal.addEventListener('abort', clear, { once: true });
    return () => {
      clear();
      owner.scope.signal.removeEventListener('abort', clear);
    };
  });
</script>

<details id="owner-name-sharing" aria-busy={loading} ontoggle={toggle}>
  <summary>{m.productNameSharing()}</summary>
  <p>{m.ownerNameSharingIntro()}</p>
  <p>{m.ownerNameSharingCopyWarning()}</p>
  <div class="product-actions">
    <button
      id="owner-name-sharing-refresh"
      disabled={disabled || loading || pending !== null}
      onclick={load}>{m.ownerNameSharingRefresh()}</button
    >
  </div>
  {#if snapshot}
    <section aria-labelledby="owner-name-sharing-preview-heading">
      <h3 id="owner-name-sharing-preview-heading">{m.ownerNameSharingPreviewHeading()}</h3>
      <p><strong>{snapshot.name}</strong></p>
      <p>{m.ownerNameSharingSource({ revision: snapshot.source.revision })}</p>
      <p>{m.ownerNameSharingUserInfoPurpose()}</p>
      {#if snapshot.recipient}
        <p>
          {m.ownerNameSharingRecipient({
            service: snapshot.recipient.service_id,
            algorithm: snapshot.recipient.algorithm,
            generation: snapshot.recipient.generation,
          })}
        </p>
      {:else}
        <p>{m.ownerNameSharingRecipientUnavailable()}</p>
      {/if}
      <p>
        {m.ownerNameSharingSystemTtl({
          seconds: snapshot.sharing.grant_ttl_seconds,
          expires: new Date(
            snapshotTime + snapshot.sharing.grant_ttl_seconds * 1000,
          ).toLocaleString(),
        })}
      </p>
      {#if !snapshot.sharing.enabled}
        <p>{m.ownerNameSharingPolicyDisabled()}</p>
      {:else if sharingCurrent}
        <p>
          {m.ownerNameSharingActive({
            expires: new Date(snapshot.sharing.grant!.expires_at * 1000).toLocaleString(),
          })}
        </p>
      {:else if systemActive}
        <p>{m.ownerNameSharingStale()}</p>
      {:else if snapshot.sharing.grant?.status === 'active'}
        <p>{m.ownerNameSharingExpired()}</p>
      {:else if snapshot.sharing.grant?.status === 'revoked'}
        <p>{m.ownerNameSharingRevoked()}</p>
      {:else}
        <p>{m.ownerNameSharingNotActive()}</p>
      {/if}
      <div class="product-actions">
        {#if snapshot.sharing.enabled && !sharingCurrent}
          <button
            id="owner-name-sharing-share"
            disabled={!canPrepare || !snapshot.recipient}
            onclick={() => prepare(() => sharing.prepareShare(snapshot!))}
            >{m.ownerNameSharingShare()}</button
          >
        {/if}
        {#if snapshot.sharing.grant?.status === 'active'}
          <button
            id="owner-name-sharing-revoke"
            disabled={disabled || loading || pending !== null}
            onclick={() => prepare(() => sharing.prepareRevokeShare(snapshot!))}
            >{m.ownerNameSharingRevoke()}</button
          >
        {/if}
      </div>
    </section>

    <section aria-labelledby="owner-name-sharing-rps-heading">
      <h3 id="owner-name-sharing-rps-heading">{m.ownerNameSharingRpsHeading()}</h3>
      <p>{m.ownerNameSharingRpsCopy()}</p>
      <p>
        {m.ownerNameSharingRpTtl({
          seconds: snapshot.releases.ttl_seconds,
          expires: new Date(snapshotTime + snapshot.releases.ttl_seconds * 1000).toLocaleString(),
        })}
      </p>
      {#if !snapshot.releases.enabled || !sharingCurrent || !snapshot.recipient}
        <p>{m.ownerNameSharingRpUnavailable()}</p>
      {/if}
      {#if snapshot.releases.clients.length === 0}
        <p>{m.ownerNameSharingNoRps()}</p>
      {:else}
        <label for="owner-name-sharing-client">{m.ownerNameSharingChooseRp()}</label>
        <select
          id="owner-name-sharing-client"
          bind:value={selectedClient}
          disabled={disabled || loading || pending !== null}
        >
          {#each snapshot.releases.clients as client (client.client_id)}
            <option value={client.client_id}>
              {client.sector_identifier || client.client_id} · {client.client_id}
            </option>
          {/each}
        </select>
        {@const client = snapshot.releases.clients.find(
          (entry) => entry.client_id === selectedClient,
        )}
        {#if client}
          <p>{m.ownerNameSharingRpPurpose({ rp: client.sector_identifier || client.client_id })}</p>
          {#if client.current && sharingCurrent && client.expires_at !== null && client.expires_at > renderClock / 1000}
            <p>
              {m.ownerNameSharingRpActive({
                expires: new Date(client.expires_at * 1000).toLocaleString(),
              })}
            </p>
          {:else if client.release_status === 'active' && client.expires_at !== null && client.expires_at <= renderClock / 1000}
            <p>{m.ownerNameSharingRpExpired()}</p>
          {:else if client.release_status === 'active'}
            <p>{m.ownerNameSharingRpStale()}</p>
          {:else if client.release_status === 'revoked'}
            <p>{m.ownerNameSharingRpRevoked()}</p>
          {:else}
            <p>{m.ownerNameSharingRpNotActive()}</p>
          {/if}
          {#if client.release_status === 'active'}
            <button
              id="owner-name-sharing-withdraw"
              disabled={!canPrepare}
              onclick={() =>
                prepare(() => sharing.prepareRevokeRelease(snapshot!, client.client_id))}
              >{m.ownerNameSharingWithdraw()}</button
            >
          {/if}
          {#if client.eligible && sharingCurrent && !client.current}
            <button
              id="owner-name-sharing-allow"
              disabled={!canPrepare}
              onclick={() => prepare(() => sharing.prepareRelease(snapshot!, client.client_id))}
              >{m.ownerNameSharingAllow()}</button
            >
          {/if}
        {/if}
      {/if}
    </section>
  {/if}
  {#if pending}
    <button
      id="owner-name-sharing-retry"
      disabled={disabled || loading}
      onclick={() => commit(pending!)}>{m.ownerNameSharingRetry()}</button
    >
  {/if}
  <p id="owner-name-sharing-status" role="status" aria-live="polite">{status}</p>
</details>
