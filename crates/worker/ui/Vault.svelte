<script lang="ts">
  import { restoreActionFocus } from './action-focus.js';
  import { vaultScope, vaultContext } from './vault-context.js';
  const context = vaultContext();
  const scope = vaultScope();
  const fetch = scope.request;
  import { onMount } from 'svelte';
  import {
    decodeBase64Url,
    encodeBase64Url,
    newPrfInput,
    openAttribute,
    parseOwnerEnvelope,
    sealAttribute,
    withOpenedAttribute,
    type SealedAttribute,
  } from './vault-crypto.js';
  import { fetchVerifiedUserInfoRecipient } from './recipient-directory.js';
  import { sealUserInfoDataKey } from './vault-recipient-envelope.js';
  import * as m from './paraglide/messages.js';
  import ProductHeader from './ProductHeader.svelte';
  import type { Locale } from './paraglide/runtime.js';
  import AgentPanel from './AgentPanel.svelte';
  import PasskeyTransfer from './PasskeyTransfer.svelte';
  import OwnerNote from './OwnerNote.svelte';

  type RecordResponse = SealedAttribute & { revision: number };
  type Pending = {
    method: 'PUT' | 'DELETE';
    revision: number;
    value: string;
    id: string;
    body: string | undefined;
  };
  type ShareStatus = {
    enabled: boolean;
    grant_ttl_seconds: number;
    active: boolean;
    grant_version: number | null;
    expires_at: number | null;
  };
  type PendingShare = { method: 'POST' | 'DELETE'; revision: number; id: string; body?: string };
  type ReleaseClient = {
    client_id: string;
    sector_identifier: string;
    client_revision: number;
    connection_grant_version: number;
    release_active: boolean;
    release_version: number | null;
    expires_at: number | null;
  };
  type ReleaseStatus = {
    enabled: boolean;
    ttl_seconds: number;
    policy_revision: number;
    share_active: boolean;
    share_grant_version: number | null;
    clients: ReleaseClient[];
  };
  type PendingRelease = {
    method: 'POST' | 'DELETE';
    clientId: string;
    revision: number;
    id: string;
    body: string;
  };

  let { locale }: { locale: Locale } = $props();

  const attribute = 'name';
  const endpoint = `/vault/attributes/${attribute}`;
  const origin = location.origin;
  let current: RecordResponse | null = $state(null);
  let currentRevision = $state(0);
  let sessionCredential: Uint8Array<ArrayBuffer> | null = $state(null);
  let accountId = $state('');
  let noteRevision = $state(0);
  let sharing: ShareStatus | null = $state(null);
  let pendingShare: PendingShare | null = null;
  let releases: ReleaseStatus | null = $state(null);
  let pendingRelease: PendingRelease | null = null;
  let opened = $state(false);
  let loading = $state(true);
  let busy = $state(false);
  let transferBusy = $state(false);
  let noteBusy = $state(false);
  let agentBusy = $state(false);
  let loadFailed = $state(false);
  let originalName = $state('');
  let pending: Pending | null = $state(null);
  let name = $state('');
  let status = $state(m.vaultLoading());
  let shareStatus = $state('');
  let releaseStatus = $state('');
  const oauthRequested = new URL(location.href).searchParams.has('agent_oauth_request');
  const initialSection = location.hash.slice(1) || (oauthRequested ? 'connections' : 'profile');
  let activeSection = $state(initialSection);
  let connectionsExpanded = $state(initialSection === 'connections' || oauthRequested);
  let securityExpanded = $state(location.hash === '#security');
  const dirty = $derived(pending !== null || (opened && name !== originalName));

  function errorMessage(error: unknown, fallback: string): string {
    const known = [
      m.vaultUnsupported(),
      m.vaultWrongCredential(),
      m.vaultPrfUnsupported(),
      m.vaultExpired(),
      m.vaultCredentialMissing(),
      m.vaultRevisionInvalid(),
      m.vaultRecordInvalid(),
      m.vaultReadFailed(),
      m.vaultInvalidName(),
      m.vaultRetryChanged(),
      m.vaultPrepareFailed(),
      m.vaultConflict(),
      m.vaultWriteFailed(),
      m.productDeleteFailed(),
      m.vaultShareFailed(),
      m.vaultReleaseFailed(),
    ];
    if (error instanceof DOMException && error.name === 'NotAllowedError')
      return m.productPasskeyCancelled();
    return error instanceof Error && known.includes(error.message) ? error.message : fallback;
  }

  async function reload(): Promise<void> {
    if (busy || transferBusy || loading) return;
    if ((pending || (opened && name !== originalName)) && !confirm(m.productProfileDiscard()))
      return;
    busy = true;
    try {
      await load();
    } catch (error) {
      message(errorMessage(error, m.vaultLoadFailed()));
    } finally {
      busy = false;
    }
  }

  function message(value: string): void {
    status = value;
  }

  function shareRecord(value: unknown): value is ShareStatus {
    if (typeof value !== 'object' || value === null) return false;
    const item = value as Partial<ShareStatus>;
    return (
      typeof item.enabled === 'boolean' &&
      Number.isSafeInteger(item.grant_ttl_seconds) &&
      typeof item.grant_ttl_seconds === 'number' &&
      item.grant_ttl_seconds >= 60 &&
      typeof item.active === 'boolean' &&
      (item.grant_version === null ||
        (Number.isSafeInteger(item.grant_version) && typeof item.grant_version === 'number')) &&
      (item.expires_at === null ||
        (Number.isSafeInteger(item.expires_at) && typeof item.expires_at === 'number'))
    );
  }

  async function loadShareStatus(): Promise<void> {
    const response = await fetch('/vault/shares/userinfo/name', { cache: 'no-store' });
    if (!response.ok) {
      sharing = null;
      return;
    }
    const body: unknown = await response.json();
    sharing = shareRecord(body) ? body : null;
  }

  function releaseRecord(value: unknown): value is ReleaseStatus {
    if (typeof value !== 'object' || value === null) return false;
    const item = value as Partial<ReleaseStatus>;
    return (
      typeof item.enabled === 'boolean' &&
      Number.isSafeInteger(item.ttl_seconds) &&
      Number.isSafeInteger(item.policy_revision) &&
      typeof item.share_active === 'boolean' &&
      (item.share_grant_version === null || Number.isSafeInteger(item.share_grant_version)) &&
      Array.isArray(item.clients) &&
      item.clients.every(
        (client: ReleaseClient) =>
          typeof client.client_id === 'string' &&
          typeof client.sector_identifier === 'string' &&
          Number.isSafeInteger(client.client_revision) &&
          Number.isSafeInteger(client.connection_grant_version) &&
          typeof client.release_active === 'boolean' &&
          (client.release_version === null || Number.isSafeInteger(client.release_version)) &&
          (client.expires_at === null || Number.isSafeInteger(client.expires_at)),
      )
    );
  }

  async function loadReleaseStatus(): Promise<void> {
    const response = await fetch('/vault/releases/name', { cache: 'no-store' });
    if (!response.ok) {
      releases = null;
      return;
    }
    const body: unknown = await response.json();
    releases = releaseRecord(body) ? body : null;
  }

  function record(value: unknown): value is RecordResponse {
    if (typeof value !== 'object' || value === null) return false;
    const item = value as Partial<RecordResponse>;
    return (
      item.format_version === 1 &&
      Number.isSafeInteger(item.revision) &&
      typeof item.revision === 'number' &&
      item.revision > 0 &&
      typeof item.ciphertext === 'string' &&
      typeof item.owner_envelope === 'string'
    );
  }

  async function prf(
    credentialId: Uint8Array<ArrayBuffer>,
    prfInput: Uint8Array<ArrayBuffer>,
  ): Promise<Uint8Array<ArrayBuffer>> {
    if (!window.PublicKeyCredential || !navigator.credentials)
      throw new Error(m.vaultUnsupported());
    await scope.ensure();
    const credential = await navigator.credentials.get({
      signal: scope.signal,
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ id: credentialId, type: 'public-key' }],
        userVerification: 'required',
        timeout: 120000,
        extensions: { prf: { eval: { first: prfInput } } },
      },
    });
    if (
      !(credential instanceof PublicKeyCredential) ||
      encodeBase64Url(new Uint8Array(credential.rawId)) !== encodeBase64Url(credentialId)
    ) {
      throw new Error(m.vaultWrongCredential());
    }
    const output = credential.getClientExtensionResults().prf?.results?.first;
    if (!(output instanceof ArrayBuffer) || output.byteLength !== 32) {
      throw new Error(m.vaultPrfUnsupported());
    }
    try {
      await scope.ensure();
    } catch (error) {
      new Uint8Array(output).fill(0);
      throw error;
    }
    return new Uint8Array(output);
  }

  async function load(): Promise<void> {
    loading = true;
    loadFailed = true;
    try {
      opened = false;
      current = null;
      currentRevision = 0;
      pending = null;
      pendingShare = null;
      pendingRelease = null;
      shareStatus = '';
      releaseStatus = '';
      name = '';
      sharing = null;
      releases = null;
      accountId = '';
      sessionCredential = null;
      const session = await fetch('/vault/session', { cache: 'no-store' });
      if (!session.ok)
        throw new Error(
          [401, 403].includes(session.status) ? m.vaultExpired() : m.vaultLoadFailed(),
        );
      const sessionBody: unknown = await session.json();
      if (
        typeof sessionBody !== 'object' ||
        sessionBody === null ||
        !('credential_id' in sessionBody) ||
        typeof sessionBody.credential_id !== 'string' ||
        !('account_id' in sessionBody) ||
        typeof sessionBody.account_id !== 'string' ||
        sessionBody.account_id.length === 0
      ) {
        throw new Error(m.vaultCredentialMissing());
      }
      sessionCredential = decodeBase64Url(sessionBody.credential_id);
      accountId = sessionBody.account_id;
      // Independent reads may overlap after the owner session has been checked.
      // Settle all reads so an optional-panel failure cannot leave late state updates.
      const [share, release, stored] = await Promise.allSettled([
        loadShareStatus(),
        loadReleaseStatus(),
        fetch(endpoint, { cache: 'no-store' }),
      ]);
      if (share.status === 'rejected') sharing = null;
      if (release.status === 'rejected') releases = null;
      if (stored.status === 'rejected') throw stored.reason;
      const response = stored.value;
      if (response.status === 404) {
        const etag = response.headers.get('ETag');
        if (etag !== null) {
          const match = /^"([1-9][0-9]*)"$/.exec(etag);
          if (!match) throw new Error(m.vaultRevisionInvalid());
          currentRevision = Number(match[1]);
          if (!Number.isSafeInteger(currentRevision)) throw new Error(m.vaultRevisionInvalid());
        }
        message(m.vaultNotFound());
        loadFailed = false;
        return;
      }
      if (!response.ok) throw new Error(m.vaultReadFailed());
      const body: unknown = await response.json();
      if (!record(body)) throw new Error(m.vaultRecordInvalid());
      current = body;
      currentRevision = body.revision;
      message(m.vaultLoaded());
      loadFailed = false;
    } finally {
      loading = false;
    }
  }

  async function unlock(): Promise<void> {
    if (loading || loadFailed || busy || transferBusy || opened) return;
    const previousFocus = document.activeElement;
    busy = true;
    try {
      if (current) {
        const envelope = parseOwnerEnvelope(current.owner_envelope);
        const output = await prf(envelope.credentialId, envelope.prfInput);
        try {
          const plaintext = await openAttribute(
            current,
            output,
            envelope.credentialId,
            origin,
            attribute,
            current.revision,
          );
          try {
            name = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
          } finally {
            plaintext.fill(0);
          }
        } finally {
          output.fill(0);
        }
      } else {
        if (!sessionCredential) throw new Error(m.vaultCredentialMissing());
        const output = await prf(sessionCredential, newPrfInput());
        output.fill(0);
      }
      originalName = name;
      opened = true;
      message(m.vaultReady());
    } catch (error) {
      message(errorMessage(error, m.vaultOpenFailed()));
    } finally {
      busy = false;
      await restoreActionFocus(previousFocus, () =>
        document.getElementById(opened ? 'name' : 'unlock'),
      );
    }
  }

  async function exportSavedName(): Promise<string> {
    if (!opened || busy || transferBusy || pending || !current)
      throw new Error(m.vaultOpenFailed());
    const record = current;
    const envelope = parseOwnerEnvelope(record.owner_envelope);
    const output = await prf(envelope.credentialId, envelope.prfInput);
    try {
      return await withOpenedAttribute(
        record,
        output,
        envelope.credentialId,
        origin,
        attribute,
        record.revision,
        async (plaintext) => {
          try {
            return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
          } finally {
            plaintext.fill(0);
          }
        },
      );
    } finally {
      output.fill(0);
    }
  }

  async function mutate(method: 'PUT' | 'DELETE'): Promise<void> {
    if (!opened || busy || transferBusy || loading) return;
    if (method === 'DELETE' && !pending && !confirm(m.productProfileDeleteConfirm())) return;
    const previousFocus = document.activeElement;
    busy = true;
    try {
      const revision = currentRevision;
      const value = name;
      if (method === 'PUT' && (value.length === 0 || value.length > 256)) {
        throw new Error(m.vaultInvalidName());
      }
      if (method === 'DELETE' && !current) return;
      if (
        pending &&
        (pending.method !== method || pending.revision !== revision || pending.value !== value)
      ) {
        throw new Error(m.vaultRetryChanged());
      }
      if (!pending) {
        let body: string | undefined;
        if (method === 'PUT') {
          const envelope = current ? parseOwnerEnvelope(current.owner_envelope) : null;
          const credentialId = envelope?.credentialId ?? sessionCredential;
          if (!credentialId) throw new Error(m.vaultCredentialMissing());
          const prfInput = envelope?.prfInput ?? newPrfInput();
          const output = await prf(credentialId, prfInput);
          const plaintext = new TextEncoder().encode(value);
          try {
            const sealed = await sealAttribute(
              plaintext,
              output,
              credentialId,
              prfInput,
              origin,
              attribute,
              revision + 1,
            );
            body = JSON.stringify(sealed);
          } finally {
            output.fill(0);
            plaintext.fill(0);
          }
        }
        pending = {
          method,
          revision,
          value,
          id: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
          body,
        };
      }
      const operation = pending;
      if (!operation) throw new Error(m.vaultPrepareFailed());
      const headers: Record<string, string> = {
        'X-Operation-ID': operation.id,
        [revision === 0 ? 'If-None-Match' : 'If-Match']: revision === 0 ? '*' : `"${revision}"`,
      };
      if (method === 'PUT') headers['Content-Type'] = 'application/json';
      const response = await fetch(endpoint, { method, headers, body: operation.body ?? null });
      if (response.status === 409) throw new Error(m.vaultConflict());
      if (!response.ok)
        throw new Error(method === 'DELETE' ? m.productDeleteFailed() : m.vaultWriteFailed());
      pending = null;
      try {
        await load();
      } catch {
        message(m.productProfileRefreshFailed());
        return;
      }
      message(method === 'PUT' ? m.vaultSaved() : m.vaultDeleted());
    } catch (error) {
      message(
        errorMessage(error, method === 'DELETE' ? m.productDeleteFailed() : m.vaultWriteFailed()),
      );
    } finally {
      busy = false;
      await restoreActionFocus(previousFocus, () =>
        document.getElementById(
          pending
            ? method === 'PUT'
              ? 'save'
              : 'delete'
            : !opened
              ? loadFailed
                ? 'reload-profile'
                : 'unlock'
              : method === 'PUT' && (name.length === 0 || name.length > 256)
                ? 'name'
                : method === 'PUT'
                  ? 'save'
                  : 'delete',
        ),
      );
    }
  }

  async function changeShare(method: 'POST' | 'DELETE'): Promise<void> {
    if (!opened || busy || transferBusy || pending || !current || !sharing || !accountId) return;
    if (method === 'POST' && !sharing.enabled) return;
    if (method === 'DELETE' && (!sharing.active || !sharing.grant_version)) return;
    busy = true;
    try {
      const revision = method === 'POST' ? current.revision : sharing.grant_version;
      if (revision === null) return;
      if (pendingShare && (pendingShare.method !== method || pendingShare.revision !== revision)) {
        throw new Error(m.vaultRetryChanged());
      }
      if (!pendingShare) {
        let body: string | undefined;
        if (method === 'POST') {
          const recipient = await fetchVerifiedUserInfoRecipient(fetch, localStorage);
          const envelope = parseOwnerEnvelope(current.owner_envelope);
          const output = await prf(envelope.credentialId, envelope.prfInput);
          try {
            const ciphertext = decodeBase64Url(current.ciphertext);
            const frame = await withOpenedAttribute(
              current,
              output,
              envelope.credentialId,
              origin,
              attribute,
              current.revision,
              async (plaintext, dataKey) => {
                try {
                  return await sealUserInfoDataKey(dataKey, recipient, {
                    origin,
                    accountId,
                    revision: current.revision,
                    ciphertext,
                  });
                } finally {
                  plaintext.fill(0);
                }
              },
            );
            const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', ciphertext));
            body = JSON.stringify({
              frame: encodeBase64Url(frame),
              key_id: recipient.key_id,
              generation: recipient.generation,
              directory_revision: recipient.revision,
              ciphertext_sha256: encodeBase64Url(digest),
            });
          } finally {
            output.fill(0);
          }
        }
        pendingShare = {
          method,
          revision,
          id: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
          body,
        };
      }
      const operation = pendingShare;
      const response = await fetch('/vault/shares/userinfo/name', {
        method,
        headers: {
          'X-Operation-ID': operation.id,
          'If-Match': `"${operation.revision}"`,
          ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
        },
        body: operation.body ?? null,
      });
      if (!response.ok) throw new Error(m.vaultShareFailed());
      pendingShare = null;
      await loadShareStatus();
      await loadReleaseStatus();
      shareStatus = method === 'POST' ? m.vaultShared() : m.vaultShareRevoked();
    } catch (error) {
      shareStatus = errorMessage(error, m.vaultShareFailed());
    } finally {
      busy = false;
    }
  }

  async function changeRelease(client: ReleaseClient, method: 'POST' | 'DELETE'): Promise<void> {
    if (!opened || busy || transferBusy || pending || !releases?.enabled) return;
    if (method === 'POST' && (!releases.share_active || !releases.share_grant_version)) return;
    if (method === 'DELETE' && (!client.release_active || !client.release_version)) return;
    busy = true;
    try {
      const revision = method === 'POST' ? releases.share_grant_version : client.release_version;
      if (!revision) return;
      if (
        pendingRelease &&
        (pendingRelease.method !== method ||
          pendingRelease.clientId !== client.client_id ||
          pendingRelease.revision !== revision)
      ) {
        throw new Error(m.vaultRetryChanged());
      }
      pendingRelease ??= {
        method,
        clientId: client.client_id,
        revision,
        id: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
        body: JSON.stringify(
          method === 'POST'
            ? {
                client_id: client.client_id,
                client_revision: client.client_revision,
                connection_grant_version: client.connection_grant_version,
                policy_revision: releases.policy_revision,
              }
            : { client_id: client.client_id },
        ),
      };
      const operation = pendingRelease;
      const response = await fetch('/vault/releases/name', {
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-Operation-ID': operation.id,
          'If-Match': `"${operation.revision}"`,
        },
        body: operation.body,
      });
      if (!response.ok) throw new Error(m.vaultReleaseFailed());
      pendingRelease = null;
      await loadReleaseStatus();
      releaseStatus = method === 'POST' ? m.vaultReleaseGranted() : m.vaultReleaseRevoked();
    } catch (error) {
      releaseStatus = errorMessage(error, m.vaultReleaseFailed());
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    const unregister = context.registerDraft(() => dirty || (opened && busy));
    void load().catch((error: unknown) => {
      message(errorMessage(error, m.vaultLoadFailed()));
    });
    return unregister;
  });
</script>

<svelte:window
  onhashchange={() => {
    activeSection = location.hash.slice(1) || 'profile';
    if (activeSection === 'connections') connectionsExpanded = true;
    if (activeSection === 'security') securityExpanded = true;
  }}
/>
<div class="vault-shell">
  <ProductHeader
    {locale}
    onlock={context.lock}
    material
    paused={busy || transferBusy || loading || noteBusy || agentBusy}
  />
  <main id="product-main" tabindex="-1" class="product-main">
    <div class="product-heading">
      <h1>{m.vaultHeading()}</h1>
      <p>{m.productVaultHint()}</p>
    </div>
    <div class="product-workspace">
      <nav class="product-nav" aria-label={m.vaultHeading()}>
        <a href="#profile" aria-current={activeSection === 'profile' ? 'location' : undefined}
          >{m.productProfile()}</a
        >
        <a href="#notes" aria-current={activeSection === 'notes' ? 'location' : undefined}
          >{m.vaultNoteHeading()}</a
        >
        <a
          href="#connections"
          onclick={() => (connectionsExpanded = true)}
          aria-current={activeSection === 'connections' ? 'location' : undefined}
          >{m.productSharing()}</a
        >
        <a
          href="#security"
          onclick={() => (securityExpanded = true)}
          aria-current={activeSection === 'security' ? 'location' : undefined}
          >{m.productSecurity()}</a
        >
      </nav>
      <div class="product-content">
        <section id="profile" aria-labelledby="profile-heading" aria-busy={busy || loading}>
          <div class="product-section-top">
            <h2 id="profile-heading">{m.productProfile()}</h2>
            <span class="product-lock-state" class:is-open={opened}
              >{opened ? m.productUnlocked() : m.productLocked()}</span
            >
          </div>
          <p>{m.vaultIntro()}</p>
          <label for="name">{m.vaultName()}</label>
          <input
            id="name"
            type="text"
            maxlength="256"
            autocomplete="name"
            disabled={!opened || busy || transferBusy || pending !== null}
            aria-describedby="status"
            bind:value={name}
          />
          <div class="product-actions">
            <button
              class="product-primary"
              id="unlock"
              type="button"
              disabled={opened || loading || loadFailed || busy || transferBusy}
              onclick={unlock}>{m.vaultUnlock()}</button
            >
            <button
              class="product-primary"
              id="save"
              type="button"
              disabled={!opened || busy || transferBusy || pending?.method === 'DELETE'}
              onclick={() => mutate('PUT')}>{m.vaultSave()}</button
            >
            <button
              class="product-danger"
              id="delete"
              type="button"
              disabled={!opened ||
                current === null ||
                busy ||
                transferBusy ||
                pending?.method === 'PUT'}
              onclick={() => mutate('DELETE')}>{m.vaultDelete()}</button
            >
            <button
              id="reload-profile"
              type="button"
              disabled={busy || transferBusy || loading}
              onclick={reload}>{m.productProfileReload()}</button
            >
          </div>
          <p id="status" role="status" aria-live="polite">{status}</p>
          {#if dirty}<p class="product-draft-status" data-draft-state="profile" aria-live="polite">
              {pending ? m.productUnfinishedOperation() : m.productUnsavedChanges()}
            </p>{/if}
        </section>
        <div id="notes" class="product-content">
          <OwnerNote
            onBusy={(value) => {
              noteBusy = value;
            }}
            credentialId={sessionCredential}
            evaluatePrf={prf}
            onSavedRevision={(revision) => {
              noteRevision = revision;
            }}
          />
        </div>
        <details id="connections" class="product-details" bind:open={connectionsExpanded}>
          <summary>{m.productSharing()}</summary>
          <div class="product-content">
            {#if sharing?.enabled && current}
              <section aria-label={m.productSharing()}>
                <h2>{m.productSharing()}</h2>
                <p>
                  {m.vaultShareExplanation({
                    expiry: new Date(
                      sharing.active && sharing.expires_at
                        ? sharing.expires_at * 1000
                        : Date.now() + sharing.grant_ttl_seconds * 1000,
                    ).toLocaleString(locale),
                  })}
                </p>
                <p role="status">{shareStatus}</p>
                {#if sharing.active}
                  <p>{m.vaultShareActive()}</p>
                  <button
                    type="button"
                    disabled={!opened || busy || transferBusy || pending !== null}
                    onclick={() => changeShare('DELETE')}>{m.vaultShareRevoke()}</button
                  >
                {:else}
                  <button
                    type="button"
                    disabled={!opened || busy || transferBusy || pending !== null}
                    onclick={() => changeShare('POST')}>{m.vaultShare()}</button
                  >
                {/if}
              </section>
            {/if}
            <AgentPanel
              onBusy={(value) => {
                agentBusy = value;
              }}
              {opened}
              sourceRevision={current?.revision ?? 0}
              ownerId={accountId}
              loadName={exportSavedName}
              {noteRevision}
              {locale}
              credentialId={sessionCredential}
              evaluatePrf={prf}
            />
            {#if releases?.enabled && releases.clients.length > 0}
              <section aria-label={m.vaultReleaseHeading()}>
                <h2>{m.vaultReleaseHeading()}</h2>
                <p>{m.vaultReleaseExplanation()}</p>
                <p role="status">{releaseStatus}</p>
                {#each releases.clients as client (client.client_id)}
                  <div class="product-release-client">
                    <p>{client.sector_identifier} ({client.client_id})</p>
                    {#if client.release_active}
                      <p>
                        {m.vaultReleaseUntil({
                          expiry: new Date((client.expires_at ?? 0) * 1000).toLocaleString(locale),
                        })}
                      </p>
                      <button
                        type="button"
                        disabled={!opened || busy || transferBusy || pending !== null}
                        onclick={() => changeRelease(client, 'DELETE')}
                        >{m.vaultReleaseRevoke()}</button
                      >
                    {:else}
                      <button
                        type="button"
                        disabled={!opened ||
                          busy ||
                          transferBusy ||
                          pending !== null ||
                          !releases.share_active}
                        onclick={() => changeRelease(client, 'POST')}
                        >{m.vaultReleaseGrant()}</button
                      >
                    {/if}
                  </div>
                {/each}
              </section>
            {/if}
          </div>
        </details>
        <details id="security" class="product-details" bind:open={securityExpanded}>
          <summary>{m.productSecurity()}</summary>
          <div class="product-content">
            <PasskeyTransfer
              saved={current}
              {opened}
              evaluatePrf={prf}
              changed={load}
              beforeTransfer={() => !dirty || confirm(m.productTransferDiscard())}
              disabled={busy || pending !== null}
              onBusy={(value) => {
                transferBusy = value;
              }}
            />
          </div>
        </details>
      </div>
    </div>
  </main>
</div>
