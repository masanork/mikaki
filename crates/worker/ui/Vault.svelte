<script lang="ts">
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
  import { switchLocale } from './locale.js';
  import type { Locale } from './paraglide/runtime.js';

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
  let sharing: ShareStatus | null = $state(null);
  let pendingShare: PendingShare | null = null;
  let releases: ReleaseStatus | null = $state(null);
  let pendingRelease: PendingRelease | null = null;
  let opened = $state(false);
  let loading = $state(true);
  let pending: Pending | null = null;
  let name = $state('');
  let status = $state(m.vaultLoading());

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
    const credential = await navigator.credentials.get({
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
    return new Uint8Array(output);
  }

  async function load(): Promise<void> {
    loading = true;
    opened = false;
    current = null;
    currentRevision = 0;
    pending = null;
    pendingShare = null;
    pendingRelease = null;
    name = '';
    sharing = null;
    releases = null;
    accountId = '';
    const session = await fetch('/vault/session', { cache: 'no-store' });
    if (!session.ok) throw new Error(m.vaultExpired());
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
    await loadShareStatus().catch(() => {
      sharing = null;
    });
    await loadReleaseStatus().catch(() => {
      releases = null;
    });
    const response = await fetch(endpoint, { cache: 'no-store' });
    if (response.status === 404) {
      const etag = response.headers.get('ETag');
      if (etag !== null) {
        const match = /^"([1-9][0-9]*)"$/.exec(etag);
        if (!match) throw new Error(m.vaultRevisionInvalid());
        currentRevision = Number(match[1]);
        if (!Number.isSafeInteger(currentRevision)) throw new Error(m.vaultRevisionInvalid());
      }
      message(m.vaultNotFound());
      loading = false;
      return;
    }
    if (!response.ok) throw new Error(m.vaultReadFailed());
    const body: unknown = await response.json();
    if (!record(body)) throw new Error(m.vaultRecordInvalid());
    current = body;
    currentRevision = body.revision;
    message(m.vaultLoaded());
    loading = false;
  }

  async function unlock(): Promise<void> {
    if (loading) return;
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
      opened = true;
      message(m.vaultReady());
    } catch (error) {
      message(error instanceof Error ? error.message : m.vaultOpenFailed());
    }
  }

  async function mutate(method: 'PUT' | 'DELETE'): Promise<void> {
    if (!opened) return;
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
      if (!response.ok) throw new Error(m.vaultWriteFailed());
      pending = null;
      await load();
      message(method === 'PUT' ? m.vaultSaved() : m.vaultDeleted());
    } catch (error) {
      message(error instanceof Error ? error.message : m.vaultOperationFailed());
    }
  }

  async function changeShare(method: 'POST' | 'DELETE'): Promise<void> {
    if (!opened || !current || !sharing || !accountId) return;
    if (method === 'POST' && !sharing.enabled) return;
    if (method === 'DELETE' && (!sharing.active || !sharing.grant_version)) return;
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
      message(method === 'POST' ? m.vaultShared() : m.vaultShareRevoked());
    } catch (error) {
      message(error instanceof Error ? error.message : m.vaultShareFailed());
    }
  }

  async function changeRelease(client: ReleaseClient, method: 'POST' | 'DELETE'): Promise<void> {
    if (!opened || !releases?.enabled) return;
    if (method === 'POST' && (!releases.share_active || !releases.share_grant_version)) return;
    if (method === 'DELETE' && (!client.release_active || !client.release_version)) return;
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
      message(method === 'POST' ? m.vaultReleaseGranted() : m.vaultReleaseRevoked());
    } catch (error) {
      message(error instanceof Error ? error.message : m.vaultReleaseFailed());
    }
  }

  onMount(() => {
    void load().catch((error: unknown) => {
      message(error instanceof Error ? error.message : m.vaultLoadFailed());
    });
  });
</script>

<main>
  <label
    >{m.language()}
    <select
      aria-label={m.language()}
      value={locale}
      onchange={(event) => switchLocale(event.currentTarget.value)}
    >
      <option value="ja">日本語</option>
      <option value="en">English</option>
    </select>
  </label>
  <h1>{m.vaultHeading()}</h1>
  <p>{m.vaultIntro()}</p>
  <label for="name">{m.vaultName()}</label>
  <input
    id="name"
    type="text"
    maxlength="256"
    autocomplete="name"
    disabled={!opened}
    bind:value={name}
  />
  <button id="unlock" type="button" disabled={opened || loading} onclick={unlock}
    >{m.vaultUnlock()}</button
  >
  <button id="save" type="button" disabled={!opened} onclick={() => mutate('PUT')}
    >{m.vaultSave()}</button
  >
  <button
    id="delete"
    type="button"
    disabled={!opened || current === null}
    onclick={() => mutate('DELETE')}>{m.vaultDelete()}</button
  >
  {#if sharing?.enabled && current}
    <p>
      {m.vaultShareExplanation({
        expiry: new Date(
          sharing.active && sharing.expires_at
            ? sharing.expires_at * 1000
            : Date.now() + sharing.grant_ttl_seconds * 1000,
        ).toLocaleString(locale),
      })}
    </p>
    {#if sharing.active}
      <p>{m.vaultShareActive()}</p>
      <button type="button" disabled={!opened} onclick={() => changeShare('DELETE')}
        >{m.vaultShareRevoke()}</button
      >
    {:else}
      <button type="button" disabled={!opened} onclick={() => changeShare('POST')}
        >{m.vaultShare()}</button
      >
    {/if}
  {/if}
  {#if releases?.enabled && releases.clients.length > 0}
    <section aria-label={m.vaultReleaseHeading()}>
      <h2>{m.vaultReleaseHeading()}</h2>
      <p>{m.vaultReleaseExplanation()}</p>
      {#each releases.clients as client (client.client_id)}
        <div>
          <p>{client.sector_identifier} ({client.client_id})</p>
          {#if client.release_active}
            <p>
              {m.vaultReleaseUntil({
                expiry: new Date((client.expires_at ?? 0) * 1000).toLocaleString(locale),
              })}
            </p>
            <button type="button" disabled={!opened} onclick={() => changeRelease(client, 'DELETE')}
              >{m.vaultReleaseRevoke()}</button
            >
          {:else}
            <button
              type="button"
              disabled={!opened || !releases.share_active}
              onclick={() => changeRelease(client, 'POST')}>{m.vaultReleaseGrant()}</button
            >
          {/if}
        </div>
      {/each}
    </section>
  {/if}
  <p id="status" role="status">{status}</p>
</main>
