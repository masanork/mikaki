<script lang="ts">
  import { onMount } from 'svelte';
  import {
    decodeBase64Url,
    encodeBase64Url,
    newPrfInput,
    openAttribute,
    parseOwnerEnvelope,
    sealAttribute,
    type SealedAttribute,
  } from './vault-crypto.js';
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

  let { locale }: { locale: Locale } = $props();

  const attribute = 'name';
  const endpoint = `/vault/attributes/${attribute}`;
  const origin = location.origin;
  let current: RecordResponse | null = $state(null);
  let currentRevision = $state(0);
  let sessionCredential: Uint8Array<ArrayBuffer> | null = $state(null);
  let opened = $state(false);
  let pending: Pending | null = null;
  let name = $state('');
  let status = $state(m.vaultLoading());

  function message(value: string): void {
    status = value;
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
    opened = false;
    current = null;
    currentRevision = 0;
    pending = null;
    name = '';
    const session = await fetch('/vault/session', { cache: 'no-store' });
    if (!session.ok) throw new Error(m.vaultExpired());
    const sessionBody: unknown = await session.json();
    if (
      typeof sessionBody !== 'object' ||
      sessionBody === null ||
      !('credential_id' in sessionBody) ||
      typeof sessionBody.credential_id !== 'string'
    ) {
      throw new Error(m.vaultCredentialMissing());
    }
    sessionCredential = decodeBase64Url(sessionBody.credential_id);
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
      return;
    }
    if (!response.ok) throw new Error(m.vaultReadFailed());
    const body: unknown = await response.json();
    if (!record(body)) throw new Error(m.vaultRecordInvalid());
    current = body;
    currentRevision = body.revision;
    message(m.vaultLoaded());
  }

  async function unlock(): Promise<void> {
    try {
      if (current) {
        const envelope = parseOwnerEnvelope(current.owner_envelope);
        const output = await prf(envelope.credentialId, envelope.prfInput);
        const plaintext = await openAttribute(
          current,
          output,
          envelope.credentialId,
          origin,
          attribute,
          current.revision,
        );
        name = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
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
          const sealed = await sealAttribute(
            new TextEncoder().encode(value),
            output,
            credentialId,
            prfInput,
            origin,
            attribute,
            revision + 1,
          );
          output.fill(0);
          body = JSON.stringify(sealed);
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
  <button id="unlock" type="button" disabled={opened} onclick={unlock}>{m.vaultUnlock()}</button>
  <button id="save" type="button" disabled={!opened} onclick={() => mutate('PUT')}
    >{m.vaultSave()}</button
  >
  <button
    id="delete"
    type="button"
    disabled={!opened || current === null}
    onclick={() => mutate('DELETE')}>{m.vaultDelete()}</button
  >
  <p id="status" role="status">{status}</p>
</main>
