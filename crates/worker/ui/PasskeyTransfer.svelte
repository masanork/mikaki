<script lang="ts">
  import { vaultScope, vaultContext } from './vault-context.js';
  const context = vaultContext();
  const scope = vaultScope();
  const fetch = scope.request;
  import { onMount } from 'svelte';
  import {
    decodeBase64Url,
    encodeBase64Url,
    newPrfInput,
    parseOwnerEnvelope,
    transferAttribute,
    type SealedAttribute,
  } from './vault-crypto.js';
  import * as m from './paraglide/messages.js';
  import { decodeOwnerNote } from './vault-note.js';

  let {
    saved,
    opened,
    evaluatePrf,
    changed,
    beforeTransfer = () => true,
    attribute = 'name',
    disabled = false,
    onBusy = () => {},
  }: {
    saved: (SealedAttribute & { revision: number }) | null;
    opened: boolean;
    evaluatePrf: (
      credential: Uint8Array<ArrayBuffer>,
      input: Uint8Array<ArrayBuffer>,
    ) => Promise<Uint8Array<ArrayBuffer>>;
    changed: () => Promise<void>;
    beforeTransfer?: () => boolean;
    attribute?: 'name' | 'owner_note';
    disabled?: boolean;
    onBusy?: (busy: boolean) => void;
  } = $props();
  let credentials: string[] = $state([]);
  let selected = $state('');
  let consent = $state(false);
  let busy = $state(false);
  let status = $state('');
  let pendingTransfer: {
    attribute: string;
    target: string;
    revision: number;
    id: string;
    body: string;
  } | null = $state(null);
  let pendingRegistration: {
    transaction_id: string;
    response: { id: string; client_data: string; attestation: string };
  } | null = $state(null);
  const heading = $derived(
    attribute === 'owner_note' ? m.vaultNoteTransferHeading() : m.vaultTransferHeading(),
  );
  const sourceId = $derived.by(() => {
    try {
      return saved ? encodeBase64Url(parseOwnerEnvelope(saved.owner_envelope).credentialId) : '';
    } catch {
      // The main unlock flow reports invalid envelopes; do not crash the page while locked.
      return '';
    }
  });

  async function refresh() {
    const response = await fetch('/vault/passkeys', { cache: 'no-store' });
    if (!response.ok) throw new Error(m.vaultPasskeyFailed());
    const ids: unknown = await response.json();
    if (
      !Array.isArray(ids) ||
      ids.length > 10 ||
      !ids.every(
        (id: unknown) =>
          typeof id === 'object' &&
          id !== null &&
          'credential_id' in id &&
          typeof id.credential_id === 'string',
      )
    )
      throw new Error(m.vaultPasskeyFailed());
    credentials = ids.map((id: { credential_id: string }) => id.credential_id);
  }

  async function register() {
    if (busy || disabled || pendingTransfer || !consent) return;
    busy = true;
    onBusy(true);
    try {
      if (!pendingRegistration) {
        const started = await fetch('/vault/passkeys/start', { method: 'POST' });
        if (!started.ok) throw new Error(m.vaultPasskeyFreshLogin());
        const options: unknown = await started.json();
        if (
          typeof options !== 'object' ||
          options === null ||
          !('transaction_id' in options) ||
          typeof options.transaction_id !== 'string' ||
          !('challenge' in options) ||
          typeof options.challenge !== 'string' ||
          !('rp_id' in options) ||
          typeof options.rp_id !== 'string' ||
          !('user_handle' in options) ||
          typeof options.user_handle !== 'string' ||
          !('exclude_credentials' in options) ||
          !Array.isArray(options.exclude_credentials)
        )
          throw new Error(m.vaultPasskeyFailed());
        await scope.ensure();
        const credential = await navigator.credentials.create({
          signal: scope.signal,
          publicKey: {
            challenge: decodeBase64Url(options.challenge),
            rp: { id: options.rp_id, name: 'mikaki' },
            user: {
              id: decodeBase64Url(options.user_handle),
              name: 'mikaki account',
              displayName: 'mikaki',
            },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            excludeCredentials: options.exclude_credentials.map((item: unknown) => {
              if (
                typeof item !== 'object' ||
                item === null ||
                !('credential_id' in item) ||
                typeof item.credential_id !== 'string'
              )
                throw new Error(m.vaultPasskeyFailed());
              return { type: 'public-key' as const, id: decodeBase64Url(item.credential_id) };
            }),
            authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
            attestation: 'none',
            timeout: 120000,
            extensions: { credProps: true, prf: {} },
          },
        });
        if (
          !(credential instanceof PublicKeyCredential) ||
          !(credential.response instanceof AuthenticatorAttestationResponse) ||
          credential.getClientExtensionResults().credProps?.rk !== true
        )
          throw new Error(m.vaultPasskeyFailed());
        await scope.ensure();
        pendingRegistration = {
          transaction_id: options.transaction_id,
          response: {
            id: credential.id,
            client_data: encodeBase64Url(new Uint8Array(credential.response.clientDataJSON)),
            attestation: encodeBase64Url(new Uint8Array(credential.response.attestationObject)),
          },
        };
      }
      const response = await fetch('/vault/passkeys/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pendingRegistration),
      });
      if (!response.ok) throw new Error(m.vaultPasskeyFailed());
      selected = pendingRegistration.response.id;
      pendingRegistration = null;
      await refresh();
      status = m.vaultPasskeyAdded();
    } catch (error) {
      status = error instanceof Error ? error.message : m.vaultPasskeyFailed();
    } finally {
      busy = false;
      onBusy(false);
    }
  }

  async function transfer() {
    if (busy || disabled || !consent || !opened || !saved || !selected || selected === sourceId)
      return;
    if (!pendingTransfer && !beforeTransfer()) return;
    busy = true;
    onBusy(true);
    try {
      if (
        pendingTransfer &&
        (pendingTransfer.target !== selected || pendingTransfer.attribute !== attribute)
      )
        throw new Error(m.vaultRetryChanged());
      if (!pendingTransfer) {
        const snapshot = saved;
        const source = parseOwnerEnvelope(snapshot.owner_envelope);
        const sourceOutput = await evaluatePrf(source.credentialId, source.prfInput);
        try {
          const targetInput = newPrfInput();
          const targetCredential = decodeBase64Url(selected);
          const targetOutput = await evaluatePrf(targetCredential, targetInput);
          try {
            const sealed = await transferAttribute(
              snapshot,
              sourceOutput,
              targetOutput,
              targetCredential,
              targetInput,
              location.origin,
              attribute,
              snapshot.revision,
              attribute === 'owner_note'
                ? (bytes) => {
                    try {
                      decodeOwnerNote(bytes);
                    } catch {
                      throw new Error(m.vaultNoteInvalidImport());
                    }
                  }
                : undefined,
            );
            pendingTransfer = {
              attribute,
              target: selected,
              revision: snapshot.revision,
              id: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
              body: JSON.stringify(sealed),
            };
          } finally {
            targetOutput.fill(0);
          }
        } finally {
          sourceOutput.fill(0);
        }
      }
      const operation = pendingTransfer;
      const response = await fetch(`/vault/attributes/${operation.attribute}/transfer`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Operation-ID': operation.id,
          'If-Match': `"${operation.revision}"`,
        },
        body: operation.body,
      });
      if (response.status === 409) throw new Error(m.vaultConflict());
      if (!response.ok) throw new Error(m.vaultPasskeyFailed());
      pendingTransfer = null;
      await changed();
      status = attribute === 'owner_note' ? m.vaultNoteTransferSaved() : m.vaultTransferSaved();
    } catch (error) {
      status = error instanceof Error ? error.message : m.vaultPasskeyFailed();
    } finally {
      busy = false;
      onBusy(false);
    }
  }
  onMount(() => {
    void refresh().catch(() => {});
    return context.registerDraft(
      () => pendingTransfer !== null || pendingRegistration !== null || busy,
    );
  });
</script>

<section aria-label={heading}>
  <h2>{heading}</h2>
  <p>
    {attribute === 'owner_note' ? m.vaultNoteTransferExplanation() : m.vaultTransferExplanation()}
  </p>
  <label
    ><input type="checkbox" bind:checked={consent} disabled={busy || disabled} />{attribute ===
    'owner_note'
      ? m.vaultNoteTransferConsent()
      : m.vaultTransferConsent()}</label
  >
  <button
    type="button"
    disabled={busy || disabled || pendingTransfer !== null || !consent}
    onclick={register}>{m.vaultPasskeyAdd()}</button
  >
  <label
    >{attribute === 'owner_note' ? m.vaultNoteTransferTarget() : m.vaultTransferTarget()}
    <select
      bind:value={selected}
      disabled={busy || disabled || pendingTransfer !== null}
      onfocus={() => {
        void refresh().catch(() => {});
      }}
    >
      <option value="">{m.vaultTransferSelect()}</option>
      {#each credentials.filter((id) => id !== sourceId) as id}<option value={id}>{id}</option
        >{/each}
    </select>
  </label>
  <button
    class="product-primary"
    type="button"
    disabled={busy ||
      disabled ||
      !consent ||
      !opened ||
      !saved ||
      !selected ||
      selected === sourceId}
    onclick={transfer}
    >{attribute === 'owner_note' ? m.vaultNoteTransferAction() : m.vaultTransferAction()}</button
  >
  {#if pendingTransfer || pendingRegistration}
    <button
      type="button"
      disabled={busy}
      onclick={() => {
        pendingTransfer = null;
        pendingRegistration = null;
        status = m.vaultTransferDiscarded();
      }}>{m.vaultTransferDiscard()}</button
    >
  {/if}
  <p role="status">{status}</p>
</section>
