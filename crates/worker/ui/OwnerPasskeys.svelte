<script lang="ts">
  import { onMount } from 'svelte';
  import { restoreActionFocus } from './action-focus.ts';
  import * as m from './paraglide/messages.js';
  import type { OwnerVaultController } from './vault-owner-controller.ts';
  import {
    readOwnerKeyWrappers,
    commitOwnerKeyWrapperOperation,
    type OwnerKeyWrapperOperation,
  } from './vault-owner-store.ts';
  import {
    listOwnerPasskeys,
    prepareOwnerPasskey,
    finishOwnerPasskey,
    type PreparedPasskeyRegistration,
  } from './vault-owner-passkeys.ts';
  let {
    owner,
    disabled,
    hasDrafts,
    onbusy,
  }: {
    owner: OwnerVaultController;
    disabled: boolean;
    hasDrafts: () => boolean;
    onbusy: (value: boolean) => void;
  } = $props();
  let rows: { id: string; wrapped: boolean; active: boolean }[] = $state([]);
  let loading = $state(false);
  let initialized = $state(false);
  let expanded = $state(false);
  let status = $state('');
  let pending: OwnerKeyWrapperOperation | null = $state(null);
  let registration: PreparedPasskeyRegistration | null = $state(null);
  const source = $derived(owner.scope.identity?.credential_id);

  async function load() {
    await owner.scope.ensure();
    const token = owner.checkpoint();
    await owner.verifyAuthority();
    owner.assertCurrent(token);
    const [login, registry] = await Promise.all([
      listOwnerPasskeys(owner),
      readOwnerKeyWrappers(owner.scope, owner.lease().stored),
    ]);
    owner.assertCurrent(token);
    const entries = new Map(login.map((id) => [id, { id, wrapped: false, active: true }]));
    for (const wrapped of registry.credentials)
      entries.set(wrapped.credentialId, {
        id: wrapped.credentialId,
        wrapped: true,
        active: wrapped.active,
      });
    rows = [...entries.values()];
  }
  function failed(error: unknown) {
    if (owner.scope.signal.aborted) return;
    status =
      error instanceof Error && error.message === 'fresh_login_or_capacity_required'
        ? m.ownerPasskeysFreshLogin()
        : error instanceof Error && error.message === 'owner_unsaved_changes'
          ? m.productUnsavedChanges()
          : m.ownerPasskeysFailed();
  }
  async function run(action: () => Promise<void>) {
    if (disabled || loading) return;
    const focus = document.activeElement;
    loading = true;
    onbusy(true);
    try {
      await action();
    } catch (error) {
      failed(error);
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () => document.getElementById('owner-passkeys-refresh'));
    }
  }
  async function finishRegistration() {
    if (!registration) return;
    await finishOwnerPasskey(owner, registration);
    registration = null;
    await load();
    status = m.ownerPasskeysLoginAdded();
  }
  async function enroll() {
    registration = await prepareOwnerPasskey(owner);
    await finishRegistration();
  }
  async function commit() {
    if (!pending) return;
    if (hasDrafts()) throw new Error('owner_unsaved_changes');
    const token = owner.checkpoint();
    await owner.scope.verify();
    owner.assertCurrent(token);
    if (hasDrafts()) throw new Error('owner_unsaved_changes');
    try {
      await commitOwnerKeyWrapperOperation(owner.scope, pending);
    } catch (error) {
      if (error instanceof Error && error.message === 'owner_wrapper_conflict') {
        pending = null;
        owner.lock('unconfirmed');
      } else if (
        error instanceof Error &&
        ['owner_wrapper_origin', 'owner_wrapper_session', 'owner_wrapper_rejected'].includes(
          error.message,
        )
      ) {
        pending = null;
        if (error.message === 'owner_wrapper_session') owner.lock('unconfirmed');
      }
      throw error;
    }
    owner.assertCurrent(token);
    pending = null;
    owner.lock();
  }
  async function authorize(id: string) {
    if (!confirm(m.ownerPasskeysAuthorizeConfirm())) return;
    pending = await owner.prepareWrapper(id);
    await commit();
  }
  async function remove(id: string) {
    if (!confirm(m.ownerPasskeysRemoveConfirm())) return;
    pending = await owner.prepareWrapperRemoval(id);
    await commit();
  }
  onMount(() => {
    const clear = () => {
      pending = null;
      registration = null;
      rows = [];
      status = '';
    };
    owner.scope.signal.addEventListener('abort', clear, { once: true });
    return () => {
      clear();
      owner.scope.signal.removeEventListener('abort', clear);
    };
  });
  $effect(() => {
    if (expanded && !disabled && !loading && !initialized) {
      initialized = true;
      void run(load);
    }
  });
</script>

<details
  id="owner-passkeys"
  aria-busy={loading}
  ontoggle={(event) => (expanded = event.currentTarget.open)}
>
  <summary>{m.ownerPasskeysHeading()}</summary>
  <p>{m.ownerPasskeysExplanation()}</p>
  <p>{m.ownerPasskeysRecovery()}</p>
  <div class="product-actions">
    <button
      id="owner-passkeys-enroll"
      disabled={disabled || loading || pending !== null || registration !== null}
      onclick={() => run(enroll)}>{m.ownerPasskeysEnroll()}</button
    >
    <button
      id="owner-passkeys-refresh"
      disabled={disabled || loading || pending !== null || registration !== null}
      onclick={() => run(load)}>{m.ownerPasskeysRefresh()}</button
    >
  </div>
  <ul>
    {#each rows as row (row.id)}
      <li>
        <code>{row.id.slice(0, 12)}…</code>
        {row.id === source
          ? m.ownerPasskeysCurrent()
          : row.active
            ? row.wrapped
              ? m.ownerPasskeysAuthorized()
              : m.ownerPasskeysLoginOnly()
            : m.ownerPasskeysInactive()}
        {#if row.id !== source}
          {#if row.wrapped}
            <button
              disabled={disabled || loading || pending !== null || registration !== null}
              onclick={() => run(() => remove(row.id))}>{m.ownerPasskeysRemove()}</button
            >
          {:else if row.active}
            <button
              disabled={disabled || loading || pending !== null || registration !== null}
              onclick={() => run(() => authorize(row.id))}>{m.ownerPasskeysAuthorize()}</button
            >
          {/if}
        {/if}
      </li>
    {/each}
  </ul>
  {#if pending}<button
      id="owner-passkeys-retry"
      disabled={disabled || loading}
      onclick={() => run(commit)}>{m.ownerPasskeysRetry()}</button
    >{/if}
  {#if registration}<button
      id="owner-passkeys-registration-retry"
      disabled={disabled || loading}
      onclick={() => run(finishRegistration)}>{m.ownerPasskeysRegistrationRetry()}</button
    >{/if}
  <p role="status" aria-live="polite">{status}</p>
</details>
