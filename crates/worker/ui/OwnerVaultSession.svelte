<script lang="ts">
  import { onMount, setContext, tick } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import { OwnerVaultController } from './vault-owner-controller.ts';
  import { VaultScope, type LockReason } from './vault-lifecycle.ts';
  import { OWNER_VAULT_CONTEXT, type OwnerVaultContext } from './vault-context.ts';
  import { subscribeVaultLock } from './session-events.ts';
  import OwnerVault from './OwnerVault.svelte';
  import ProductHeader from './ProductHeader.svelte';
  import * as m from './paraglide/messages.js';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
  let controller: OwnerVaultController | null = null;
  let epoch = 0;
  let opened = $state(false);
  let checking = $state(false);
  let suspended = $state(false);
  let reason: LockReason | null = $state(null);
  let error = $state('');
  const drafts = new SvelteSet<() => boolean>();
  const dirty = $derived([...drafts].some((read) => read()));
  const context: OwnerVaultContext = {
    current: () => {
      if (!controller) throw new Error('owner_key_locked');
      return controller;
    },
    registerDraft: (read) => {
      drafts.add(read);
      return () => {
        drafts.delete(read);
      };
    },
    lock: () => {
      if (dirty && !confirm(m.productVaultDiscard())) return;
      controller?.lock();
    },
  };
  setContext(OWNER_VAULT_CONTEXT, context);
  function locked(value: LockReason): void {
    opened = false;
    checking = false;
    suspended = false;
    reason = value;
    void tick().then(() => document.getElementById('owner-lock-title')?.focus());
  }
  async function unlock(): Promise<void> {
    if (checking || document.visibilityState !== 'visible') return;
    controller?.dispose();
    const token = ++epoch;
    const candidate = new OwnerVaultController(
      new VaultScope((value) => {
        if (token === epoch) locked(value);
      }),
      location.origin,
    );
    controller = candidate;
    checking = true;
    error = '';
    try {
      await candidate.open();
      if (token !== epoch) {
        candidate.dispose();
        return;
      }
      candidate.lease();
      opened = true;
      reason = null;
      suspended = false;
      await tick();
      document.getElementById('product-main')?.focus();
    } catch (cause) {
      candidate.dispose();
      if (token === epoch) {
        opened = false;
        error =
          cause instanceof DOMException && cause.name === 'NotAllowedError'
            ? m.productPasskeyCancelled()
            : cause instanceof Error && cause.message === 'prf_unsupported'
              ? m.vaultPrfUnsupported()
              : m.ownerVaultOpenFailed();
      }
    } finally {
      if (token === epoch) checking = false;
    }
  }
  async function resume(): Promise<void> {
    if (!opened || checking || !controller || document.visibilityState !== 'visible') return;
    const candidate = controller,
      token = epoch;
    checking = true;
    try {
      await candidate.resume();
    } catch {
      candidate.lock('unconfirmed');
    } finally {
      if (token === epoch) {
        checking = false;
        suspended = document.visibilityState !== 'visible';
      }
    }
  }
  $effect(() => {
    if (!opened || !dirty) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  });
  onMount(() => {
    const activity = (event: Event) => {
      if (opened && !checking && !suspended && event.isTrusted) {
        try {
          controller?.scope.activity();
        } catch {
          /* Lease already ended. */
        }
      }
    };
    const visibility = () => {
      if (document.visibilityState === 'hidden') {
        suspended = true;
        controller?.suspend();
      } else if (opened) void resume();
      else suspended = false;
    };
    const focus = () => {
      if (suspended) void resume();
    };
    const pagehide = () => controller?.lock('pagehide');
    const pageshow = (event: PageTransitionEvent) => {
      if (event.persisted && opened) void resume();
    };
    const unsubscribe = subscribeVaultLock(() => controller?.lock('external'));
    const interval = setInterval(() => {
      const expired = controller?.scope.expired();
      if (expired) controller?.lock(expired);
    }, 1000);
    for (const name of ['pointerdown', 'keydown', 'input']) window.addEventListener(name, activity);
    document.addEventListener('visibilitychange', visibility);
    window.addEventListener('focus', focus);
    window.addEventListener('pagehide', pagehide);
    window.addEventListener('pageshow', pageshow);
    return () => {
      epoch++;
      controller?.lock('pagehide');
      controller = null;
      clearInterval(interval);
      unsubscribe();
      for (const name of ['pointerdown', 'keydown', 'input'])
        window.removeEventListener(name, activity);
      document.removeEventListener('visibilitychange', visibility);
      window.removeEventListener('focus', focus);
      window.removeEventListener('pagehide', pagehide);
      window.removeEventListener('pageshow', pageshow);
    };
  });
</script>

{#if opened}
  <div hidden={suspended || checking} inert={suspended || checking}><OwnerVault {locale} /></div>
{/if}
{#if !opened || suspended || checking}
  <div class="vault-shell">
    <ProductHeader
      {locale}
      vaultHref={`/vault?lang=${locale}&storage=owner-v2`}
      contentId="owner-status-main"
      material
      paused={checking || suspended}
    />
    <main id="owner-status-main" tabindex="-1" class="product-result-shell">
      <section class="product-result" aria-labelledby="owner-lock-title" aria-busy={checking}>
        <span class="product-eyebrow">PERSONAL VAULT</span>
        <h1 id="owner-lock-title" tabindex="-1">
          {checking || suspended ? m.vaultSessionChecking() : m.vaultSessionLocked()}
        </h1>
        <p>{m.ownerVaultPreview()}</p>
        <p role="status">
          {error ||
            (checking || suspended
              ? m.vaultSessionCheckingBody()
              : reason === 'session'
                ? m.vaultSessionChanged()
                : reason === 'unconfirmed'
                  ? m.vaultSessionUnconfirmed()
                  : m.ownerVaultLockedBody())}
        </p>
        {#if !opened}<button
            id="owner-unlock"
            class="product-button product-primary"
            type="button"
            disabled={checking || suspended}
            onclick={unlock}>{m.ownerVaultUnlock()}</button
          >{/if}
      </section>
    </main>
  </div>
{/if}
