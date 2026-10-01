<script lang="ts">
  import { onMount, setContext, tick } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import Vault from './Vault.svelte';
  import ProductHeader from './ProductHeader.svelte';
  import * as m from './paraglide/messages.js';
  import type { Locale } from './paraglide/runtime.js';
  import { VaultScope, type LockReason } from './vault-lifecycle.js';
  import { VAULT_CONTEXT } from './vault-context.js';
  import { subscribeVaultLock } from './session-events.js';
  let { locale }: { locale: Locale } = $props();
  let reason: LockReason | null = $state(null);
  let checking = $state(false);
  let suspended = $state(false);
  let generation = $state(0);
  let scope = new VaultScope(locked);
  const drafts = new SvelteSet<() => boolean>();
  const dirty = $derived([...drafts].some((read) => read()));
  setContext(VAULT_CONTEXT, {
    current: () => scope,
    registerDraft: (read: () => boolean) => {
      drafts.add(read);
      return () => {
        drafts.delete(read);
      };
    },
    lock: () => {
      if (dirty && !confirm(m.productVaultDiscard())) return;
      scope.end('manual');
    },
  });
  $effect(() => {
    if (reason || !dirty) return;
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (reason) return;
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', beforeUnload);
    return () => window.removeEventListener('beforeunload', beforeUnload);
  });
  function locked(value: LockReason): void {
    reason = value;
    checking = false;
    suspended = false;
    void tick().then(() => document.getElementById('vault-lock-title')?.focus());
  }
  async function resume(): Promise<void> {
    if (reason || checking || document.visibilityState !== 'visible') return;
    checking = true;
    try {
      await scope.verify();
    } catch {
      scope.end('unconfirmed');
    } finally {
      checking = false;
      suspended = document.visibilityState !== 'visible';
    }
  }
  async function reopen(): Promise<void> {
    if (checking) return;
    checking = true;
    const candidate = new VaultScope(locked);
    scope = candidate;
    await candidate.verify();
    if (!candidate.signal.aborted) {
      scope = candidate;
      generation += 1;
      reason = null;
      suspended = false;
    }
    checking = false;
  }
  onMount(() => {
    const activity = (event: Event) => {
      if (!reason && !checking && !suspended && event.isTrusted) {
        try {
          scope.activity();
        } catch {
          /* The deadline already locked the scope. */
        }
      }
    };
    const visibility = () => {
      if (document.visibilityState === 'hidden') suspended = true;
      else void resume();
    };
    const focus = () => {
      if (suspended) void resume();
    };
    const pagehide = () => scope.end('pagehide');
    const pageshow = (event: PageTransitionEvent) => {
      if (event.persisted && !reason) void resume();
    };
    const unsubscribe = subscribeVaultLock(() => scope.end('external'));
    const interval = setInterval(() => {
      const expired = scope.expired();
      if (expired) scope.end(expired);
    }, 1000);
    for (const name of ['pointerdown', 'keydown', 'input']) window.addEventListener(name, activity);
    document.addEventListener('visibilitychange', visibility);
    window.addEventListener('focus', focus);
    window.addEventListener('pagehide', pagehide);
    window.addEventListener('pageshow', pageshow);
    return () => {
      scope.end('pagehide');
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

{#if !reason}
  <div hidden={suspended || checking} inert={suspended || checking}>
    {#key generation}<Vault {locale} />{/key}
  </div>
{/if}
{#if reason || suspended || checking}
  <div class="vault-shell">
    <ProductHeader {locale} material paused={checking || suspended} />
    <main class="product-result-shell">
      <section class="product-result" aria-labelledby="vault-lock-title" aria-busy={checking}>
        <div class="product-result-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
            ><rect x="5" y="10" width="14" height="11" rx="2" /><path
              d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"
            /></svg
          >
        </div>
        <span class="product-eyebrow">PERSONAL VAULT</span>
        <h1 id="vault-lock-title" tabindex="-1">
          {checking || suspended ? m.vaultSessionChecking() : m.vaultSessionLocked()}
        </h1>
        <p role="status">
          {checking || suspended
            ? m.vaultSessionCheckingBody()
            : reason === 'session'
              ? m.vaultSessionChanged()
              : reason === 'unconfirmed'
                ? m.vaultSessionUnconfirmed()
                : m.vaultSessionLockedBody()}
        </p>
        {#if reason && !checking}<button
            class="product-button product-primary"
            type="button"
            onclick={reopen}>{m.vaultSessionReopen()}</button
          >{/if}
      </section>
    </main>
  </div>
{/if}
