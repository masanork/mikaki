<script lang="ts">
  import { onMount } from 'svelte';
  import ProductHeader from './ProductHeader.svelte';
  import ProductChat from './ProductChat.svelte';
  import OwnerPasskeys from './OwnerPasskeys.svelte';
  import { vaultContext } from './vault-context.js';
  import { OwnerVaultController, evaluateOwnerPrf } from './vault-owner-controller.ts';
  import type { OwnerLoginPrf } from './vault-login-prf.ts';
  import type { Locale } from './paraglide/runtime.js';
  import * as m from './paraglide/messages.js';

  let { locale, takeLogin }: { locale: Locale; takeLogin?: () => OwnerLoginPrf | undefined } =
    $props();
  const native = '__MIKAKI_NATIVE__' in window;
  const context = vaultContext(),
    scope = context.current();
  let owner: OwnerVaultController | null = $state(null);
  let tab = $state(location.hash === '#chat' ? 'chat' : 'wallet');
  let busy = $state(false),
    status = $state(''),
    settings = $state(false);
  let passkeysBusy = $state(false),
    unconfirmed = $state(false);
  const ja = $derived(locale === 'ja');
  function select(value: string) {
    if (!settings && value === tab) return;
    if (context.hasDrafts?.() && !confirm(m.productVaultDiscard())) return;
    settings = false;
    tab = value;
    history.replaceState(history.state, '', `#${value}`);
  }
  function toggleSettings() {
    if (context.hasDrafts?.() && !confirm(m.productVaultDiscard())) return;
    settings = !settings;
  }
  async function unlock(ticket?: OwnerLoginPrf) {
    if (owner || busy) return;
    busy = true;
    const candidate = new OwnerVaultController(
      scope,
      location.origin,
      ticket
        ? async (credential, input, signal) => {
            const initial = ticket;
            ticket = undefined;
            return (
              initial?.consume(credential, input, signal) ??
              evaluateOwnerPrf(credential, input, signal)
            );
          }
        : evaluateOwnerPrf,
    );
    try {
      await scope.verify();
      await candidate.open(Boolean(ticket));
      scope.assert();
      owner = candidate;
      status = '';
    } catch (error) {
      candidate.dispose();
      if (!scope.signal.aborted)
        status =
          error instanceof DOMException && error.name === 'NotAllowedError'
            ? m.productPasskeyCancelled()
            : error instanceof Error && error.message === 'prf_unsupported'
              ? m.vaultPrfUnsupported()
              : error instanceof Error && error.message === 'credential_not_wrapped'
                ? m.ownerVaultLoginAccessMissing()
                : m.error();
    } finally {
      ticket?.dispose();
      busy = false;
    }
  }
  onMount(() => {
    const initial = takeLogin?.();
    if (initial) void unlock(initial);
    else void scope.verify().catch(() => scope.end('unconfirmed'));
    const unregister = context.registerResume(async () => {
      if (owner) await owner.resume();
    });
    const visibility = () => {
      if (document.hidden) owner?.suspend();
    };
    document.addEventListener('visibilitychange', visibility);
    return () => {
      unregister();
      document.removeEventListener('visibilitychange', visibility);
      owner?.dispose();
    };
  });
</script>

<div class="vault-shell product-mvp">
  <ProductHeader {locale} showOrigin onlock={context.lock} lockLabel={ja ? 'ロック' : 'Lock'} />
  <main id="product-main" class="product-main" tabindex="-1">
    <div class="product-heading">
      <h1>mikaki</h1>
      <button type="button" aria-expanded={settings} onclick={toggleSettings}
        >{ja ? '設定' : 'Settings'}</button
      >
    </div>
    <nav class="mvp-tabs" aria-label={ja ? '画面' : 'Pages'}>
      <button
        type="button"
        aria-current={tab === 'wallet' ? 'page' : undefined}
        onclick={() => select('wallet')}>Wallet</button
      >
      <button
        type="button"
        aria-current={tab === 'chat' ? 'page' : undefined}
        onclick={() => select('chat')}>Chat</button
      >
    </nav>
    {#if settings}
      <section class="product-card" aria-label={ja ? '設定' : 'Settings'}>
        <h2>{ja ? '設定' : 'Settings'}</h2>
        {#if owner}<OwnerPasskeys
            {owner}
            disabled={passkeysBusy}
            hasDrafts={() => context.hasDrafts?.() ?? false}
            onbusy={(value) => (passkeysBusy = value)}
            onunconfirmed={(value) => (unconfirmed = value)}
          />
        {:else}<p>
            {ja ? 'パスキーの管理にはロック解除が必要です。' : 'Unlock to manage passkeys.'}
          </p>
          <button type="button" class="product-primary" disabled={busy} onclick={() => unlock()}
            >{m.vaultUnlock()}</button
          >
          <p role="status">{status}</p>{/if}
      </section>
    {:else if tab === 'wallet'}
      <section class="product-card mvp-empty" aria-labelledby="wallet-title">
        <h2 id="wallet-title">Wallet</h2>
        <p>
          {ja
            ? '本人確認をして証明書を受け取り、必要な相手に提示します。'
            : 'Receive credentials and present what you need to the right person.'}
        </p>
        <a class="mvp-primary" href={native ? '/native/wallet' : 'mikaki-wallet:'}
          >{ja ? 'Walletアプリで開く' : 'Open the Wallet app'}</a
        >
        <p class="product-muted">
          {ja
            ? '本人確認書類の読取と証明書の保管・提示は、スマートフォンのMikakiアプリで行います。'
            : 'Read identity documents, keep credentials and present them in the Mikaki mobile app.'}
        </p>
      </section>
    {:else if !owner}
      <section class="product-card mvp-empty" aria-labelledby="chat-title" aria-busy={busy}>
        <h2 id="chat-title">Chat</h2>
        <p>
          {ja
            ? '相手と1対1で、暗号化されたメッセージをやり取りします。'
            : 'Exchange encrypted messages with one other person.'}
        </p>
        <button
          id="unlock"
          class="product-primary"
          type="button"
          disabled={busy}
          onclick={() => unlock()}>{m.vaultUnlock()}</button
        >
        <p role="status">{status}</p>
      </section>
    {:else}
      <ProductChat {owner} {locale} disabled={passkeysBusy || unconfirmed} />
    {/if}
  </main>
</div>
