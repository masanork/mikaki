<script lang="ts">
  import type { Locale } from './paraglide/runtime.js';
  let { className = '', locale }: { className?: string; locale: Locale } = $props();
  // A UI hint, never authentication or an IPC permission.
  const native = '__MIKAKI_NATIVE__' in window;
</script>

{#if native}
  <a
    class={className}
    href="https://auth.mikaki.org/native/wallet"
    aria-label={locale === 'ja' ? 'この端末のWalletを開く' : 'Open device Wallet'}>Wallet</a
  >
{/if}
