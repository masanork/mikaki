<script lang="ts">
  import Vault from './Vault.svelte';
  import OwnerVault from './OwnerVault.svelte';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
  // Server-selected presentation, never an authorization decision.
  const newFormat = document.getElementById('app')?.dataset['vaultFormat'] === 'owner-v2';
</script>

{#if newFormat}<OwnerVault {locale} />{:else}<Vault {locale} />{/if}
