<script lang="ts">
  import Vault from './Vault.svelte';
  import OwnerWorkspace from './OwnerWorkspace.svelte';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
  // Server-selected presentation, never an authorization decision.
  const legacy = new URL(location.href).searchParams.get('storage') === 'legacy-v1';
  const newFormat =
    !legacy && document.getElementById('app')?.dataset['vaultFormat'] === 'owner-v2';
</script>

{#if newFormat}<OwnerWorkspace {locale} />{:else}<Vault {locale} />{/if}
