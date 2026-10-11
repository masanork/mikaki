<script lang="ts">
  import VaultSession from './VaultSession.svelte';
  import OwnerWorkspace from './OwnerWorkspace.svelte';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
</script>

<VaultSession {locale}><OwnerWorkspace {locale} /></VaultSession>
