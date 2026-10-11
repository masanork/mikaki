<script lang="ts">
  import VaultSession from './VaultSession.svelte';
  import WorkSourceWorkspace from './WorkSourceWorkspace.svelte';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
</script>

<VaultSession {locale} sourceReview><WorkSourceWorkspace {locale} /></VaultSession>
