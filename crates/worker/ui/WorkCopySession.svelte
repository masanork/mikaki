<script lang="ts">
  import VaultSession from './VaultSession.svelte';
  import WorkCopyWorkspace from './WorkCopyWorkspace.svelte';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
</script>

<VaultSession {locale} preparationReview><WorkCopyWorkspace {locale} /></VaultSession>
