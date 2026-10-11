<script lang="ts">
  import VaultSession from './VaultSession.svelte';
  import WorkPreparationWorkspace from './WorkPreparationWorkspace.svelte';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
</script>

<VaultSession {locale} preparationReview><WorkPreparationWorkspace {locale} /></VaultSession>
