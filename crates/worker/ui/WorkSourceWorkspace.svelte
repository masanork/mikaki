<script lang="ts">
  import { onMount } from 'svelte';
  import ProductHeader from './ProductHeader.svelte';
  import WorkSources from './WorkSources.svelte';
  import { vaultContext } from './vault-context.js';
  import { sourceHttpPort } from './work-source-view.js';
  import * as m from './paraglide/messages.js';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
  const context = vaultContext(),
    scope = context.current();
  const port = sourceHttpPort(scope.request);
  let ready = $state(false);
  onMount(() => {
    void scope
      .verify()
      .then(async () => {
        await scope.ensure();
        ready = true;
      })
      .catch(() => scope.end('unconfirmed'));
  });
</script>

<div class="vault-shell">
  <ProductHeader {locale} onlock={context.lock} lockLabel={m.source_lock()} material />
  <main id="product-main" tabindex="-1" class="product-main source-page">
    <div class="product-heading"><h1>{m.source_title()}</h1></div>
    {#if ready}<WorkSources {port} />{:else}<p role="status">{m.source_loading()}</p>{/if}
  </main>
</div>
