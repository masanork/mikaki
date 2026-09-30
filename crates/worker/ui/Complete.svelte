<script lang="ts">
  import * as m from './paraglide/messages.js';
  import ProductHeader from './ProductHeader.svelte';
  import type { Locale } from './paraglide/runtime.js';

  let { locale, admin }: { locale: Locale; admin: boolean } = $props();
</script>

<ProductHeader {locale} />
<main class="product-result-shell">
  <div class="product-result">
    <div class="product-result-icon is-success" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
        ><path d="m5 12 4 4L19 6" /></svg
      >
    </div>
    <span class="product-eyebrow">READY TO GO</span>
    <h1>{m.enrollCompleteHeading()}</h1>
    <p>{m.enrollCompleteBody()}</p>
    <a class="product-button product-primary" href="/vault?lang={locale}"
      >{m.productVaultLink()} <span aria-hidden="true">→</span></a
    >
    {#if admin}<a class="product-button" href="/admin?lang={locale}">{m.enrollAdminLink()}</a>{/if}
    <footer class="product-footer">mikaki · PRIVATE BY DESIGN</footer>
  </div>
</main>
