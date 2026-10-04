<script lang="ts">
  import { ownerVaultContext } from './vault-context.ts';
  import { OWNER_NAME, OWNER_NOTE } from './vault-owner-record-store.ts';
  import ProductHeader from './ProductHeader.svelte';
  import OwnerRecordEditor from './OwnerRecordEditor.svelte';
  import * as m from './paraglide/messages.js';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
  const context = ownerVaultContext();
</script>

<div class="vault-shell">
  <ProductHeader {locale} vaultHref={`/vault?lang=${locale}`} onlock={context.lock} material />
  <main id="product-main" tabindex="-1" class="product-main">
    <div class="product-heading">
      <h1>{m.vaultHeading()}</h1>
      <p>{m.ownerVaultReady()}</p>
    </div>
    <p role="note">{m.ownerVaultPreview()}</p>
    <div class="product-workspace">
      <nav class="product-nav" aria-label={m.vaultHeading()}>
        <a href="#owner-profile">{m.productProfile()}</a>
        <a href="#owner-note">{m.vaultNoteHeading()}</a>
        <a href="#owner-connections">{m.productSharing()}</a>
      </nav>
      <div class="product-content">
        <OwnerRecordEditor target={OWNER_NAME} />
        <OwnerRecordEditor target={OWNER_NOTE} />
        <section id="owner-connections" aria-labelledby="owner-connections-title">
          <h2 id="owner-connections-title">{m.productSharing()}</h2>
          <p>{m.ownerVaultAdapterBoundary()}</p>
        </section>
      </div>
    </div>
  </main>
</div>
