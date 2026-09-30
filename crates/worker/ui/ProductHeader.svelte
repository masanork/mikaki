<script lang="ts">
  import BrandMark from './BrandMark.svelte';
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import type { Locale } from './paraglide/runtime.js';
  let {
    locale,
    session = true,
    onlock,
  }: { locale: Locale; session?: boolean; onlock?: () => void } = $props();
</script>

<header class="product-header">
  <div class="product-header-inner">
    <a class="auth-brand product-brand" href="/" aria-label="mikaki">
      <BrandMark />
      mikaki
    </a>
    <span class="product-brand-tag">PRIVATE BY DESIGN</span>
    <div class="product-toolbar">
      <label class="product-language"
        >{m.language()}
        <select
          aria-label={m.language()}
          value={locale}
          onchange={(event) => {
            const next = event.currentTarget.value;
            event.currentTarget.value = locale;
            switchLocale(next);
          }}
        >
          <option value="ja">日本語</option><option value="en">English</option>
        </select>
      </label>
      {#if onlock}<button class="product-signout product-lock-button" type="button" onclick={onlock}
          >{m.vaultSessionLockAction()}</button
        >{/if}
      {#if session}<a class="product-signout" href="/logout?lang={locale}"
          >{m.logoutTitle()} <span aria-hidden="true">↗</span></a
        >{/if}
    </div>
  </div>
</header>
