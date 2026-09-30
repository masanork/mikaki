<script lang="ts">
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import type { Locale } from './paraglide/runtime.js';
  let { locale, session = true }: { locale: Locale; session?: boolean } = $props();
</script>

<header class="product-header">
  <div class="product-header-inner">
    <a class="auth-brand product-brand" href="/" aria-label="mikaki">
      <span class="auth-mark" aria-hidden="true"
        ><span></span><span></span><span></span><span></span></span
      >
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
      {#if session}<a class="product-signout" href="/logout?lang={locale}"
          >{m.logoutTitle()} <span aria-hidden="true">↗</span></a
        >{/if}
    </div>
  </div>
</header>
