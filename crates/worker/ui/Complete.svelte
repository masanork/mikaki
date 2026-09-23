<script lang="ts">
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import type { Locale } from './paraglide/runtime.js';

  let { locale, admin }: { locale: Locale; admin: boolean } = $props();
</script>

<main>
  <label
    >{m.language()}
    <select
      aria-label={m.language()}
      value={locale}
      onchange={(event) => switchLocale(event.currentTarget.value)}
    >
      <option value="ja">日本語</option>
      <option value="en">English</option>
    </select>
  </label>
  <h1>{m.enrollCompleteHeading()}</h1>
  <p>{m.enrollCompleteBody()}</p>
  {#if admin}<a href="/admin">{m.enrollAdminLink()}</a>{/if}
</main>
