<script lang="ts">
  import BrandMark from './BrandMark.svelte';
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import type { Locale } from './paraglide/runtime.js';
  import { onMount } from 'svelte';
  import WovenGate from './WovenGate.svelte';
  import { weaveProfile } from './woven-gate.js';
  let {
    locale,
    contentId = 'product-main',
    session = true,
    onlock,
    material = false,
    paused = false,
  }: {
    locale: Locale;
    contentId?: string;
    session?: boolean;
    onlock?: () => void;
    material?: boolean;
    paused?: boolean;
  } = $props();
  const page = new URL(location.href);
  let header: HTMLElement;
  $effect(() => {
    const surface = header?.closest<HTMLElement>('.vault-shell, .product-material-shell');
    if (surface) surface.dataset.materialPaused = String(paused);
  });
  onMount(() => {
    if (!material) return;
    const profile = weaveProfile(page.origin);
    const surface = header.closest<HTMLElement>('.vault-shell, .product-material-shell') ?? header;
    // CSSOM properties work under the product's self-only style policy.
    surface.style.setProperty('--page-hue', String(profile.hue));
    surface.style.setProperty('--rp-hue', String(profile.hue));
    surface.style.setProperty('--grain-step', `${profile.spacing / 2}px`);
    surface.style.setProperty('--grain-angle', `${profile.grainAngle}deg`);
  });
</script>

<a
  class="product-skip"
  href={`#${contentId}`}
  onclick={(event) => {
    const main = document.getElementById(contentId);
    if (main) {
      event.preventDefault();
      main.focus();
    }
  }}>{m.productSkipContent()}</a
>
<header class="product-header" class:product-material={material} bind:this={header}>
  {#if material}
    <WovenGate
      pageOrigin={page.origin}
      rpOrigin={page.origin}
      {paused}
      layout="fence"
      sceneSelector=".product-material"
      tiltControl={false}
    />
  {/if}
  <div class="product-header-inner">
    <a
      class="auth-brand product-brand"
      href={session ? `/vault?lang=${locale}` : '/'}
      aria-label="mikaki"
    >
      {#if !material}<BrandMark />{/if}
      mikaki
    </a>
    {#if material}
      <div class="product-origin">
        <span>{m.authOriginLabel()}</span><strong>{page.host}</strong>
      </div>
    {:else}<span class="product-brand-tag">PRIVATE BY DESIGN</span>{/if}
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
