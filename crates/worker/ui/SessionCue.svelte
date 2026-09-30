<script lang="ts">
  import { onMount } from 'svelte';

  let {
    seed,
    cueUrl,
    pageUri,
    rpUri,
    pageLabel,
    rpLabel,
    hint,
    onSeed,
  }: {
    seed: string;
    cueUrl?: string;
    pageUri: string;
    rpUri: string;
    pageLabel: string;
    rpLabel: string;
    hint: string;
    onSeed?: (value: string) => void;
  } = $props();

  let liveSeed = $state('');

  onMount(() => {
    const endpoint = cueUrl;
    if (!endpoint || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function refresh(): Promise<void> {
      let delay = 10_000;
      try {
        const response = await fetch(endpoint, { cache: 'no-store', credentials: 'same-origin' });
        if (response.status === 400 || response.status === 401) return;
        if (response.ok) {
          const body: unknown = await response.json();
          if (
            typeof body === 'object' &&
            body !== null &&
            'seed' in body &&
            typeof body.seed === 'string' &&
            /^[A-Za-z0-9_-]{43}$/.test(body.seed) &&
            'refresh_in_ms' in body &&
            typeof body.refresh_in_ms === 'number' &&
            Number.isFinite(body.refresh_in_ms)
          ) {
            if (active) {
              liveSeed = body.seed;
              onSeed?.(body.seed);
            }
            delay = Math.max(1_000, Math.min(body.refresh_in_ms, 30_000));
          }
        }
      } catch {
        // The cue is decorative; retain the last pattern when the request fails.
      }
      if (active) timer = setTimeout(() => void refresh(), delay);
    }
    void refresh();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  });

  function hash(value: string): number {
    let result = 2166136261;
    for (const character of value) {
      result = Math.imul(result ^ character.charCodeAt(0), 16777619);
    }
    return result >>> 0;
  }

  const page = $derived(new URL(pageUri));
  const rp = $derived(new URL(rpUri));
  const pageHue = $derived(190 + (hash(page.origin + page.pathname) % 140));
  const rpHue = $derived((pageHue + 25 + (hash(rp.origin + rp.pathname) % 46)) % 360);
  const phase = $derived(hash(liveSeed || seed));
  const tiles = $derived(
    Array.from({ length: 16 }, (_, index) => {
      const value = hash(`${page.origin}${page.pathname}|${rp.href}|${liveSeed || seed}|${index}`);
      return {
        tone: (value >>> 12) % 4,
        style: `--turn: ${((value >>> 16) % 4) * 90}deg; --delay: -${((value >>> 8) % 36) / 10}s;`,
      };
    }),
  );
</script>

<div
  class="auth-session-cue"
  data-cue-live={liveSeed !== ''}
  style={`--page-hue: ${pageHue}; --rp-hue: ${rpHue}; --cue-duration: ${8 + (phase % 50) / 10}s; --cue-tilt: ${((phase >>> 8) % 9) - 4}deg;`}
>
  <div class="auth-session-pattern" aria-hidden="true">
    {#each tiles as tile}
      <span
        class="auth-session-tile"
        class:auth-session-tone-1={tile.tone === 1}
        class:auth-session-tone-2={tile.tone === 2}
        class:auth-session-tone-3={tile.tone === 3}
        style={tile.style}
      ></span>
    {/each}
  </div>
  <div class="auth-origin">
    <span class="auth-origin-label">{pageLabel}</span>
    <strong class="auth-origin-host">{page.host}</strong>
    <span class="auth-origin-label auth-origin-rp-label">{rpLabel}</span>
    <strong class="auth-origin-host">{rp.host}</strong>
    <span class="auth-origin-hint">{hint}</span>
  </div>
</div>
