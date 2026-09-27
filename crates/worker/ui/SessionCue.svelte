<script lang="ts">
  let {
    seed,
    pageUri,
    rpUri,
    pageLabel,
    rpLabel,
    hint,
  }: {
    seed: string;
    pageUri: string;
    rpUri: string;
    pageLabel: string;
    rpLabel: string;
    hint: string;
  } = $props();

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
  const tiles = $derived(
    Array.from({ length: 16 }, (_, index) => {
      const value = hash(`${page.origin}${page.pathname}|${rp.href}|${seed}|${index}`);
      return {
        tone: (value >>> 12) % 4,
        style: `--turn: ${((value >>> 16) % 4) * 90}deg; --delay: -${((value >>> 8) % 36) / 10}s;`,
      };
    }),
  );
</script>

<div class="auth-session-cue" style={`--page-hue: ${pageHue}; --rp-hue: ${rpHue};`}>
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
