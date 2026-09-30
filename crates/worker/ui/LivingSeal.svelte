<script lang="ts">
  import { onMount } from 'svelte';
  import { createSealLight } from './seal-light.js';

  let {
    seed,
    pageOrigin,
    rpOrigin,
    paused = false,
  }: {
    seed: string;
    pageOrigin: string;
    rpOrigin: string;
    paused?: boolean;
  } = $props();
  let canvas: HTMLCanvasElement;
  let light: ReturnType<typeof createSealLight> | undefined;
  let renderer = $state('svg');

  function hash(value: string): number {
    let result = 2166136261;
    for (const character of value) result = Math.imul(result ^ character.charCodeAt(0), 16777619);
    return result >>> 0;
  }
  const identity = $derived(hash(`${pageOrigin}|${rpOrigin}`));
  const phase = $derived(hash(seed) / 4294967296);
  const paths = $derived(
    Array.from({ length: 24 }, (_, index) => {
      const frequency = 8 + (identity % 5);
      const points = Array.from({ length: 481 }, (_, point) => {
        const angle = (point / 480) * Math.PI * 2;
        const radius =
          99 +
          index * 1.9 +
          Math.sin(angle * frequency + index * 0.18) * 15 +
          Math.cos(angle * (frequency - 1) - index * 0.12) * 6;
        return `${point === 0 ? 'M' : 'L'}${(200 + Math.cos(angle) * radius).toFixed(2)},${(200 + Math.sin(angle) * radius).toFixed(2)}`;
      });
      return points.join(' ') + 'Z';
    }),
  );

  onMount(() => {
    // The SVG remains complete even if GPU allocation or shader compilation fails.
    try {
      light = createSealLight(
        canvas,
        () => ({ phase, paused }),
        (active) => {
          renderer = active ? 'webgl' : 'svg';
        },
      );
    } catch {
      renderer = 'svg';
    }
    return () => light?.dispose();
  });
  $effect(() => {
    void phase;
    void paused;
    light?.refresh();
  });
</script>

<div
  class="auth-art auth-seal"
  class:auth-seal-paused={paused}
  aria-hidden="true"
  data-renderer={renderer}
  style={`--seal-phase: ${phase * 24 - 12}deg; --seal-hue: ${identity % 28}deg;`}
>
  <div class="auth-seal-aura"></div>
  <canvas bind:this={canvas} class="auth-seal-light"></canvas>
  <svg class="auth-seal-vector" viewBox="0 0 400 400" fill="none">
    <circle class="auth-seal-boundary" cx="200" cy="200" r="180" />
    <circle class="auth-seal-ticks" cx="200" cy="200" r="173" pathLength="120" />
    <g class="auth-seal-weave">
      {#each paths as path, index}
        <path d={path} class:auth-seal-thread-accent={index % 4 === 0} />
      {/each}
    </g>
    <g class="auth-seal-counterweave">
      {#each paths.filter((_, index) => index % 3 === 0) as path}
        <path d={path} />
      {/each}
    </g>
    <circle class="auth-seal-boundary" cx="200" cy="200" r="72" />
    <circle class="auth-seal-orbit" cx="200" cy="200" r="80" pathLength="100" />
    <g class="auth-seal-mark" transform="translate(200 200) rotate(-12)">
      <rect x="-38" y="-38" width="33" height="33" rx="6" />
      <rect x="5" y="-38" width="33" height="33" rx="6" />
      <rect x="-38" y="5" width="33" height="33" rx="6" />
      <rect x="5" y="5" width="33" height="33" rx="6" />
    </g>
  </svg>
  <span class="auth-art-label auth-art-label-top">MIKAKI / PASSKEY</span>
  <span class="auth-art-label auth-art-label-bottom">FIDO2 / WebAuthn</span>
</div>
