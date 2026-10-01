<script lang="ts">
  import { onMount } from 'svelte';
  import * as m from './paraglide/messages.js';
  import { createWovenGate } from './woven-gate.js';

  let {
    pageOrigin,
    rpOrigin,
    paused,
    layout = 'gate',
    sceneSelector = '.auth-shell',
    tiltControl = true,
  }: {
    pageOrigin: string;
    rpOrigin: string;
    paused: boolean;
    layout?: 'gate' | 'fence';
    sceneSelector?: string;
    tiltControl?: boolean;
  } = $props();
  let canvas: HTMLCanvasElement;
  let renderer = $state<ReturnType<typeof createWovenGate>>(null);
  let tilted = $state(false);
  let unavailable = $state(false);
  let supportsTilt = $state(false);
  let baseline: { beta: number; gamma: number } | null = null;
  let active = $state(false);

  $effect(() => {
    renderer?.pause(paused);
  });
  $effect(() => {
    // Connection changes recreate both material and event ownership.
    const page = pageOrigin,
      destination = rpOrigin;
    if (!active) return;
    const scene = canvas.closest<HTMLElement>(sceneSelector);
    if (!scene) return;
    const gate = createWovenGate(scene, canvas, page, destination, layout);
    renderer = gate;
    return () => {
      gate?.destroy();
      renderer = null;
    };
  });

  onMount(() => {
    active = true;
    supportsTilt =
      isSecureContext &&
      typeof DeviceOrientationEvent !== 'undefined' &&
      navigator.maxTouchPoints > 0;
    function orientation(event: DeviceOrientationEvent) {
      if (!tilted || event.beta === null || event.gamma === null) return;
      baseline ??= { beta: event.beta, gamma: event.gamma };
      renderer?.light(
        0.24 + (event.gamma - baseline.gamma) / 70,
        0.28 + (event.beta - baseline.beta) / 90,
      );
    }
    function lost() {
      renderer?.destroy();
      renderer = null;
    }
    canvas.addEventListener('contextlost', lost);
    window.addEventListener('deviceorientation', orientation);
    return () => {
      active = false;
      window.removeEventListener('deviceorientation', orientation);
      canvas.removeEventListener('contextlost', lost);
    };
  });

  async function toggleTilt() {
    unavailable = false;
    if (tilted) {
      tilted = false;
      baseline = null;
      renderer?.light(0.24, 0.28);
      return;
    }
    if (!renderer || matchMedia('(prefers-reduced-motion: reduce)').matches) {
      unavailable = true;
      return;
    }
    try {
      const orientation = DeviceOrientationEvent as typeof DeviceOrientationEvent & {
        requestPermission?: () => Promise<string>;
      };
      if (orientation.requestPermission && (await orientation.requestPermission()) !== 'granted') {
        unavailable = true;
        return;
      }
      // Permission may outlive the component while navigating or switching language.
      if (active) {
        baseline = null;
        tilted = true;
      }
    } catch {
      unavailable = true;
    }
  }
</script>

<div class="gate-background" data-renderer={renderer ? 'canvas' : 'css'} aria-hidden="true">
  <div class="gate-fallback">
    <span></span>{#if layout === 'gate'}<span></span>{/if}
  </div>
  <canvas bind:this={canvas}></canvas>
</div>
{#if supportsTilt && tiltControl}
  <button class="quiet" type="button" aria-pressed={tilted} disabled={paused} onclick={toggleTilt}
    >{m.authTilt()}</button
  >
{/if}
{#if unavailable}<p class="status" role="status">{m.authTiltUnavailable()}</p>{/if}
