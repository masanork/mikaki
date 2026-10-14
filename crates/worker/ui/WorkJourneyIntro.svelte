<script lang="ts">
  import { onMount, tick } from 'svelte';
  import * as m from './paraglide/messages.js';
  import { vaultContext } from './vault-context.js';
  let showing = $state(false);
  let loading = $state(false),
    failed = $state(false);
  let host: HTMLDivElement | undefined = $state();
  let generation = 0,
    dispose: (() => void) | undefined;
  const context = vaultContext(),
    scope = context.current();
  function close() {
    generation++;
    dispose?.();
    dispose = undefined;
    showing = loading = failed = false;
  }
  async function open() {
    const current = ++generation;
    showing = loading = true;
    failed = false;
    try {
      await tick();
      const url = '/work/task-demo.js';
      const module = await import(/* @vite-ignore */ url);
      if (current !== generation || !showing || !host || document.visibilityState !== 'visible')
        return;
      scope.assert();
      if (typeof module.mountDemo !== 'function') throw new Error('demo_unavailable');
      dispose = module.mountDemo(host);
    } catch {
      if (current === generation) {
        showing = false;
        failed = true;
      }
    } finally {
      if (current === generation) loading = false;
    }
  }
  onMount(() => {
    const hidden = () => {
      if (document.visibilityState === 'hidden') close();
    };
    document.addEventListener('visibilitychange', hidden);
    scope.signal.addEventListener('abort', close, { once: true });
    const unregister = context.registerResume(close);
    return () => {
      close();
      document.removeEventListener('visibilitychange', hidden);
      scope.signal.removeEventListener('abort', close);
      unregister();
    };
  });
</script>

<section class="journey-intro" aria-label={m.work_journey_title()}>
  <p class="journey-eyebrow">{m.work_journey_eyebrow()}</p>
  <h2>{m.work_journey_title()}</h2>
  <p>{m.work_journey_intro()}</p>
  <ol class="journey-outline">
    <li><strong>{m.work_journey_request()}</strong><span>{m.work_journey_request_hint()}</span></li>
    <li>
      <strong>{m.work_journey_materials()}</strong><span>{m.work_journey_materials_hint()}</span>
    </li>
    <li>
      <strong>{m.work_journey_activity()}</strong><span>{m.work_journey_activity_hint()}</span>
    </li>
    <li><strong>{m.work_journey_result()}</strong><span>{m.work_journey_result_hint()}</span></li>
  </ol>
  <p class="work-hint">{m.work_journey_available()}</p>
  <button
    type="button"
    aria-expanded={showing}
    aria-controls="work-demo-host"
    onclick={() => (showing ? close() : open())}
  >
    {showing ? m.work_journey_close() : m.work_journey_try()}
  </button>
  {#if loading}<p role="status">{m.work_demo_loading()}</p>{/if}
  {#if failed}<p role="alert">{m.work_demo_unavailable()}</p>{/if}
  <div id="work-demo-host" bind:this={host} hidden={!showing}></div>
</section>

<style>
  .journey-intro {
    margin: 0 0 2rem;
    padding: 1.5rem;
    border: 1px solid #cbd7d2;
    border-radius: 1rem;
    background: #f4f7f3;
  }
  .journey-eyebrow {
    font-size: 0.75rem;
    letter-spacing: 0.12em;
    color: #52685e;
  }
  h2 {
    font-size: 1.5rem;
    margin: 0.4rem 0 0.75rem;
  }
  .journey-outline {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 1rem;
    padding: 0;
    margin: 1.5rem 0;
    list-style-position: inside;
  }
  .journey-outline li {
    min-width: 0;
    color: #52685e;
  }
  .journey-outline strong {
    color: #263d33;
  }
  .journey-outline span {
    display: block;
    font-size: 0.85rem;
    margin-top: 0.4rem;
    line-height: 1.6;
  }
  @media (max-width: 700px) {
    .journey-outline {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .journey-intro {
      padding: 1.1rem;
    }
  }
</style>
