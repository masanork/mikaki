<script lang="ts">
  import { onMount } from 'svelte';
  import { vaultContext } from './vault-context.js';
  import { webMcpContext } from './webmcp.ts';
  import type { WorkWebMcpHost } from './work-webmcp.ts';
  import * as m from './paraglide/messages.js';
  let { host }: { host: WorkWebMcpHost } = $props();
  const scope = vaultContext().current(),
    modelContext = webMcpContext(document);
  let enabled = $state(false),
    sharedSelection = $state<string | null>(null),
    visible = $state(document.visibilityState === 'visible'),
    status = $state('');
  const selection = $derived(host.snapshot().selection),
    files = $derived(host.snapshot().files.length);
  function clear() {
    enabled = false;
    sharedSelection = null;
    status = '';
  }
  $effect(() => {
    if (!files || sharedSelection !== selection) sharedSelection = null;
  });
  $effect(() => {
    if (!modelContext || !enabled || !visible || scope.signal.aborted) return;
    const controller = new AbortController(),
      signal = AbortSignal.any([controller.signal, scope.signal]);
    const asset = '/work/browser-assistant.js';
    void import(/* @vite-ignore */ asset)
      .then(async (module: typeof import('./work-assistant.ts')) => {
        signal.throwIfAborted();
        await module.registerWorkAssistant(
          modelContext,
          host,
          () => sharedSelection,
          signal,
          (_name, phase) => {
            if (!signal.aborted)
              status = phase === 'running' ? m.busy() : phase === 'failed' ? m.error() : '';
          },
        );
      })
      .catch(() => {
        if (signal.aborted) return;
        controller.abort();
        enabled = false;
        sharedSelection = null;
        status = m.error();
      });
    return () => controller.abort();
  });
  onMount(() => {
    const visibility = () => {
      visible = document.visibilityState === 'visible';
      if (!visible) clear();
    };
    scope.signal.addEventListener('abort', clear, { once: true });
    document.addEventListener('visibilitychange', visibility);
    return () => {
      clear();
      document.removeEventListener('visibilitychange', visibility);
      scope.signal.removeEventListener('abort', clear);
    };
  });
</script>

{#if modelContext}
  <section id="work-browser-assistant" aria-labelledby="work-browser-assistant-heading">
    <h2 id="work-browser-assistant-heading">{m.webmcpHeading()}</h2>
    <label
      ><input
        id="work-assistant-enabled"
        type="checkbox"
        bind:checked={enabled}
        disabled={!visible}
        onchange={() => {
          sharedSelection = null;
        }}
      />{m.workAssistantEnable()}</label
    >
    {#if enabled && host.page !== 'copy'}
      <label
        ><input
          id="work-assistant-content"
          type="checkbox"
          checked={sharedSelection !== null}
          disabled={!files}
          onchange={(event) => {
            sharedSelection = event.currentTarget.checked ? selection : null;
          }}
        />{m.workAssistantContent()}</label
      >
    {/if}
    {#if enabled}<p>{m.workAssistantSession()}</p>{/if}
    <p role="status" aria-live="polite">{status}</p>
  </section>
{/if}
