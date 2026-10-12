<script lang="ts">
  import { onMount } from 'svelte';
  import { webMcpContext, registerWebMcpTools } from './webmcp.ts';
  import {
    createVaultWebMcpTools,
    type VaultWebMcpHost,
    type WebMcpSelection,
  } from './vault-webmcp.ts';
  import { ThreadSearchClient } from './vault-thread-search-client.ts';
  import type { SearchArchive } from './vault-thread-search.ts';
  import { vaultScope } from './vault-context.ts';
  import * as m from './paraglide/messages.js';
  let {
    host,
    records,
    nameRevision,
    noteRevision,
  }: {
    host: Omit<VaultWebMcpHost, 'selection' | 'search' | 'visible'>;
    records: SearchArchive[];
    nameRevision: number;
    noteRevision: number;
  } = $props();
  const scope = vaultScope();
  const modelContext = webMcpContext(document);
  let enabled = $state(false),
    shareName = $state(false),
    shareNote = $state(false);
  let threadIds: string[] = $state([]);
  let visible = $state(document.visibilityState === 'visible');
  let status = $state('');
  function clear() {
    enabled = shareName = shareNote = false;
    threadIds = [];
    status = '';
  }
  $effect(() => {
    if (!modelContext || !visible || scope.signal.aborted) return;
    const owner = host.owner();
    const selection: WebMcpSelection = {
      name: enabled && shareName && owner ? nameRevision : null,
      note: enabled && shareNote && owner ? noteRevision : null,
      threads:
        enabled && owner
          ? records
              .filter((record) => threadIds.includes(record.id))
              .map((record) => ({
                id: record.id,
                revision: record.revision,
                title: record.archive.title,
              }))
          : [],
    };
    const controller = new AbortController();
    const signal = AbortSignal.any([controller.signal, scope.signal]);
    const tools = createVaultWebMcpTools({
      ...host,
      selection: () => selection,
      visible: () => visible,
      search: async (snapshot, query, execution) => {
        const client = new ThreadSearchClient(
          new Worker('/vault/search.js', { type: 'module' }),
          execution,
        );
        try {
          await client.replace(snapshot);
          execution.throwIfAborted();
          return await client.search(
            query,
            snapshot.map((record) => record.id),
          );
        } finally {
          client.dispose();
        }
      },
    });
    void registerWebMcpTools(
      modelContext,
      tools.filter(
        (tool) =>
          (owner && enabled) ||
          ['mikaki_get_vault_state', 'mikaki_review_vault_action'].includes(tool.name),
      ),
      signal,
      (_name, phase) => {
        if (!signal.aborted)
          status = phase === 'running' ? m.busy() : phase === 'complete' ? '' : m.error();
      },
    ).catch(() => {
      if (signal.aborted) return;
      controller.abort();
      if (!scope.signal.aborted) status = m.error();
    });
    return () => {
      controller.abort();
    };
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
      scope.signal.removeEventListener('abort', clear);
      document.removeEventListener('visibilitychange', visibility);
    };
  });
</script>

{#if modelContext}
  <section id="vault-browser-assistant" aria-labelledby="vault-browser-assistant-heading">
    <h2 id="vault-browser-assistant-heading">{m.webmcpHeading()}</h2>
    <p>{m.webmcpExplanation()}</p>
    {#if host.owner()}
      <label
        ><input
          id="webmcp-enabled"
          type="checkbox"
          bind:checked={enabled}
          onchange={(event) => {
            if (!event.currentTarget.checked) clear();
          }}
        />{m.webmcpEnable()}</label
      >
      {#if enabled}
        <fieldset>
          <legend>{m.ownerAgentGrantPermissions()}</legend>
          <label
            ><input
              id="webmcp-name"
              type="checkbox"
              bind:checked={shareName}
            />{m.webmcpRecordAccess({ record: m.vaultName() })}</label
          >
          <label
            ><input
              id="webmcp-note"
              type="checkbox"
              bind:checked={shareNote}
            />{m.webmcpRecordAccess({ record: m.vaultNoteHeading() })}</label
          >
          {#each records as record (record.id)}
            <label
              ><input
                type="checkbox"
                value={record.id}
                bind:group={threadIds}
                disabled={!threadIds.includes(record.id) && threadIds.length >= 16}
              />{record.archive.title}</label
            >
          {/each}
          <p>{m.webmcpSessionOnly()}</p>
        </fieldset>
      {/if}
    {/if}
    <p role="status" aria-live="polite">{status}</p>
  </section>
{/if}
