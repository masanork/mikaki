<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { ThreadSearchClient } from './vault-thread-search-client.ts';
  import type { SearchArchive, SearchHit } from './vault-thread-search.ts';
  import { threadSearchTerms } from './vault-thread-search-query.ts';
  import type { OwnerVaultController } from './vault-owner-controller.ts';
  import { vaultScope } from './vault-context.ts';
  import * as m from './paraglide/messages.js';
  let {
    records,
    owner,
    disabled,
    query = $bindable(''),
    onselect,
  }: {
    records: SearchArchive[];
    owner: OwnerVaultController;
    disabled: boolean;
    query?: string;
    onselect: (hit: SearchHit) => Promise<void>;
  } = $props();
  const scope = vaultScope();
  let hits: SearchHit[] = $state([]),
    phase = $state<'idle' | 'loading' | 'ready' | 'error' | 'invalid'>('idle'),
    truncated = $state(false);
  let client: ThreadSearchClient | null = null,
    indexed = false,
    running = false,
    epoch = 0,
    serial = 0,
    timer: ReturnType<typeof setTimeout> | undefined;
  function invalidate() {
    epoch++;
    serial++;
    client?.dispose();
    client = null;
    indexed = false;
    hits = [];
    truncated = false;
    phase = 'idle';
    clearTimeout(timer);
  }
  function validQuery() {
    try {
      threadSearchTerms(query);
      return true;
    } catch {
      phase = 'invalid';
      return false;
    }
  }
  function schedule() {
    clearTimeout(timer);
    if (!disabled && query.trim() && !scope.signal.aborted && validQuery())
      timer = setTimeout(() => void run(), 180);
  }
  async function run() {
    if (running || disabled || !query.trim() || document.visibilityState === 'hidden') return;
    if (!validQuery()) return;
    running = true;
    const generation = epoch,
      ticket = serial,
      words = query,
      snapshot = $state.snapshot(records);
    const current = () =>
      generation === epoch && ticket === serial && !scope.signal.aborted && !disabled;
    phase = 'loading';
    try {
      await owner.verifyAuthority();
      if (!current()) return;
      const token = owner.checkpoint();
      client ??= new ThreadSearchClient(
        new Worker('/vault/search.js', { type: 'module' }),
        scope.signal,
      );
      if (!indexed) {
        await client.replace(snapshot);
        if (!current()) return;
        indexed = true;
      }
      const result = await client.search(
        words,
        snapshot.map((record) => record.id),
      );
      await owner.verifyAuthority();
      owner.assertCurrent(token);
      if (!current()) return;
      hits = result.hits;
      truncated = result.truncated;
      phase = 'ready';
    } catch {
      if (current()) {
        client?.dispose();
        client = null;
        indexed = false;
        hits = [];
        phase = 'error';
      }
    } finally {
      running = false;
      if (ticket !== serial) schedule();
    }
  }
  $effect(() => {
    records;
    owner;
    disabled;
    untrack(() => {
      invalidate();
      schedule();
    });
  });
  $effect(() => {
    query;
    untrack(() => {
      serial++;
      hits = [];
      truncated = false;
      phase = query.trim() ? 'loading' : 'idle';
      schedule();
    });
  });
  onMount(() => {
    const clear = () => {
      invalidate();
      query = '';
    };
    const hidden = () => {
      if (document.visibilityState === 'hidden') clear();
    };
    scope.signal.addEventListener('abort', clear, { once: true });
    window.addEventListener('pagehide', clear);
    document.addEventListener('visibilitychange', hidden);
    return () => {
      invalidate();
      scope.signal.removeEventListener('abort', clear);
      window.removeEventListener('pagehide', clear);
      document.removeEventListener('visibilitychange', hidden);
    };
  });
</script>

<label for="thread-search">{m.ownerWorkspaceSearch()}</label><input
  id="thread-search"
  type="search"
  maxlength="256"
  {disabled}
  bind:value={query}
  aria-controls="thread-search-results"
  aria-invalid={phase === 'invalid'}
  aria-describedby={query.trim() ? 'thread-search-status' : undefined}
/>
<div id="thread-search-results" aria-busy={phase === 'loading'}>
  {#if query.trim()}
    <p id="thread-search-status" role="status" aria-live="polite">
      {phase === 'loading'
        ? m.threadSearchLoading()
        : phase === 'invalid'
          ? m.threadSearchInvalidQuery()
          : phase === 'error'
            ? m.threadSearchFailed()
            : phase === 'ready' && !hits.length
              ? m.threadSearchEmpty()
              : truncated
                ? m.threadSearchLimited()
                : ''}
    </p>
    {#if phase === 'error'}<button {disabled} onclick={() => void run()}>{m.agentRefresh()}</button
      >{/if}
    <ul class="thread-search-hits">
      {#each hits as hit (`${hit.thread}:${hit.message}`)}
        {@const thread = records.find(
          (record) => record.id === hit.thread && record.revision === hit.revision,
        )}
        {#if thread}
          <li>
            <button {disabled} onclick={() => void onselect(hit)}
              ><strong>{thread.archive.title}</strong><span>{hit.text}</span></button
            >
          </li>
        {/if}
      {/each}
    </ul>
  {/if}
</div>
