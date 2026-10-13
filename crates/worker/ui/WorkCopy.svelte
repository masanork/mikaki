<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { vaultContext } from './vault-context.js';
  import { copyHttpPort, type CopyStatus } from './work-copy-view.js';
  import { getLocale } from './paraglide/runtime.js';
  import * as m from './paraglide/messages.js';
  import WorkWebMcp from './WorkWebMcp.svelte';
  import { WebMcpFailure } from './webmcp.ts';
  import type { WorkWebMcpHost } from './work-webmcp.ts';
  const context = vaultContext(),
    scope = context.current(),
    port = copyHttpPort(scope.request);
  let value = $state<CopyStatus | null>(null),
    busy = $state(false),
    failure = $state(false),
    acknowledged = $state(false);
  let generation = 0,
    controller = new AbortController();
  const id = window.location.hash.slice(1);
  function clear() {
    generation++;
    controller.abort();
    controller = new AbortController();
    value = null;
    busy = false;
    failure = false;
    acknowledged = false;
  }
  async function load(signal = controller.signal) {
    if (busy) return;
    const n = generation;
    busy = true;
    failure = false;
    acknowledged = false;
    try {
      const r = await port.read(id, AbortSignal.any([controller.signal, signal]));
      signal.throwIfAborted();
      if (n !== generation) return;
      scope.assert();
      value = r;
    } catch {
      if (n === generation) {
        value = null;
        failure = true;
      }
    } finally {
      if (n === generation) busy = false;
    }
  }
  async function start() {
    if (busy || !value?.can_start || !acknowledged) return;
    const n = generation,
      digest = value.review_digest;
    busy = true;
    failure = false;
    acknowledged = false;
    try {
      const r = await port.start(id, digest, controller.signal);
      if (n !== generation) return;
      scope.assert();
      value = r;
    } catch {
      if (n === generation) {
        value = null;
        failure = true;
      }
    } finally {
      if (n === generation) busy = false;
    }
  }
  async function stop() {
    if (busy || !value?.job) return;
    const n = generation,
      digest = value.review_digest;
    busy = true;
    failure = false;
    acknowledged = false;
    try {
      const r = await port.stop(id, digest, controller.signal);
      if (n !== generation) return;
      scope.assert();
      value = r;
    } catch {
      if (n === generation) {
        value = null;
        failure = true;
      }
    } finally {
      if (n === generation) busy = false;
    }
  }
  const assistant: WorkWebMcpHost = {
    page: 'copy',
    snapshot: () => ({
      page: 'copy',
      version: JSON.stringify([generation, id, value, acknowledged, busy, failure]),
      selection: JSON.stringify([id, value?.review_digest]),
      busy,
      loaded: value !== null,
      items: [],
      files: [],
      selected: id,
      prepared: null,
      copy: value
        ? {
            state: value.job?.state ?? 'not_started',
            done: value.job?.next_step ?? 0,
            total: value.job?.total_steps ?? 19,
            can_start: value.can_start,
            cleanup_pending: value.cleanup_pending,
          }
        : null,
    }),
    verify: async () => {
      await scope.verify();
      scope.assert();
    },
    visible: () => document.visibilityState === 'visible',
    contents: () => [],
    available: (action) => !busy && (action === 'refresh' || (action === 'review' && !!value)),
    invoke: async (action, args, signal) => {
      signal.throwIfAborted();
      if (action === 'refresh') await load(signal);
      else if (action === 'review') {
        if (args['action'] !== 'start_copy' && args['action'] !== 'stop_copy')
          throw new WebMcpFailure('unavailable');
        await load(signal);
        await tick();
        signal.throwIfAborted();
      } else throw new WebMcpFailure('unavailable');
      signal.throwIfAborted();
      if (failure) throw new WebMcpFailure('unavailable');
    },
  };
  const state = $derived(
    !value?.job
      ? m.copy_not_started()
      : value.job.state === 'queued'
        ? m.copy_queued()
        : value.job.state === 'verified'
          ? m.copy_verified()
          : value.job.state === 'blocked'
            ? m.copy_blocked()
            : m.copy_running(),
  );
  onMount(() => {
    void load();
    const hide = () => {
      if (document.visibilityState === 'hidden') clear();
    };
    document.addEventListener('visibilitychange', hide);
    scope.signal.addEventListener('abort', clear, { once: true });
    const off = context.registerResume(async () => {
      clear();
    });
    return () => {
      clear();
      off();
      document.removeEventListener('visibilitychange', hide);
      scope.signal.removeEventListener('abort', clear);
    };
  });
</script>

<section aria-busy={busy}>
  <a href={'/work/preparation-review?lang=' + getLocale() + '#' + encodeURIComponent(id)}
    >{m.source_compose_review()}</a
  >
  <button type="button" disabled={busy} onclick={() => load()}>{m.copy_refresh()}</button>
  {#if failure}<p role="alert">{m.copy_unavailable()}</p>{/if}
  {#if value}
    <section class="source-card work-progress-card">
      <h2>{m.work_copy_progress_title()}</h2>
      <p class="work-progress-state">
        {!value.job || value.job.state === 'queued'
          ? m.work_copy_waiting()
          : value.job.state === 'verified'
            ? m.work_copy_done()
            : value.job.state === 'blocked'
              ? m.work_copy_attention()
              : m.work_copy_pending()}
      </p>
      <p role="status">{state}</p>
      {#if value.job}<progress
          value={value.job.next_step}
          max={value.job.total_steps}
          aria-label={m.work_copy_progress_title()}
        ></progress>
        <p>
          {m.copy_progress({ done: value.job.next_step, total: value.job.total_steps })}
        </p>{/if}
      {#if value.cleanup_pending}<p role="status">{m.copy_cleanup_pending()}</p>{/if}
      {#if value.job && value.job.state !== 'verified'}<button
          data-work-action="stop_copy"
          type="button"
          disabled={busy}
          onclick={stop}>{m.copy_cleanup()}</button
        >{/if}
      {#if value.can_start}
        <label class="work-acknowledge"
          ><input
            type="checkbox"
            data-work-confirmation="start_copy"
            bind:checked={acknowledged}
            disabled={busy}
          />{m.copy_acknowledge()}</label
        >
        <button
          class="work-primary"
          data-work-action="start_copy"
          type="button"
          disabled={busy || !acknowledged}
          onclick={start}>{m.copy_start()}</button
        >
      {/if}
    </section>
  {/if}
  <details class="work-details work-help">
    <summary>{m.work_copy_help()}</summary>
    <p>{m.copy_boundary()}</p>
  </details>
  <WorkWebMcp host={assistant} />
</section>
