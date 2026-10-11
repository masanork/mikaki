<script lang="ts">
  import { onMount } from 'svelte';
  import { vaultContext } from './vault-context.js';
  import { copyHttpPort, type CopyStatus } from './work-copy-view.js';
  import { getLocale } from './paraglide/runtime.js';
  import * as m from './paraglide/messages.js';
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
  async function load() {
    if (busy) return;
    const n = generation;
    busy = true;
    failure = false;
    acknowledged = false;
    try {
      const r = await port.read(id, controller.signal);
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
  <p>{m.copy_boundary()}</p>
  <a href={'/work/preparation-review?lang=' + getLocale() + '#' + encodeURIComponent(id)}
    >{m.source_compose_review()}</a
  >
  <button type="button" disabled={busy} onclick={load}>{m.copy_refresh()}</button>
  {#if failure}<p role="alert">{m.copy_unavailable()}</p>{/if}
  {#if value}
    <p role="status">{state}</p>
    {#if value.job}<p>
        {m.copy_progress({ done: value.job.next_step, total: value.job.total_steps })}
      </p>{/if}
    {#if value.cleanup_pending}<p role="status">{m.copy_cleanup_pending()}</p>{/if}
    {#if value.job && value.job.state !== 'verified'}<button
        type="button"
        disabled={busy}
        onclick={stop}>{m.copy_cleanup()}</button
      >{/if}
    {#if value.can_start}
      <label
        ><input
          type="checkbox"
          bind:checked={acknowledged}
          disabled={busy}
        />{m.copy_acknowledge()}</label
      >
      <button type="button" disabled={busy || !acknowledged} onclick={start}
        >{m.copy_start()}</button
      >
    {/if}
  {/if}
</section>
