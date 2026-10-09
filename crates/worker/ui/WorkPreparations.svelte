<script lang="ts">
  import { onMount, tick } from 'svelte';
  import * as m from './paraglide/messages.js';
  import { getLocale } from './paraglide/runtime.js';
  import { vaultContext } from './vault-context.js';
  import { SourceError, sourceHttpPort, type SourceRead } from './work-source-view.js';
  import {
    preparationHttpPort,
    inspectDisclosure,
    type WorkPreparation,
    type PreparationReview,
    type CopyReview,
  } from './work-preparation-view.js';
  const context = vaultContext(),
    scope = context.current();
  const port = preparationHttpPort(scope.request),
    sources = sourceHttpPort(scope.request);
  const copyEnabled = document.documentElement.dataset.workCopyConsent === 'true';
  let copy = $state<CopyReview | null>(null),
    inspected = $state(false),
    acknowledged = $state(false);
  let generation = 0,
    controller = new AbortController();
  let preparations = $state<WorkPreparation[]>([]),
    next = $state<string | null>(null),
    review = $state<PreparationReview | null>(null);
  let reads = $state<SourceRead[]>([]),
    busy = $state(false),
    loaded = $state(false),
    failure = $state(''),
    now = $state(Date.now() / 1000);
  let heading: HTMLHeadingElement | undefined = $state(),
    previewHeading: HTMLHeadingElement | undefined = $state();
  const date = (time: number) =>
    new Intl.DateTimeFormat(getLocale(), { dateStyle: 'medium', timeStyle: 'long' }).format(
      time * 1000,
    );
  const copyState = (p: WorkPreparation) =>
    p.state === 'reserved'
      ? m.preparation_reserved()
      : p.state === 'dispatched'
        ? m.preparation_dispatched()
        : p.state === 'verified'
          ? m.preparation_verified()
          : p.state === 'cleanup_pending'
            ? m.preparation_cleanup()
            : m.preparation_cleaned();
  function invalidate() {
    generation++;
    controller.abort();
    controller = new AbortController();
    review = null;
    copy = null;
    inspected = false;
    acknowledged = false;
    reads = [];
    busy = false;
    failure = '';
  }
  function clear() {
    invalidate();
    preparations = [];
    next = null;
    loaded = false;
  }
  function failed(e: unknown) {
    review = null;
    copy = null;
    inspected = false;
    acknowledged = false;
    reads = [];
    failure = e instanceof SourceError ? e.reason : 'unavailable';
  }
  async function load(more = false) {
    if (busy) return;
    invalidate();
    const current = generation;
    busy = true;
    if (!more) {
      preparations = [];
      next = null;
      loaded = false;
    }
    try {
      const page = await port.list(more ? next : null, controller.signal);
      if (current !== generation) return;
      scope.assert();
      preparations = page.preparations;
      next = page.next_after;
      loaded = true;
    } catch (e) {
      if (current === generation) failed(e);
    } finally {
      if (current === generation) busy = false;
    }
  }
  async function choose(id: string) {
    invalidate();
    const current = generation;
    busy = true;
    try {
      const result = await port.review(id, controller.signal);
      const copyReview = copyEnabled
        ? await port.copyReview(result.preparation, controller.signal)
        : null;
      if (current !== generation) return;
      scope.assert();
      if (result.preparation.expires_at <= Date.now() / 1000) throw new SourceError('stale');
      review = result;
      copy = copyReview;
      await tick();
      if (current === generation) heading?.focus();
    } catch (e) {
      if (current === generation) failed(e);
    } finally {
      if (current === generation) busy = false;
    }
  }
  async function inspect() {
    if (!review || busy) return;
    const current = generation,
      selected = review;
    busy = true;
    reads = [];
    inspected = false;
    acknowledged = false;
    failure = '';
    try {
      const contents = await inspectDisclosure(sources, selected.disclosure, controller.signal);
      // Re-read the preparation and manifest after the source RPC. A changed
      // revision/current state never inherits an earlier displayed inspection.
      const confirmed = await port.review(selected.preparation.id, controller.signal);
      if (current !== generation) return;
      scope.assert();
      if (
        !selected.currentSources ||
        !confirmed.currentSources ||
        JSON.stringify(confirmed.preparation) !== JSON.stringify(selected.preparation) ||
        JSON.stringify(confirmed.disclosure) !== JSON.stringify(selected.disclosure) ||
        confirmed.preparation.expires_at <= Date.now() / 1000
      )
        throw new SourceError('stale');
      reads = contents;
      inspected = true;
      await tick();
      if (current === generation) previewHeading?.focus();
    } catch (e) {
      if (current === generation) failed(e);
    } finally {
      if (current === generation) busy = false;
    }
  }
  async function decideCopy(method: 'POST' | 'DELETE') {
    if (
      !review ||
      !copy ||
      busy ||
      (method === 'POST' && (!inspected || !acknowledged || !copy.can_approve))
    )
      return;
    const current = generation,
      selected = review,
      intent = copy;
    busy = true;
    try {
      const result = await port.copyDecision(
        selected.preparation,
        intent,
        method,
        controller.signal,
      );
      if (current !== generation) return;
      scope.assert();
      copy = result;
      acknowledged = false;
    } catch (e) {
      if (current === generation) failed(e);
    } finally {
      if (current === generation) busy = false;
    }
  }
  onMount(() => {
    const linked = window.location.hash.slice(1);
    void load().then(() => {
      // A fragment names only a review, never an approval or productive action.
      // Reopening needs a fresh display lease and Native owner projection.
      if (
        loaded &&
        !busy &&
        !scope.signal.aborted &&
        document.visibilityState === 'visible' &&
        /^[A-Za-z0-9_.:-]{1,128}$/.test(linked)
      )
        void choose(linked);
    });
    const visibility = () => {
      if (document.visibilityState === 'hidden') clear();
    };
    document.addEventListener('visibilitychange', visibility);
    scope.signal.addEventListener('abort', clear, { once: true });
    const unregister = context.registerResume(async () => {
      clear();
    });
    const timer = setInterval(() => {
      now = Date.now() / 1000;
      if (review && review.preparation.expires_at <= now) {
        invalidate();
        failure = 'stale';
      }
    }, 1000);
    return () => {
      clear();
      unregister();
      clearInterval(timer);
      document.removeEventListener('visibilitychange', visibility);
      scope.signal.removeEventListener('abort', clear);
    };
  });
</script>

<section aria-busy={busy}>
  <p class="source-lead">{m.preparation_intro()}</p>
  <p class="source-boundary">{m.preparation_boundary()}</p>
  <div class="source-toolbar">
    <button type="button" disabled={busy} onclick={() => load()}>{m.preparation_refresh()}</button>
    <p aria-live="polite">{busy ? m.source_loading() : ''}</p>
  </div>
  {#if failure}<p role="alert" class="source-error">
      {failure === 'session'
        ? m.source_session()
        : failure === 'stale'
          ? m.preparation_stale()
          : m.preparation_unavailable()}
    </p>{/if}
  {#if loaded && preparations.length === 0}<p>{m.preparation_empty()}</p>{/if}
  <ul class="preparation-list">
    {#each preparations as p (p.id)}
      <li>
        <button
          type="button"
          disabled={busy || p.expires_at <= now}
          onclick={() => choose(p.id)}
          aria-pressed={review?.preparation.id === p.id}
        >
          <strong>{p.task.name}</strong><span
            >{copyState(p)} · {p.expires_at <= now
              ? m.preparation_expired()
              : date(p.expires_at)}</span
          >
        </button>
      </li>
    {/each}
  </ul>
  {#if next}<button type="button" disabled={busy} onclick={() => load(true)}
      >{m.source_more()}</button
    >{/if}
  {#if review}
    {@const p = review.preparation}
    {@const d = review.disclosure}
    <section class="source-card" aria-labelledby="preparation-review-title">
      <h2 id="preparation-review-title" bind:this={heading} tabindex="-1">
        {m.preparation_details()}
      </h2>
      <dl>
        <div>
          <dt>{m.preparation_copy_state()}</dt>
          <dd>{copyState(p)}</dd>
        </div>
        <div>
          <dt>{m.preparation_availability()}</dt>
          <dd>
            {!review.currentSources
              ? m.preparation_inactive()
              : p.current_authority
                ? m.preparation_current()
                : p.materialized
                  ? m.preparation_inactive()
                  : m.preparation_unmaterialized()}
          </dd>
        </div>
        <div>
          <dt>{m.preparation_expiry()}</dt>
          <dd>{date(p.expires_at)}</dd>
        </div>
        <div>
          <dt>{m.preparation_recipient()}</dt>
          <dd>{d.recipient}</dd>
        </div>
        <div>
          <dt>{m.preparation_workload()}</dt>
          <dd>{d.workload}</dd>
        </div>
      </dl>
      <h3>{m.preparation_destinations()}</h3>
      <dl>
        <div>
          <dt>{m.source_code()}</dt>
          <dd>{p.task.namespace} / {p.task.name}</dd>
        </div>
        <div>
          <dt>{m.preparation_snapshot()}</dt>
          <dd>{p.snapshot.namespace} / {p.snapshot.name}</dd>
        </div>
      </dl>
      <h3>{m.preparation_code()}</h3>
      <p>{m.source_history({ commits: d.code.commits, files: d.code.head_files })}</p>
      <dl>
        <div>
          <dt>{m.source_version()}</dt>
          <dd><code>{d.code.commit}</code></dd>
        </div>
      </dl>
      <h3>{m.preparation_context()}</h3>
      <p>
        {m.source_selection({
          files: d.contexts.reduce((n, c) => n + c.files.length, 0),
          bytes: d.selected_bytes,
        })}
      </p>
      {#each d.contexts as c, i}<article>
          <h4>
            {d.registered_sources[i + 1]!.role === 'personal'
              ? m.source_personal()
              : m.source_project()} · {c.repository}
          </h4>
          <p>{m.source_version()}: <code>{c.commit}</code></p>
          <ul>
            {#each c.files as f}<li>
                <strong>{f.path}</strong> · {f.bytes}
                {m.source_bytes()}
              </li>{/each}
          </ul>
        </article>{/each}
      <button type="button" disabled={busy} onclick={inspect}>{m.preparation_inspect()}</button>
      <p>{m.source_read_boundary()}</p>
      {#if copy}
        <section class="source-card" aria-label={m.preparation_copy_consent()}>
          <h3>{m.preparation_copy_consent()}</h3>
          <p>{m.preparation_copy_scope()}</p>
          <dl>
            <div>
              <dt>{m.preparation_copy_operator()}</dt>
              <dd>{copy.subject.operator}</dd>
            </div>
            <div>
              <dt>{m.preparation_copy_account()}</dt>
              <dd><code>{copy.subject.artifacts_account}</code></dd>
            </div>
          </dl>
          {#if copy.status === 'unconfirmed'}
            <p>{m.preparation_copy_inspect_first()}</p>
            <label
              ><input
                type="checkbox"
                bind:checked={acknowledged}
                disabled={busy || !inspected || !copy.can_approve}
              />
              {m.preparation_copy_acknowledge()}</label
            >
            <button
              type="button"
              disabled={busy || !inspected || !acknowledged || !copy.can_approve}
              onclick={() => decideCopy('POST')}>{m.preparation_copy_approve()}</button
            >
          {:else if copy.status === 'approved'}
            <p role="status">
              {copy.current ? m.preparation_copy_approved() : m.preparation_copy_inactive()}
            </p>
            <button type="button" disabled={busy} onclick={() => decideCopy('DELETE')}
              >{m.preparation_copy_withdraw()}</button
            >
          {:else}<p role="status">{m.preparation_copy_withdrawn()}</p>{/if}
          <p>{m.preparation_copy_withdraw_boundary()}</p>
        </section>
      {/if}
      <h3>{m.preparation_delegation()}</h3>
      <p>{m.preparation_delegation_body()}</p>
      <details>
        <summary>{m.preparation_integrity()}</summary>
        <dl>
          <div>
            <dt>{m.preparation_identifier()}</dt>
            <dd><code>{p.id}</code></dd>
          </div>
          <div>
            <dt>{m.preparation_manifest()}</dt>
            <dd><code>{p.disclosure_digest}</code></dd>
          </div>
          <div>
            <dt>{m.preparation_checked()}</dt>
            <dd>{date(review.checkedAt)}</dd>
          </div>
          <div>
            <dt>{m.preparation_repository_ids()}</dt>
            <dd>
              {p.task.repository_id ?? m.preparation_unknown()} / {p.snapshot.repository_id ??
                m.preparation_unknown()}
            </dd>
          </div>
        </dl>
      </details>
    </section>
  {/if}
  {#if reads.length}<section class="source-preview" aria-label={m.source_preview_title()}>
      <h2 bind:this={previewHeading} tabindex="-1">{m.source_preview_title()}</h2>
      {#each reads as read}<h3>{read.source.label}</h3>
        {#each read.files as file}<article>
            <h4>{file.path}</h4>
            <!-- svelte-ignore a11y_no_noninteractive_tabindex (Keyboard access to a named, scrollable file region.) -->
            <pre tabindex="0" role="region" aria-label={file.path}>{file.content}</pre>
          </article>{/each}{/each}
    </section>{/if}
</section>
