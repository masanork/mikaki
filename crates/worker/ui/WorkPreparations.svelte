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
    type WorkDisclosureRecord,
  } from './work-preparation-view.js';
  import WorkWebMcp from './WorkWebMcp.svelte';
  import { WebMcpFailure } from './webmcp.ts';
  import type { WorkWebMcpHost } from './work-webmcp.ts';
  const context = vaultContext(),
    scope = context.current();
  const port = preparationHttpPort(scope.request),
    sources = sourceHttpPort(scope.request);
  const copyEnabled = document.documentElement.dataset.workCopyConsent === 'true';
  const executionEnabled = document.documentElement.dataset.workCopyExecution === 'true';
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
  async function load(more = false, signal?: AbortSignal) {
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
      const execution = signal ? AbortSignal.any([controller.signal, signal]) : controller.signal;
      const page = await port.list(more ? next : null, execution);
      execution.throwIfAborted();
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
  async function choose(id: string, signal?: AbortSignal) {
    invalidate();
    const current = generation;
    busy = true;
    try {
      const execution = signal ? AbortSignal.any([controller.signal, signal]) : controller.signal;
      const result = await port.review(id, execution);
      const copyReview = copyEnabled ? await port.copyReview(result.preparation, execution) : null;
      execution.throwIfAborted();
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
  async function inspect(signal = controller.signal) {
    if (!review || busy) return;
    const current = generation,
      selected = review;
    busy = true;
    reads = [];
    inspected = false;
    acknowledged = false;
    failure = '';
    try {
      const execution = AbortSignal.any([controller.signal, signal]);
      const contents = await inspectDisclosure(sources, selected.disclosure, execution);
      // Re-read the preparation and manifest after the source RPC. A changed
      // revision/current state never inherits an earlier displayed inspection.
      const confirmed = await port.review(selected.preparation.id, execution);
      execution.throwIfAborted();
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
  async function readDisclosure(signal = controller.signal): Promise<WorkDisclosureRecord> {
    if (!review || busy || !review.currentSources) throw new SourceError('stale');
    const current = generation,
      selected = review;
    busy = true;
    try {
      const execution = AbortSignal.any([controller.signal, signal]);
      await scope.verify();
      const confirmed = await port.review(selected.preparation.id, execution);
      await scope.verify();
      execution.throwIfAborted();
      scope.assert();
      if (
        current !== generation ||
        !confirmed.currentSources ||
        JSON.stringify(confirmed.preparation) !== JSON.stringify(selected.preparation) ||
        JSON.stringify(confirmed.disclosure) !== JSON.stringify(selected.disclosure) ||
        confirmed.preparation.expires_at <= Date.now() / 1000
      )
        throw new SourceError('stale');
      return {
        kind: 'disclosure',
        digest: confirmed.preparation.disclosure_digest,
        manifest: confirmed.disclosure,
        current_sources: true,
      };
    } finally {
      if (current === generation) busy = false;
    }
  }
  async function downloadDisclosure() {
    const current = generation;
    try {
      const record = await readDisclosure();
      scope.assert();
      if (current !== generation) throw new SourceError('stale');
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(record, null, 2) + '\n'], { type: 'application/json' }),
      );
      const link = document.createElement('a');
      link.href = url;
      link.download = `mikaki-work-disclosure-${record.digest}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (e) {
      if (current === generation) failed(e);
    }
  }
  const assistant: WorkWebMcpHost = {
    page: 'preparations',
    snapshot: () => ({
      page: 'preparations',
      version: JSON.stringify([
        generation,
        preparations,
        review,
        copy,
        inspected,
        acknowledged,
        busy,
        loaded,
      ]),
      selection: JSON.stringify(review ? [review.preparation, review.disclosure] : null),
      busy,
      loaded,
      items: preparations.map((p) => ({
        id: p.id,
        state: p.state,
        revision: p.revision,
        expires_at: p.expires_at,
      })),
      files:
        review?.disclosure.contexts.flatMap((c) =>
          c.files.map(({ path, bytes }) => ({ source_id: c.repository, path, bytes })),
        ) ?? [],
      selected: review?.preparation.id ?? null,
      prepared: null,
      copy: copy ? { status: copy.status } : null,
    }),
    verify: async () => {
      await scope.verify();
      scope.assert();
    },
    visible: () => document.visibilityState === 'visible',
    contents: () => reads,
    disclosure: readDisclosure,
    available: (action) =>
      !busy &&
      (action === 'refresh' ||
        (action === 'more' && next !== null) ||
        (action === 'open_preparation' && loaded) ||
        (action === 'inspect' && !!review && review.currentSources) ||
        (action === 'review' && !!copy)),
    invoke: async (action, args, signal) => {
      signal.throwIfAborted();
      if (action === 'refresh' || action === 'more') await load(action === 'more', signal);
      else if (action === 'open_preparation') {
        const p = preparations.find((p) => p.id === args['preparation_id']);
        if (!p) throw new WebMcpFailure('not_selected');
        await choose(p.id, signal);
      } else if (action === 'inspect') await inspect(signal);
      else if (action === 'review') {
        if (
          !review ||
          !copy ||
          (args['action'] !== 'approve_copy' && args['action'] !== 'withdraw_copy')
        )
          throw new WebMcpFailure('unavailable');
        await choose(review.preparation.id, signal);
        await tick();
        signal.throwIfAborted();
      } else throw new WebMcpFailure('unavailable');
      signal.throwIfAborted();
      if (failure) throw new WebMcpFailure('unavailable');
    },
  };
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
  {#if busy}<p role="status">{m.source_loading()}</p>{/if}
  {#if failure}<p role="alert" class="source-error">
      {failure === 'session'
        ? m.source_session()
        : failure === 'stale'
          ? m.preparation_stale()
          : m.preparation_unavailable()}
    </p>{/if}
  {#if loaded && preparations.length === 0}<p>{m.preparation_empty()}</p>{/if}
  {#if loaded && !preparations.some((p) => p.expires_at > now)}
    <a class="work-primary" href={'/work/source-review?lang=' + getLocale()}>{m.work_new_copy()}</a>
  {/if}
  <div class="source-toolbar work-quiet-toolbar">
    <details class="work-details work-list-picker" open={!review}>
      <summary>{m.work_preparation_choose()}</summary>
      <ul class="preparation-list work-current-list">
        {#each preparations.filter((p) => p.expires_at > now) as p (p.id)}
          <li>
            <button
              type="button"
              data-preparation-id={p.id}
              disabled={busy}
              onclick={() => choose(p.id)}
              aria-pressed={review?.preparation.id === p.id}
            >
              <strong>{m.work_saved_copy()} · {p.task.name}</strong><span
                >{copyState(p)} · {date(p.expires_at)}</span
              >
            </button>
          </li>
        {/each}
      </ul>
    </details>
    <button type="button" disabled={busy} onclick={() => load()}>{m.preparation_refresh()}</button>
  </div>
  {#if next}<button type="button" disabled={busy} onclick={() => load(true)}
      >{m.source_more()}</button
    >{/if}
  {#if review}
    {@const p = review.preparation}
    {@const d = review.disclosure}
    {@const files = d.contexts.reduce((n, c) => n + c.files.length, 0)}
    {@const records = [
      { label: m.source_version(), value: d.code.commit, code: true },
      ...(review.currentSources
        ? [
            {
              label: m.preparation_availability(),
              value: p.current_authority
                ? m.preparation_current()
                : p.materialized
                  ? m.preparation_inactive()
                  : m.preparation_unmaterialized(),
              code: false,
            },
          ]
        : []),
      ...(copy
        ? [
            {
              label: m.preparation_copy_account(),
              value: copy.subject.artifacts_account,
              code: true,
            },
          ]
        : []),
      { label: m.preparation_recipient(), value: d.recipient, code: false },
      { label: m.preparation_workload(), value: d.workload, code: false },
      { label: m.preparation_identifier(), value: p.id, code: true },
      { label: m.preparation_manifest(), value: p.disclosure_digest, code: true },
      { label: m.preparation_checked(), value: date(review.checkedAt), code: false },
      {
        label: m.preparation_repository_ids(),
        value:
          (p.task.repository_id ?? m.preparation_unknown()) +
          ' / ' +
          (p.snapshot.repository_id ?? m.preparation_unknown()),
        code: false,
      },
    ]}
    <section class="source-card work-review-card" aria-labelledby="preparation-review-title">
      <div class="source-heading">
        <h2 id="preparation-review-title" bind:this={heading} tabindex="-1">
          {m.preparation_details()}
        </h2>
        <span class="work-state">{copyState(p)}</span>
      </div>
      {#if !review.currentSources}<p class="source-error" role="status">
          {m.preparation_inactive()}
        </p>{/if}
      <div class="work-copy-summary">
        <div>
          <h3>{m.source_code()}</h3>
          <strong>{d.code.repository}</strong>
          <p>{m.work_code_summary({ files: d.code.head_files, commits: d.code.commits })}</p>
        </div>
        <div>
          <h3>{m.preparation_context()}</h3>
          <p>
            {files === 0
              ? m.work_context_none()
              : m.source_selection({ files, bytes: d.selected_bytes })}
          </p>
        </div>
      </div>
      {#if files > 0}<details class="work-details work-selected-files">
          <summary>{m.work_selected_files({ count: files })}</summary>
          {#each d.contexts as c, i}<article>
              <h4>
                {d.registered_sources[i + 1]!.role === 'personal'
                  ? m.source_personal()
                  : m.source_project()} · {c.repository}
              </h4>
              <ul>
                {#each c.files as f}<li>
                    <strong>{f.path}</strong> · {f.bytes}
                    {m.source_bytes()}
                  </li>{/each}
              </ul>
            </article>{/each}
        </details>{/if}
      <div class="work-destination">
        <h3>
          {m.preparation_destinations()}{#if copy}
            · <span>{copy.subject.operator}</span>{/if}
        </h3>
        <dl>
          <div>
            <dt>{m.source_code()}</dt>
            <dd>{p.task.namespace} / {p.task.name}</dd>
          </div>
          <div>
            <dt>{m.preparation_snapshot()}</dt>
            <dd>{p.snapshot.namespace} / {p.snapshot.name}</dd>
          </div>
          <div>
            <dt>{m.preparation_expiry()}</dt>
            <dd>{date(p.expires_at)}</dd>
          </div>
        </dl>
      </div>
      <div class="work-inspection">
        <button
          class:work-primary={!inspected}
          data-work-action="inspect_copy"
          type="button"
          disabled={busy}
          onclick={() => inspect()}>{m.preparation_inspect()}</button
        >
        {#if inspected}<p class="work-checked" role="status">{m.work_inspection_ready()}</p>{/if}
      </div>
      {#if reads.length}<section class="source-preview" aria-label={m.source_preview_title()}>
          <h2 bind:this={previewHeading} tabindex="-1">{m.source_preview_title()}</h2>
          {#each reads as read}<h3>{read.source.label}</h3>
            {#each read.files as file}<article>
                <h4>{file.path}</h4>
                <!-- svelte-ignore a11y_no_noninteractive_tabindex (Keyboard access to a named, scrollable file region.) -->
                <pre tabindex="0" role="region" aria-label={file.path}>{file.content}</pre>
              </article>{/each}{/each}
        </section>{/if}

      {#if copy}
        <section class="work-consent" aria-label={m.preparation_copy_consent()}>
          <p class="work-copy-notice">{m.work_copy_notice()}</p>
          {#if copy.status === 'unconfirmed' && inspected}
            <label class="work-acknowledge"
              ><input
                type="checkbox"
                data-work-confirmation="approve_copy"
                bind:checked={acknowledged}
                disabled={busy || !inspected || !copy.can_approve}
              />
              {m.preparation_copy_acknowledge()}</label
            >
            <button
              class="work-primary"
              type="button"
              disabled={busy || !inspected || !acknowledged || !copy.can_approve}
              data-work-action="approve_copy"
              onclick={() => decideCopy('POST')}>{m.preparation_copy_approve()}</button
            >
          {:else if copy.status === 'approved'}
            <p role="status">
              {copy.current ? m.preparation_copy_approved() : m.preparation_copy_inactive()}
            </p>
            {#if executionEnabled}<a
                class="work-primary"
                href={'/work/copy-review?lang=' + getLocale() + '#' + encodeURIComponent(p.id)}
                >{m.copy_open()}</a
              >{/if}
            <button
              data-work-action="withdraw_copy"
              type="button"
              disabled={busy}
              onclick={() => decideCopy('DELETE')}>{m.preparation_copy_withdraw()}</button
            >
            <p class="work-hint">{m.preparation_copy_withdraw_boundary()}</p>
          {:else if copy.status === 'withdrawn'}<p role="status">
              {m.preparation_copy_withdrawn()}
            </p>
            {#if executionEnabled}<a
                href={'/work/copy-review?lang=' + getLocale() + '#' + encodeURIComponent(p.id)}
                >{m.copy_open()}</a
              >{/if}
          {/if}
        </section>
      {/if}
      <div class="work-review-record">
        <button
          type="button"
          disabled={busy || !review.currentSources || p.expires_at <= now}
          onclick={() => downloadDisclosure()}>{m.preparation_record_save()}</button
        >
        <details class="work-details work-record-details">
          <summary>{m.preparation_integrity()}</summary>
          <p>{m.preparation_record_scope()}</p>
          <dl>
            {#each records as record}<div>
                <dt>{record.label}</dt>
                <dd>
                  {#if record.code}<code>{record.value}</code>{:else}{record.value}{/if}
                </dd>
              </div>{/each}
          </dl>
          <h3>{m.preparation_delegation()}</h3>
          <p>{m.preparation_delegation_body()}</p>
          <p>{m.preparation_boundary()}</p>
        </details>
      </div>
    </section>
  {/if}
  {#if preparations.some((p) => p.expires_at <= now)}
    <details class="work-details work-history">
      <summary
        >{m.work_history({
          count: preparations.filter((p) => p.expires_at <= now).length,
        })}</summary
      >
      <ul class="preparation-list">
        {#each preparations.filter((p) => p.expires_at <= now) as p (p.id)}
          <li>
            <button type="button" disabled
              ><strong>{m.work_past_copy()}</strong><span
                >{copyState(p)} · {m.preparation_expired()}</span
              ></button
            >
          </li>
        {/each}
      </ul>
    </details>
  {/if}
  <WorkWebMcp host={assistant} />
</section>
