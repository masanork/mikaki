<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { getLocale } from './paraglide/runtime.js';
  import * as m from './paraglide/messages.js';
  import { vaultContext } from './vault-context.js';
  import {
    SourceError,
    type OwnedSource,
    type SourceRead,
    sourceHttpPort,
  } from './work-source-view.js';
  import { preparationComposePort, type PreparedSelection } from './work-compose-view.js';
  import WorkWebMcp from './WorkWebMcp.svelte';
  import WorkJourneyIntro from './WorkJourneyIntro.svelte';
  import { WebMcpFailure } from './webmcp.ts';
  import type { WorkWebMcpHost } from './work-webmcp.ts';
  let { port }: { port: ReturnType<typeof sourceHttpPort> } = $props();
  const context = vaultContext(),
    scope = context.current();
  const composePort = preparationComposePort(scope.request);
  const composeEnabled = document.documentElement.dataset.workCompose === 'true';
  let codeId = $state(''),
    minutes = $state(10),
    compositionExpires = 0;
  let prepared = $state<PreparedSelection | null>(null);
  let generation = 0;
  let controller = new AbortController();
  function clear() {
    generation++;
    controller.abort();
    controller = new AbortController();
    sources = [];
    selected = {};
    expandedReferences = {};
    reads = [];
    next = null;
    loaded = false;
    busy = false;
    failure = '';
    codeId = '';
    prepared = null;
    compositionExpires = 0;
  }
  let sources = $state<OwnedSource[]>([]),
    next = $state<string | null>(null),
    busy = $state(false);
  let selected = $state<Record<string, string[]>>({}),
    reads = $state<SourceRead[]>([]),
    failure = $state('');
  let expandedReferences = $state<Record<string, boolean>>({});
  let loaded = $state(false);
  let previewHeading: HTMLHeadingElement | undefined = $state();
  const total = $derived(
    sources.reduce(
      (n, s) =>
        n +
        s.files
          .filter((f) => selected[s.source_id]?.includes(f.path))
          .reduce((n, f) => n + f.bytes, 0),
      0,
    ),
  );
  const count = $derived(Object.values(selected).reduce((n, p) => n + p.length, 0));
  const contexts = $derived(Object.values(selected).filter((p) => p.length > 0).length);
  const codeSource = $derived(sources.find((s) => s.role === 'code' && s.source_id === codeId));
  const date = (time: number) =>
    new Intl.DateTimeFormat(getLocale(), { dateStyle: 'medium', timeStyle: 'long' }).format(
      time * 1000,
    );
  function failed(e: unknown) {
    failure = e instanceof SourceError ? e.reason : 'unavailable';
    reads = [];
    prepared = null;
  }
  async function load(more = false, signal = controller.signal) {
    if (busy) return;
    const current = generation;
    busy = true;
    failure = '';
    reads = [];
    prepared = null;
    if (!more) {
      sources = [];
      selected = {};
      expandedReferences = {};
      loaded = false;
      next = null;
      codeId = '';
      prepared = null;
      compositionExpires = 0;
    }
    try {
      const page = await port.list(
        more ? next : null,
        AbortSignal.any([controller.signal, signal]),
      );
      signal.throwIfAborted();
      if (current !== generation) return;
      scope.assert();
      sources = more ? [...sources, ...page.sources] : page.sources;
      next = page.next_after;
      loaded = true;
    } catch (e) {
      if (current === generation) failed(e);
    } finally {
      if (current === generation) busy = false;
    }
  }
  function choose(source: OwnedSource, path: string, checked: boolean) {
    expandedReferences[source.source_id] = true;
    const paths = selected[source.source_id] ?? [];
    selected = {
      ...selected,
      [source.source_id]: checked ? [...paths, path] : paths.filter((p) => p !== path),
    };
    reads = [];
    failure = '';
    prepared = null;
    compositionExpires = 0;
  }
  function chooseCode(id: string) {
    codeId = id;
    reads = [];
    prepared = null;
    compositionExpires = 0;
    failure = '';
  }
  async function prepare(signal = controller.signal) {
    if (
      busy ||
      !codeSource ||
      !Number.isInteger(minutes) ||
      minutes < 2 ||
      minutes > 30 ||
      (contexts > 0 && reads.length !== contexts) ||
      contexts > 4 ||
      count > 32 ||
      total > 131072
    )
      return;
    const current = generation;
    compositionExpires ||= Math.floor(Date.now() / 1000) + minutes * 60;
    busy = true;
    failure = '';
    prepared = null;
    try {
      const result = await composePort.prepare(
        codeSource,
        sources.flatMap((source) =>
          selected[source.source_id]?.length
            ? [{ source, paths: selected[source.source_id]! }]
            : [],
        ),
        compositionExpires,
        AbortSignal.any([controller.signal, signal]),
      );
      signal.throwIfAborted();
      if (current !== generation) return;
      scope.assert();
      prepared = result;
    } catch (e) {
      if (current === generation) failed(e);
    } finally {
      if (current === generation) busy = false;
    }
  }
  async function review(signal = controller.signal) {
    if (busy || count === 0 || count > 32 || total > 131072 || contexts > 4) return;
    const current = generation;
    busy = true;
    reads = [];
    failure = '';
    prepared = null;
    try {
      const results = [];
      for (const source of sources) {
        const paths = selected[source.source_id];
        if (paths?.length)
          results.push(
            await port.read(source, paths, AbortSignal.any([controller.signal, signal])),
          );
        signal.throwIfAborted();
        if (current !== generation) return;
        scope.assert();
      }
      reads = results;
      await tick();
      if (current === generation) previewHeading?.focus();
    } catch (e) {
      if (current === generation) failed(e);
    } finally {
      if (current === generation) busy = false;
    }
  }
  const assistant: WorkWebMcpHost = {
    page: 'sources',
    snapshot: () => ({
      page: 'sources',
      version: JSON.stringify([
        generation,
        sources,
        selected,
        codeId,
        minutes,
        prepared,
        busy,
        loaded,
        failure,
      ]),
      selection: JSON.stringify([sources, selected, codeId, failure]),
      busy,
      loaded,
      items: sources.map((source) => ({
        id: source.source_id,
        label: source.label,
        role: source.role,
        revision: source.source_revision,
        commit: source.commit,
        files: source.files.map(({ path, bytes }) => ({ path, bytes })),
      })),
      files: sources.flatMap((source) =>
        source.files
          .filter((file) => selected[source.source_id]?.includes(file.path))
          .map(({ path, bytes }) => ({ source_id: source.source_id, path, bytes })),
      ),
      selected: codeId || null,
      prepared: prepared?.preparation_id ?? null,
      copy: null,
    }),
    verify: async () => {
      await scope.verify();
      scope.assert();
    },
    visible: () => document.visibilityState === 'visible',
    contents: () => reads,
    available: (action) =>
      !busy &&
      (action === 'refresh' ||
        (action === 'more' && next !== null) ||
        (action === 'select_files' && loaded) ||
        (action === 'select_code' && composeEnabled && loaded) ||
        (action === 'inspect' && count > 0 && count <= 32 && contexts <= 4 && total <= 131072) ||
        (action === 'prepare' &&
          composeEnabled &&
          !!codeSource &&
          Number.isInteger(minutes) &&
          minutes >= 2 &&
          minutes <= 30 &&
          contexts <= 4 &&
          count <= 32 &&
          total <= 131072 &&
          (contexts === 0 || reads.length === contexts)) ||
        (action === 'open_preparation' && prepared !== null)),
    invoke: async (action, args, signal) => {
      signal.throwIfAborted();
      if (action === 'refresh' || action === 'more') await load(action === 'more', signal);
      else if (action === 'select_code') {
        const source = sources.find((s) => s.source_id === args['source_id'] && s.role === 'code');
        if (!source) throw new WebMcpFailure('not_selected');
        chooseCode(source.source_id);
      } else if (action === 'select_files') {
        const source = sources.find((s) => s.source_id === args['source_id'] && s.role !== 'code');
        const paths = args['paths'] as string[];
        if (!source || paths.some((path) => !source.files.some((file) => file.path === path)))
          throw new WebMcpFailure('not_selected');
        const proposed = { ...selected, [source.source_id]: paths };
        if (
          Object.values(proposed).reduce((n, files) => n + files.length, 0) > 32 ||
          Object.values(proposed).filter((files) => files.length).length > 4 ||
          sources.reduce(
            (n, s) =>
              n +
              s.files
                .filter((file) => proposed[s.source_id]?.includes(file.path))
                .reduce((bytes, file) => bytes + file.bytes, 0),
            0,
          ) > 131072
        )
          throw new WebMcpFailure('selection_limit');
        for (const file of source.files) choose(source, file.path, paths.includes(file.path));
      } else if (action === 'inspect') await review(signal);
      else if (action === 'prepare') await prepare(signal);
      else if (action === 'open_preparation') {
        if (!prepared || prepared.preparation_id !== args['preparation_id'])
          throw new WebMcpFailure('not_selected');
        window.location.assign(
          '/work/preparation-review?lang=' +
            getLocale() +
            '#' +
            encodeURIComponent(prepared.preparation_id),
        );
      } else throw new WebMcpFailure('unavailable');
      signal.throwIfAborted();
      if (failure) throw new WebMcpFailure('unavailable');
    },
  };
  onMount(() => {
    void load();
    const visibility = () => {
      if (document.visibilityState === 'hidden') clear();
    };
    document.addEventListener('visibilitychange', visibility);
    scope.signal.addEventListener('abort', clear, { once: true });
    const unregister = context.registerResume(async () => {
      clear();
    });
    return () => {
      clear();
      unregister();
      document.removeEventListener('visibilitychange', visibility);
      scope.signal.removeEventListener('abort', clear);
    };
  });
</script>

<section id="work-sources" aria-busy={busy}>
  {#if composeEnabled}<WorkJourneyIntro />
    <h2>{m.source_title()}</h2>{/if}
  <p class="source-lead">{m.source_intro()}</p>
  <div class="source-toolbar">
    <button type="button" disabled={busy} onclick={() => load()}>{m.source_refresh()}</button>
    <p aria-live="polite">{busy ? m.source_loading() : ''}</p>
  </div>
  {#if failure}<p role="alert" class="source-error">
      {failure === 'session'
        ? m.source_session()
        : failure === 'stale'
          ? m.source_stale()
          : m.source_unavailable()}
    </p>{/if}
  {#if loaded && sources.length === 0}<p>{m.source_empty()}</p>{/if}
  {#each sources as source (source.source_id)}
    {#if source.code}
      <section
        class="source-card"
        class:work-code-selected={codeId === source.source_id}
        aria-label={source.label}
      >
        <div class="source-heading">
          <h2>{source.label}</h2>
          <span>{m.source_code()}</span>
        </div>
        <p>
          {m.work_code_summary({ files: source.code.head_files, commits: source.code.commits })}
        </p>
        {#if composeEnabled}<label class="work-code-choice"
            ><input
              type="radio"
              name="copy-code"
              disabled={busy}
              aria-label={m.source_compose_code() + ' (' + source.label + ')'}
              checked={codeId === source.source_id}
              onchange={() => chooseCode(source.source_id)}
            />{codeId === source.source_id ? m.work_source_selected() : m.work_select_code()}</label
          >{/if}
        <details class="work-details work-source-metadata">
          <summary>{m.work_selection_details()}</summary>
          <p>{m.source_history({ commits: source.code.commits, files: source.code.head_files })}</p>
          <dl>
            <div>
              <dt>{m.source_version()}</dt>
              <dd><code>{source.commit}</code></dd>
            </div>
            <div>
              <dt>{m.source_revision()}</dt>
              <dd>{source.source_revision}</dd>
            </div>
          </dl>
        </details>
      </section>
    {:else}
      <details
        class="source-card work-reference-source"
        open={!composeEnabled || expandedReferences[source.source_id]}
        ontoggle={(event) => {
          expandedReferences[source.source_id] = event.currentTarget.open;
        }}
      >
        <summary class="source-heading"
          ><span>{source.label}</span><span>{m.work_context_optional()}</span></summary
        >
        <section aria-label={source.label}>
          <p class="work-hint">{m.source_selected_only()}</p>
          <fieldset disabled={busy}>
            <legend>{m.source_choose()}</legend>
            {#each source.files as file (file.path)}<label class="source-file"
                ><input
                  type="checkbox"
                  checked={selected[source.source_id]?.includes(file.path) ?? false}
                  onchange={(event) => choose(source, file.path, event.currentTarget.checked)}
                />
                <span
                  ><strong>{file.path}</strong><small>{file.bytes} {m.source_bytes()}</small></span
                ></label
              >{/each}
          </fieldset>
          <details class="work-details">
            <summary>{m.work_selection_details()}</summary>
            <dl>
              <div>
                <dt>{m.source_version()}</dt>
                <dd><code>{source.commit}</code></dd>
              </div>
              <div>
                <dt>{m.source_revision()}</dt>
                <dd>{source.source_revision}</dd>
              </div>
            </dl>
          </details>
        </section>
      </details>
    {/if}
  {/each}
  {#if next}<button type="button" disabled={busy} onclick={() => load(true)}
      >{m.source_more()}</button
    >{/if}
  <div class="source-review-action">
    {#if composeEnabled}<p>
        {codeSource
          ? m.source_code_selected({ label: codeSource.label })
          : m.source_code_unselected()}
      </p>{/if}
    <p>
      {composeEnabled && count === 0
        ? m.work_context_none()
        : m.source_selection({ files: count, bytes: total })}
    </p>
    {#if count > 0 || !composeEnabled}<button
        class="source-primary work-primary"
        type="button"
        disabled={busy || count === 0 || count > 32 || total > 131072 || contexts > 4}
        onclick={() => review()}>{m.source_preview()}</button
      >{/if}
  </div>
  {#if reads.length}<section aria-label={m.source_preview_title()} class="source-preview">
      <h2 bind:this={previewHeading} tabindex="-1">{m.source_preview_title()}</h2>
      <p>{m.source_read_boundary()}</p>
      {#each reads as read}<h3>{read.source.label}</h3>
        {#each read.files as file}<article>
            <h4>{file.path}</h4>
            <details><summary>{m.source_integrity()}</summary><code>{file.sha256}</code></details>
            <!-- svelte-ignore a11y_no_noninteractive_tabindex (Keyboard access to a named, scrollable file region.) -->
            <pre tabindex="0" role="region" aria-label={file.path}>{file.content}</pre>
          </article>{/each}{/each}
    </section>{/if}
  {#if composeEnabled}<section class="source-preview" aria-label={m.source_compose_title()}>
      <p class="work-hint">{m.source_compose_intro()}</p>
      <details class="work-details">
        <summary>{m.work_expiry_settings()}</summary><label
          >{m.source_compose_minutes()}<input
            type="number"
            min="2"
            max="30"
            step="1"
            bind:value={minutes}
            disabled={busy}
            onchange={() => {
              prepared = null;
              compositionExpires = 0;
            }}
          /></label
        >
      </details>
      {#if !prepared}<button
          class="source-primary work-primary"
          type="button"
          disabled={busy ||
            !codeSource ||
            !Number.isInteger(minutes) ||
            minutes < 2 ||
            minutes > 30 ||
            contexts > 4 ||
            count > 32 ||
            total > 131072 ||
            (contexts > 0 && reads.length !== contexts)}
          onclick={() => prepare()}>{m.source_compose_action()}</button
        >{/if}
      {#if prepared}<div role="status">
          <p>{m.source_compose_ready()}</p>
          <p>{m.preparation_expiry()}: {date(prepared.expires_at)}</p>
          <a
            class="work-primary"
            href={'/work/preparation-review?lang=' +
              getLocale() +
              '#' +
              encodeURIComponent(prepared.preparation_id)}>{m.source_compose_review()}</a
          >
        </div>{/if}
    </section>{/if}
  <details class="work-details work-help">
    <summary>{m.work_source_help()}</summary>
    <p>{m.source_read_boundary()}</p>
    <p>{m.source_limits()}</p>
    <p>{m.source_display_lease()}</p>
  </details>
  <WorkWebMcp host={assistant} />
</section>
