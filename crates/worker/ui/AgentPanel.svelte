<script lang="ts">
  import { vaultScope } from './vault-context.js';
  const scope = vaultScope();
  const fetch = scope.request;
  import { onMount, untrack } from 'svelte';
  import {
    readSavedHead,
    compareSource,
    type SourceAttribute,
    type SourceObservation,
  } from './vault-freshness.js';
  import type { VaultSourceInfo } from '../../agent-worker/tool-results.js';
  import AgentOAuth from './AgentOAuth.svelte';
  import { agentKeyId, sealAgentSnapshot, type AgentRecipient } from './agent-crypto.js';
  import { encodeBase64Url, openAttribute, parseOwnerEnvelope } from './vault-crypto.js';
  import * as m from './paraglide/messages.js';
  import type { Locale } from './paraglide/runtime.js';
  import { decodeOwnerNote, encodeOwnerNote, NOTE_ATTRIBUTE } from './vault-note.js';
  import {
    prepareApprovedNote,
    verifyPreparedNote,
    type PreparedNote,
  } from './attribute-commit.js';

  let {
    opened,
    sourceRevision,
    ownerId,
    loadName,
    noteRevision,
    locale,
    credentialId,
    evaluatePrf,
  }: {
    opened: boolean;
    sourceRevision: number;
    ownerId: string;
    loadName: () => Promise<string>;
    noteRevision: number;
    locale: Locale;
    credentialId: Uint8Array<ArrayBuffer> | null;
    evaluatePrf: (
      credential: Uint8Array<ArrayBuffer>,
      input: Uint8Array<ArrayBuffer>,
    ) => Promise<Uint8Array<ArrayBuffer>>;
  } = $props();
  type Grant = {
    grant_id: string;
    delegate: string;
    provider: string;
    resource: string;
    expires_at: number;
    revoked: number;
    source_revision: number;
    created_at: number;
    active: number;
    operations: string;
  };
  type Proposal = {
    proposal_id: string;
    request_hash: string;
    title: string;
    text: string | null;
    state: string;
    expires_at: number;
  };
  type Draft = { draft_id: string; title: string; text: string };
  type AttributeProposal = {
    proposal_id: string;
    request_hash: string;
    payload: string | null;
    attribute_id: 'owner_note';
    base_revision: number;
    expires_at: number;
    state: string;
    delegate: string;
    provider: string;
    destination: 'owner-vault';
    grant_id: string;
    operation_id: string | null;
    candidate: string | null;
    result_revision: number | null;
  };
  type Audit = { event_id: string; operation: string; outcome: string; created_at: number };
  type Status = {
    recipient: AgentRecipient;
    grants: Grant[];
    proposals: Proposal[];
    drafts: Draft[];
    audit: Audit[];
    attribute_proposals: AttributeProposal[];
    note_revision: number;
  };
  let remote: Status | null = $state(null);
  let remoteCheckedAt = $state(0);
  let clockNow = $state(Date.now());
  let checkingSources = $state(false);
  let sources: Record<SourceAttribute, SourceObservation> = $state({
    name: { head: null, failed: true },
    owner_note: { head: null, failed: true },
  });
  let checkSequence = 0;
  let statusSequence = 0;
  const sourceAttributes: SourceAttribute[] = ['name', 'owner_note'];
  type ExportRecord = {
    id: string;
    copiedAt: number;
    expiry: string;
    documents: { attribute: SourceAttribute; revision: number; checkedAt: number }[];
  };
  let exports: ExportRecord[] = $state([]);
  function sourceLabel(attribute: SourceAttribute) {
    return attribute === 'name' ? m.vaultName() : m.vaultNoteHeading();
  }
  function relation(attribute: SourceAttribute, revision: number) {
    switch (compareSource(sources[attribute], revision)) {
      case 'same':
        return m.agentSourceSame();
      case 'newer':
        return m.agentSourceNewer();
      case 'different':
        return m.agentSourceDifferent();
      case 'deleted':
        return m.agentSourceDeleted();
      case 'missing':
        return m.agentSourceMissing();
      default:
        return m.agentSourceUnknown();
    }
  }
  async function checkSources(account = ownerId): Promise<boolean> {
    if (!account) return false;
    const sequence = ++checkSequence;
    checkingSources = true;
    const observations = await Promise.allSettled([
      readSavedHead('name', fetch),
      readSavedHead('owner_note', fetch),
    ]);
    let sameOwner = false;
    try {
      const response = await fetch('/vault/session', { cache: 'no-store' });
      sameOwner = response.ok && (await response.json()).account_id === account;
    } catch {
      /* A failed account check cannot confirm either observation. */
    }
    if (sequence !== checkSequence || ownerId !== account) return false;
    for (const [index, attribute] of (['name', 'owner_note'] as const).entries()) {
      const result = observations[index]!;
      sources[attribute] =
        sameOwner && result.status === 'fulfilled'
          ? { head: result.value, failed: false }
          : { head: sources[attribute].head, failed: true };
    }
    // A downloaded file stays independent; only the still-prepared download can be cleared.
    if (
      local &&
      local.documents.some(
        (document) => compareSource(sources[document.attribute], document.revision) !== 'same',
      )
    )
      local = null;
    checkingSources = false;
    if (!sameOwner) remote = null;
    return sameOwner;
  }

  let selected = $state(false);
  let selectedNote = $state(false);
  let consent = $state(false);
  let delegate = $state('codex-local');
  let provider = $state('OpenAI');
  let ttl = $state(3600);
  let actions = $state(false);
  let noteConsent = $state(false);
  let busy = $state(false);
  let status = $state('');
  let credential = $state('');
  type LocalDocument = {
    id: string;
    title: string;
    source: string;
    text: string;
    source_info: VaultSourceInfo;
  };
  let local: {
    bundle: string;
    grant: string;
    selection: string;
    preview: { label: string; text: string }[];
    expiry: string;
    id: string;
    documents: ExportRecord['documents'];
  } | null = $state(null);
  const selection = $derived(
    JSON.stringify([
      selected ? opened : null,
      selected ? sourceRevision : null,
      selectedNote ? noteRevision : null,
      ownerId,
      credentialId && encodeBase64Url(credentialId),
      selected,
      selectedNote,
      consent,
      delegate,
      provider,
      ttl,
    ]),
  );
  let pending: { body: string; token: string } | null = $state(null);
  let notePending: {
    proposal: AttributeProposal;
    body: string;
    operation: string;
    prepareBody: string | null;
    prepared: boolean;
    owner: string;
  } | null = $state(null);
  const allowed = $derived(
    opened &&
      sourceRevision > 0 &&
      selected &&
      !selectedNote &&
      consent &&
      /^[A-Za-z0-9_-]{1,80}$/.test(delegate.trim()) &&
      provider.trim().length > 0,
  );
  const localAllowed = $derived(
    ownerId.length > 0 &&
      credentialId !== null &&
      (selected || selectedNote) &&
      (!selected || (opened && sourceRevision > 0)) &&
      (!selectedNote || noteRevision > 0) &&
      consent &&
      /^[A-Za-z0-9_-]{1,80}$/.test(delegate.trim()) &&
      provider.trim().length > 0 &&
      provider.trim().length <= 160 &&
      [3600, 14400, 86400].includes(ttl),
  );
  const random = () => encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));

  function validStatus(value: unknown): value is Status {
    if (typeof value !== 'object' || value === null) return false;
    const item = value as Partial<Status>;
    return (
      !!item.recipient &&
      typeof item.recipient.key_id === 'string' &&
      typeof item.recipient.resource === 'string' &&
      typeof item.recipient.enabled === 'boolean' &&
      typeof item.recipient.public_jwk === 'object' &&
      Array.isArray(item.grants) &&
      item.grants.every(
        (g) =>
          typeof g.grant_id === 'string' &&
          typeof g.delegate === 'string' &&
          typeof g.provider === 'string' &&
          typeof g.resource === 'string' &&
          Number.isSafeInteger(g.expires_at) &&
          Number.isSafeInteger(g.source_revision) &&
          g.source_revision > 0 &&
          Number.isSafeInteger(g.created_at) &&
          g.created_at >= 0 &&
          typeof g.operations === 'string' &&
          (g.revoked === 0 || g.revoked === 1) &&
          (g.active === 0 || g.active === 1),
      ) &&
      Array.isArray(item.proposals) &&
      item.proposals.every(
        (p) =>
          typeof p.proposal_id === 'string' &&
          typeof p.request_hash === 'string' &&
          typeof p.title === 'string' &&
          (p.text === null || typeof p.text === 'string') &&
          typeof p.state === 'string' &&
          Number.isSafeInteger(p.expires_at),
      ) &&
      Array.isArray(item.drafts) &&
      Number.isSafeInteger(item.note_revision) &&
      item.note_revision! >= 0 &&
      Array.isArray(item.attribute_proposals) &&
      item.attribute_proposals.every(validAttributeProposal) &&
      item.drafts.every(
        (d) =>
          typeof d.draft_id === 'string' &&
          typeof d.title === 'string' &&
          typeof d.text === 'string',
      ) &&
      Array.isArray(item.audit) &&
      item.audit.every(
        (a) =>
          typeof a.event_id === 'string' &&
          typeof a.operation === 'string' &&
          typeof a.outcome === 'string' &&
          Number.isSafeInteger(a.created_at),
      )
    );
  }

  function validAttributeProposal(value: unknown): value is AttributeProposal {
    if (typeof value !== 'object' || value === null) return false;
    const p = value as Partial<AttributeProposal>;
    if (
      typeof p.proposal_id !== 'string' ||
      typeof p.request_hash !== 'string' ||
      p.attribute_id !== 'owner_note' ||
      !Number.isSafeInteger(p.base_revision) ||
      p.base_revision! < 0 ||
      !Number.isSafeInteger(p.expires_at) ||
      !['pending', 'approved', 'rejected', 'invalid', 'committed'].includes(p.state ?? '') ||
      p.destination !== 'owner-vault' ||
      typeof p.delegate !== 'string' ||
      typeof p.provider !== 'string'
    )
      return false;
    if (
      p.state === 'committed' &&
      (!Number.isSafeInteger(p.result_revision) ||
        p.result_revision !== p.base_revision! + 1 ||
        p.payload !== null ||
        p.candidate === null ||
        p.operation_id === null)
    )
      return false;
    if (
      typeof p.grant_id !== 'string' ||
      !(p.operation_id === null || typeof p.operation_id === 'string') ||
      !(p.candidate === null || typeof p.candidate === 'string') ||
      !(p.result_revision === null || Number.isSafeInteger(p.result_revision))
    )
      return false;
    if (p.payload === null) return ['rejected', 'invalid', 'committed'].includes(p.state!);
    if (typeof p.payload !== 'string') return false;
    try {
      decodeOwnerNote(new TextEncoder().encode(p.payload));
      return true;
    } catch {
      return false;
    }
  }
  function proposalValue(payload: string) {
    return decodeOwnerNote(new TextEncoder().encode(payload));
  }

  async function commitNote(proposal: AttributeProposal): Promise<void> {
    if (
      busy ||
      !credentialId ||
      !remote ||
      (notePending && notePending.proposal.proposal_id !== proposal.proposal_id)
    )
      return;
    busy = true;
    try {
      if (!notePending) {
        if (proposal.state !== 'approved' || proposal.payload === null) throw new Error();
        if (proposal.candidate !== null && proposal.operation_id !== null) {
          await verifyPreparedNote(
            { ...proposal, payload: proposal.payload },
            proposal.candidate,
            credentialId,
            evaluatePrf,
          );
          notePending = {
            proposal,
            body: proposal.candidate,
            operation: proposal.operation_id,
            prepareBody: null,
            prepared: true,
            owner: ownerId,
          };
        } else {
          const prepared: PreparedNote = await prepareApprovedNote(
            { ...proposal, payload: proposal.payload },
            ownerId,
            remote.recipient,
            credentialId,
            evaluatePrf,
          );
          notePending = {
            proposal,
            body: prepared.candidate,
            operation: prepared.operation_id,
            prepareBody: JSON.stringify(prepared),
            prepared: false,
            owner: ownerId,
          };
        }
      }
      const operation = notePending;
      if (!operation.prepared) {
        const response = await fetch('/vault/agents/attribute-prepare', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: operation.prepareBody,
        });
        if (!response.ok) throw new Error();
        operation.prepared = true;
        operation.prepareBody = null;
      }
      const response = await fetch('/vault/attributes/owner_note/approved', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Operation-ID': operation.operation,
          'X-Attribute-Proposal': operation.proposal.proposal_id,
          'X-Proposal-Hash': operation.proposal.request_hash,
          ...(operation.proposal.base_revision === 0
            ? { 'If-None-Match': '*' }
            : { 'If-Match': `"${operation.proposal.base_revision}"` }),
        },
        body: operation.body,
      });
      if (!response.ok) throw new Error();
      notePending = null;
      status = m.agentNoteCommitted();
      await refresh();
    } catch {
      status = m.agentNoteCommitFailed();
    } finally {
      busy = false;
    }
  }

  async function refresh(): Promise<void> {
    const account = ownerId;
    const sequence = ++statusSequence;
    if (!account) return;
    const sameOwner = await checkSources(account);
    if (ownerId !== account || sequence !== statusSequence) return;
    if (!sameOwner) {
      remote = null;
      return;
    }
    try {
      const response = await fetch('/vault/agents/status', { cache: 'no-store' });
      if (ownerId !== account || sequence !== statusSequence) return;
      if (!response.ok) {
        remote = null;
        return;
      }
      const body: unknown = await response.json();
      if (ownerId !== account || sequence !== statusSequence) return;
      if (
        !validStatus(body) ||
        (await agentKeyId(body.recipient.public_jwk)) !== body.recipient.key_id
      )
        throw new Error();
      const resource = new URL(body.recipient.resource);
      if (
        resource.protocol !== 'https:' ||
        resource.pathname !== '/mcp' ||
        resource.search ||
        resource.hash
      )
        throw new Error();
      if (ownerId !== account || sequence !== statusSequence) return;
      remote = body;
      remoteCheckedAt = Date.now();
    } catch {
      if (ownerId === account && sequence === statusSequence) remote = null;
    }
  }

  async function prepareLocal(): Promise<void> {
    if (!localAllowed || busy || pending) return;
    const preparedSelection = selection;
    const expectedNoteRevision = noteRevision;
    busy = true;
    local = null;
    try {
      const documents: LocalDocument[] = [];
      const observedDocuments: ExportRecord['documents'] = [];
      const preview: { label: string; text: string }[] = [];
      if (selected) {
        const name = await loadName();
        const confirmedAt = Date.now();
        documents.push({
          id: 'name',
          title: m.vaultName(),
          source: `vault:name:${sourceRevision}`,
          source_info: {
            kind: 'vault',
            attribute: 'name',
            revision: sourceRevision,
            provenance: 'self-asserted',
            confirmed_at: Math.floor(confirmedAt / 1000),
          },
          text: name,
        });
        preview.push({ label: m.agentLocalSavedName({ revision: sourceRevision }), text: name });
        observedDocuments.push({
          attribute: 'name',
          revision: sourceRevision,
          checkedAt: confirmedAt,
        });
      }
      if (selectedNote) {
        const record = await readNoteRecord(expectedNoteRevision);
        const envelope = parseOwnerEnvelope(record.owner_envelope);
        const output = await evaluatePrf(envelope.credentialId, envelope.prfInput);
        let plaintext: Uint8Array<ArrayBuffer> | null = null;
        try {
          plaintext = await openAttribute(
            record,
            output,
            envelope.credentialId,
            location.origin,
            NOTE_ATTRIBUTE,
            expectedNoteRevision,
          );
          const note = decodeOwnerNote(plaintext);
          // Recheck the live saved head after the passkey prompt; edits in the editor are excluded.
          const current = await readNoteRecord(expectedNoteRevision);
          if (
            current.ciphertext !== record.ciphertext ||
            current.owner_envelope !== record.owner_envelope
          )
            throw new Error();
          const confirmedAt = Date.now();
          const encoded = encodeOwnerNote(note);
          try {
            documents.push({
              id: NOTE_ATTRIBUTE,
              title: m.vaultNoteHeading(),
              source: `vault:owner_note:${expectedNoteRevision}:self-asserted`,
              source_info: {
                kind: 'vault',
                attribute: NOTE_ATTRIBUTE,
                revision: expectedNoteRevision,
                provenance: 'self-asserted',
                confirmed_at: Math.floor(confirmedAt / 1000),
              },
              text: new TextDecoder().decode(encoded),
            });
          } finally {
            encoded.fill(0);
          }
          observedDocuments.push({
            attribute: NOTE_ATTRIBUTE,
            revision: expectedNoteRevision,
            checkedAt: confirmedAt,
          });
          preview.push({
            label: m.agentLocalSavedNote({ revision: expectedNoteRevision }),
            text: `${note.title}\n${note.text}`,
          });
        } finally {
          output.fill(0);
          plaintext?.fill(0);
        }
      }
      const bundle = JSON.stringify({
        version: 1,
        owner: ownerId,
        collection: 'vault',
        documents,
      });
      const bytes = new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bundle)),
      );
      const start = Math.floor(Date.now() / 1000);
      const grantId = random();
      const grant = JSON.stringify({
        version: 1,
        id: grantId,
        owner: ownerId,
        collection: 'vault',
        delegate: delegate.trim(),
        service: provider.trim(),
        export_sha256: Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(''),
        document_ids: documents.map((document) => document.id),
        operations: ['list', 'search', 'read'],
        not_before: start,
        expires_at: start + ttl,
        revoked: false,
      });
      const session = await fetch('/vault/session', { cache: 'no-store' });
      if (
        !session.ok ||
        (await session.json()).account_id !== ownerId ||
        !localAllowed ||
        selection !== preparedSelection
      )
        throw new Error();
      local = {
        id: grantId,
        documents: observedDocuments,
        bundle,
        grant,
        selection: preparedSelection,
        preview,
        expiry: new Date((start + ttl) * 1000).toLocaleString(locale),
      };
      status = m.agentLocalReady();
    } catch {
      status = m.agentFailed();
    } finally {
      busy = false;
    }
  }

  async function readNoteRecord(expectedRevision: number) {
    const response = await fetch(`/vault/attributes/${NOTE_ATTRIBUTE}`, { cache: 'no-store' });
    if (!response.ok || response.headers.get('ETag') !== `"${expectedRevision}"`) throw new Error();
    const record: unknown = await response.json();
    if (
      typeof record !== 'object' ||
      record === null ||
      !('revision' in record) ||
      record.revision !== expectedRevision ||
      !('format_version' in record) ||
      record.format_version !== 1 ||
      !('ciphertext' in record) ||
      typeof record.ciphertext !== 'string' ||
      !('owner_envelope' in record) ||
      typeof record.owner_envelope !== 'string'
    )
      throw new Error();
    return {
      format_version: 1 as const,
      ciphertext: record.ciphertext,
      owner_envelope: record.owner_envelope,
    };
  }

  function downloadLocal(): void {
    if (!local) return;
    download('agent-export.json', local.bundle);
    if (!exports.some((item) => item.id === local!.id)) {
      exports = [
        {
          id: local.id,
          copiedAt: Date.now(),
          expiry: local.expiry,
          documents: local.documents.map((item) => ({ ...item })),
        },
        ...exports,
      ].slice(0, 20);
    }
  }

  function download(name: string, body: string): void {
    scope.assert();
    const url = URL.createObjectURL(new Blob([body], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function createRemote(): Promise<void> {
    if (!remote?.recipient.enabled || !allowed || busy) return;
    busy = true;
    credential = '';
    local = null;
    try {
      if (!pending) {
        const name = await loadName();
        const token = `mag_${random()}`;
        const grantId = random();
        const expiresAt = Math.floor(Date.now() / 1000) + ttl;
        const recipient = remote.recipient;
        const envelope = await sealAgentSnapshot(
          [
            {
              id: 'name',
              title: m.vaultName(),
              source: `vault:name:${sourceRevision}`,
              text: name,
            },
          ],
          recipient,
          {
            owner: ownerId,
            grant_id: grantId,
            key_id: recipient.key_id,
            resource: recipient.resource,
            expires_at: expiresAt,
            source_revision: sourceRevision,
          },
        );
        const tokenHash = encodeBase64Url(
          new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))),
        );
        pending = {
          token,
          body: JSON.stringify({
            grant_id: grantId,
            delegate: delegate.trim(),
            provider: provider.trim(),
            resource: recipient.resource,
            source_revision: sourceRevision,
            recipient_key_id: recipient.key_id,
            operations: actions
              ? ['list', 'search', 'read', 'propose', 'execute']
              : ['list', 'search', 'read'],
            document_ids: ['name'],
            envelope,
            token_hash: tokenHash,
            expires_at: expiresAt,
          }),
        };
      }
      const response = await fetch('/vault/agents/grants', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: pending.body,
      });
      if (!response.ok) throw new Error();
      credential = pending.token;
      pending = null;
      status = m.agentReady();
      await refresh();
    } catch {
      status = m.agentFailed();
    } finally {
      busy = false;
    }
  }

  async function mutate(
    path: 'revoke' | 'decide' | 'attribute-capability' | 'attribute-decide',
    body: unknown,
  ): Promise<void> {
    if (busy) return;
    busy = true;
    try {
      const response = await fetch(`/vault/agents/${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error();
      if (path === 'revoke') {
        credential = '';
        pending = null;
      }
      if (path === 'attribute-capability') {
        noteConsent = false;
        status = m.agentNoteAllowed();
      }
      if (path === 'attribute-decide') status = m.agentNoteDecided();
      await refresh();
    } catch {
      status = m.agentFailed();
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    if (notePending && notePending.owner !== ownerId) notePending = null;
    if (local && local.selection !== selection) local = null;
    if (!opened || sourceRevision < 1) {
      credential = '';
      pending = null;
    }
    if (
      !ownerId ||
      !credentialId ||
      (selected && (!opened || sourceRevision < 1)) ||
      (selectedNote && noteRevision < 1)
    ) {
      local = null;
      consent = false;
    }
  });
  $effect(() => {
    const account = ownerId;
    checkSequence += 1;
    checkingSources = false;
    sources = { name: { head: null, failed: true }, owner_note: { head: null, failed: true } };
    exports = [];
    remote = null;
    remoteCheckedAt = 0;
    statusSequence += 1;
    untrack(() => {
      if (account) void refresh();
    });
  });
  onMount(() => {
    void refresh();
    const interval = setInterval(() => {
      clockNow = Date.now();
    }, 1000);
    return () => {
      clearInterval(interval);
      checkSequence += 1;
      statusSequence += 1;
    };
  });
</script>

<section aria-label={m.agentHeading()}>
  <h2>{m.agentHeading()}</h2>
  <p>{m.agentExplanation()}</p>
  <AgentOAuth grants={remote?.grants ?? []} />
  <section aria-label={m.agentSourcesHeading()}>
    <h3>{m.agentSourcesHeading()}</h3>
    <p>{m.agentSourcesExplanation()}</p>
    <button
      type="button"
      disabled={busy || checkingSources || !ownerId}
      onclick={() => {
        void checkSources();
      }}>{m.agentCheckSources()}</button
    >
    {#each sourceAttributes as attribute}
      <div data-source={attribute}>
        <h4>{sourceLabel(attribute)}</h4>
        {#if sources[attribute].head}
          {#if sources[attribute].head!.revision > 0}
            <p>{m.agentSourceObserved({ revision: sources[attribute].head!.revision })}</p>
          {/if}
          <p>
            {m.agentSourceChecked({
              time: new Date(sources[attribute].head!.checkedAt).toLocaleString(locale),
            })}
          </p>
        {/if}
        <p>
          {checkingSources
            ? m.agentSourceChecking()
            : sources[attribute].failed
              ? m.agentSourceUnknown()
              : sources[attribute].head?.state === 'saved'
                ? m.agentSourceSaved()
                : relation(attribute, 0)}
        </p>
        {#if (attribute === 'name' ? sourceRevision : noteRevision) > 0}
          <p>
            {m.agentEditorRevision({
              revision: attribute === 'name' ? sourceRevision : noteRevision,
            })} · {relation(attribute, attribute === 'name' ? sourceRevision : noteRevision)}
          </p>
        {/if}
      </div>
    {/each}
  </section>
  <fieldset disabled={busy || pending !== null}>
    <label
      ><input
        type="checkbox"
        bind:checked={selected}
        disabled={(!opened || sourceRevision < 1) && !selected}
      />{m.agentSelectName()}</label
    >
    <label
      ><input
        type="checkbox"
        bind:checked={selectedNote}
        disabled={!credentialId || (noteRevision < 1 && !selectedNote)}
      />{m.agentSelectLocalNote()}</label
    >
    <p>{m.agentLocalNoteScope()}</p>
    <label>{m.agentDelegate()}<input type="text" maxlength="80" bind:value={delegate} /></label>
    <label>{m.agentProvider()}<input type="text" maxlength="160" bind:value={provider} /></label>
    <label
      >{m.agentLifetime()}<select bind:value={ttl}
        ><option value={3600}>{m.agentOneHour()}</option><option value={14400}
          >{m.agentFourHours()}</option
        ><option value={86400}>{m.agentOneDay()}</option></select
      ></label
    >
    <p>{m.agentReadScope()}</p>
    <label
      ><input
        type="checkbox"
        bind:checked={actions}
        disabled={selectedNote}
      />{m.agentActionScope()}</label
    >
    <label><input type="checkbox" bind:checked={consent} />{m.agentConsent()}</label>
  </fieldset>
  <p>{m.agentLocalDisclosure()}</p>
  <button
    class="product-primary"
    type="button"
    disabled={!localAllowed || busy || pending !== null}
    onclick={prepareLocal}>{m.agentPrepareLocal()}</button
  >
  {#if local}
    <h3>{m.agentLocalPreview()}</h3>
    <p>
      {m.agentLocalRecipient({
        delegate: delegate.trim(),
        provider: provider.trim(),
        expiry: local.expiry,
      })}
    </p>
    {#each local.preview as item}
      <h4>{item.label}</h4>
      <pre style="white-space: pre-wrap; overflow-wrap: anywhere;">{item.text}</pre>
    {/each}
    <button type="button" onclick={downloadLocal}>{m.agentDownloadExport()}</button>
    <button type="button" onclick={() => local && download('agent-grant.json', local.grant)}
      >{m.agentDownloadGrant()}</button
    >
  {/if}
  {#if exports.length}
    <section aria-label={m.agentExportHistoryHeading()}>
      <h3>{m.agentExportHistoryHeading()}</h3>
      <p>{m.agentExportHistoryExplanation()}</p>
      {#each exports as item (item.id)}
        <div>
          <p>{m.agentExportStarted({ time: new Date(item.copiedAt).toLocaleString(locale) })}</p>
          <p>{m.agentUntil({ expiry: item.expiry })}</p>
          {#each item.documents as document}
            <p>
              {sourceLabel(document.attribute)} · {m.agentSnapshotRevision({
                revision: document.revision,
              })} · {relation(document.attribute, document.revision)}
            </p>
            <p>
              {m.agentSourceChecked({ time: new Date(document.checkedAt).toLocaleString(locale) })}
            </p>
          {/each}
        </div>
      {/each}
    </section>
  {/if}
  {#if remote}
    <p>{remote.recipient.resource}</p>
    <button
      class="product-primary"
      type="button"
      disabled={!remote.recipient.enabled || !allowed || busy}
      onclick={createRemote}>{pending ? m.agentRetryRemote() : m.agentCreateRemote()}</button
    >
  {:else}<p>{m.agentRemoteUnavailable()}</p>{/if}
  {#if credential}
    <label>{m.agentCredential()}<input type="password" readonly value={credential} /></label>
    <button
      type="button"
      onclick={() => {
        void scope
          .ensure()
          .then(() => {
            scope.assert();
            return navigator.clipboard.writeText(credential);
          })
          .catch(() => {
            status = m.agentFailed();
          });
      }}>{m.agentCopyCredential()}</button
    >
    <button
      class="product-danger"
      type="button"
      onclick={() => {
        credential = '';
      }}>{m.agentForgetCredential()}</button
    >
  {/if}
  <p role="status">{busy ? m.agentBusy() : status}</p>
  <button type="button" disabled={busy || checkingSources || !ownerId} onclick={refresh}
    >{m.agentRefresh()}</button
  >
  {#if remote}
    <h3>{m.agentConnections()}</h3>
    <p>{m.agentSourceChecked({ time: new Date(remoteCheckedAt).toLocaleString(locale) })}</p>
    <button
      class="product-danger"
      type="button"
      disabled={busy}
      onclick={() => mutate('revoke', { grant_id: null })}>{m.agentRevokeAll()}</button
    >
    <p>{m.agentNoteScope()}</p>
    <p>{m.agentNoteRevision({ revision: String(remote.note_revision) })}</p>
    <label
      ><input
        type="checkbox"
        bind:checked={noteConsent}
        disabled={busy}
      />{m.agentNoteConsent()}</label
    >
    {#each remote.grants as grant (grant.grant_id)}
      <div>
        <p>{grant.delegate} · {grant.provider} · {grant.resource}</p>
        <p>{m.vaultName()} · {m.agentReadScope()}</p>
        <p>
          {m.agentSnapshotRevision({ revision: grant.source_revision })} · {relation(
            'name',
            grant.source_revision,
          )}
        </p>
        <p>
          {m.agentShareCreated({ time: new Date(grant.created_at * 1000).toLocaleString(locale) })}
        </p>
        {#if grant.operations.includes('"execute"')}<p>{m.agentActionScope()}</p>{/if}
        {#if grant.active && grant.operations.includes('"propose"')}
          <button
            type="button"
            disabled={busy || !noteConsent}
            onclick={() =>
              remote &&
              mutate('attribute-capability', {
                grant_id: grant.grant_id,
                attribute_id: 'owner_note',
                base_revision: remote.note_revision,
              })}>{m.agentNoteAllow()}</button
          >
        {/if}
        <p>{m.agentUntil({ expiry: new Date(grant.expires_at * 1000).toLocaleString(locale) })}</p>
        {#if !grant.active || grant.expires_at * 1000 <= clockNow}<p>
            {m.agentInactive()}
          </p>
        {:else}<button
            class="product-danger"
            type="button"
            disabled={busy}
            onclick={() => mutate('revoke', { grant_id: grant.grant_id })}>{m.agentRevoke()}</button
          >{/if}
      </div>
    {/each}
    <ul>
      {#each remote.audit as event (event.event_id)}<li>
          {new Date(event.created_at * 1000).toLocaleString(locale)} · {event.operation} · {event.outcome}
        </li>{/each}
    </ul>
    <h3>{m.agentProposalHeading()}</h3>
    {#each remote.proposals as proposal (proposal.proposal_id)}
      <div>
        <h4>{proposal.title}</h4>
        <pre>{proposal.text ?? ''}</pre>
        {#if proposal.state === 'pending' && proposal.expires_at * 1000 > Date.now()}
          <button
            class="product-primary"
            type="button"
            disabled={busy}
            onclick={() =>
              mutate('decide', {
                proposal_id: proposal.proposal_id,
                request_hash: proposal.request_hash,
                approve: true,
              })}>{m.agentApprove()}</button
          >
          <button
            class="product-danger"
            type="button"
            disabled={busy}
            onclick={() =>
              mutate('decide', {
                proposal_id: proposal.proposal_id,
                request_hash: proposal.request_hash,
                approve: false,
              })}>{m.agentReject()}</button
          >
        {/if}
      </div>
    {/each}
    <h3>{m.agentDraftHeading()}</h3>
    {#each remote.drafts as draft (draft.draft_id)}<div>
        <h4>{draft.title}</h4>
        <pre>{draft.text}</pre>
      </div>{/each}
    <h3>{m.agentNoteProposalHeading()}</h3>
    <p>{m.agentNoteDecisionOnly()}</p>
    {#each remote.attribute_proposals as proposal (proposal.proposal_id)}
      <div>
        <p>{proposal.delegate} · {proposal.provider}</p>
        <p>
          {m.agentNoteRevision({ revision: String(proposal.base_revision) })} · {proposal.state}
        </p>
        <p>
          {m.agentUntil({ expiry: new Date(proposal.expires_at * 1000).toLocaleString(locale) })}
        </p>
        {#if proposal.payload !== null}
          <h4>{proposalValue(proposal.payload).title}</h4>
          <pre>{proposalValue(proposal.payload).text}</pre>
        {/if}
        {#if proposal.state === 'pending' && proposal.expires_at * 1000 > Date.now() && proposal.base_revision === remote.note_revision}
          <button
            class="product-primary"
            type="button"
            disabled={busy}
            onclick={() =>
              mutate('attribute-decide', {
                proposal_id: proposal.proposal_id,
                request_hash: proposal.request_hash,
                approve: true,
              })}>{m.agentNoteApprove()}</button
          >
          <button
            class="product-danger"
            type="button"
            disabled={busy}
            onclick={() =>
              mutate('attribute-decide', {
                proposal_id: proposal.proposal_id,
                request_hash: proposal.request_hash,
                approve: false,
              })}>{m.agentReject()}</button
          >
        {/if}
        {#if proposal.state === 'approved' && proposal.payload !== null && proposal.expires_at * 1000 > Date.now() && proposal.base_revision === remote.note_revision}
          <button
            class="product-primary"
            type="button"
            disabled={busy ||
              !credentialId ||
              (notePending !== null && notePending.proposal.proposal_id !== proposal.proposal_id)}
            onclick={() => commitNote(proposal)}>{m.agentNoteCommit()}</button
          >
        {/if}
        {#if proposal.state === 'committed'}<p>
            {m.agentNoteCommittedRevision({ revision: String(proposal.result_revision) })}
          </p>{/if}
      </div>
    {/each}
    {#if notePending}
      <button
        type="button"
        disabled={busy}
        onclick={() => notePending && commitNote(notePending.proposal)}
        >{m.agentNoteCommitRetry()}</button
      >
      <button
        type="button"
        disabled={busy}
        onclick={() => {
          notePending = null;
          void refresh();
        }}>{m.agentNoteCommitForget()}</button
      >
    {/if}
  {/if}
</section>
