<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { restoreActionFocus } from './action-focus.ts';
  import * as m from './paraglide/messages.js';
  import type { OwnerVaultController } from './vault-owner-controller.ts';
  import {
    OwnerNoteProposals,
    OwnerNoteProposalError,
    type OwnerNoteProposalSnapshot,
    type OwnerNoteProposal,
    type PreparedOwnerNoteCommit,
    type PreparedOwnerNoteDecision,
  } from './vault-owner-note-proposals.ts';

  type PendingOperation =
    | { kind: 'decision'; proposalId: string; operation: PreparedOwnerNoteDecision }
    | { kind: 'commit'; proposalId: string; operation: PreparedOwnerNoteCommit };

  let {
    owner,
    sourceRevision,
    disabled,
    hasDrafts,
    onbusy,
    onunconfirmed,
    onapplied,
  }: {
    owner: OwnerVaultController;
    sourceRevision: number;
    disabled: boolean;
    hasDrafts: () => boolean;
    onbusy: (value: boolean) => void;
    onunconfirmed: (value: boolean) => void;
    onapplied: () => void;
  } = $props();

  const proposals = untrack(() => new OwnerNoteProposals(owner));
  let expanded = $state(false);
  let loading = $state(false);
  // The helper uses WeakSets/WeakMaps to bind snapshots and opaque operations.
  let snapshot = $state.raw<OwnerNoteProposalSnapshot | null>(null);
  let pending = $state.raw<PendingOperation | null>(null);
  let submittedUnknown = false;
  let status = $state('');
  let renderClock = $state(Date.now());
  let observedSourceRevision = untrack(() => sourceRevision);
  const canStart = $derived(!disabled && !loading && pending === null);

  $effect(() => {
    const currentRevision = sourceRevision;
    const previousRevision = untrack(() => observedSourceRevision);
    if (currentRevision === previousRevision) return;
    observedSourceRevision = currentRevision;
    const freshSnapshot = untrack(() => snapshot);
    if (freshSnapshot?.head.revision === currentRevision) return;
    snapshot = null;
    status = freshSnapshot ? m.ownerNoteProposalSourceChanged() : '';
    if (!submittedUnknown) pending = null;
  });

  $effect(() => {
    if (!snapshot) return;
    const deadlines = snapshot.proposals
      .map((proposal) => proposal.expires_at)
      .filter((expires) => expires * 1000 > renderClock);
    if (!deadlines.length) return;
    const next = Math.min(...deadlines) * 1000;
    const timer = setTimeout(
      () => (renderClock = Date.now()),
      Math.max(0, Math.min(2_147_483_647, next - renderClock + 1)),
    );
    return () => clearTimeout(timer);
  });

  function actionable(proposal: OwnerNoteProposal): boolean {
    return (
      proposal.matchingGrantActive &&
      proposal.targetCurrent &&
      proposal.expires_at > renderClock / 1000
    );
  }

  function failure(error: unknown): string {
    if (error instanceof Error && error.message === 'owner_unsaved_changes')
      return m.productUnsavedChanges();
    if (error instanceof OwnerNoteProposalError) {
      if (error.code === 'proposal_unavailable' || error.code === 'recovery_unavailable')
        return m.ownerNoteProposalNoLongerAvailable();
      if (error.code === 'source_changed' || error.code === 'stale_snapshot')
        return m.ownerNoteProposalSourceChanged();
    }
    return owner.scope.signal.aborted ? '' : m.ownerNoteProposalFailed();
  }

  async function load() {
    if (disabled || loading || pending) return;
    const focus = document.activeElement;
    loading = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.verifyAuthority();
      owner.assertCurrent(token);
      const next = await proposals.load();
      owner.assertCurrent(token);
      snapshot = next;
      renderClock = Date.now();
      status = '';
    } catch (error) {
      status = failure(error);
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () =>
          document.getElementById('owner-note-proposals-refresh'),
        );
    }
  }

  async function send(operation: PendingOperation) {
    const focus = document.activeElement;
    const wasSubmitted = submittedUnknown;
    loading = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.scope.verify();
      owner.assertCurrent(token);
      if (hasDrafts()) {
        if (!wasSubmitted) pending = null;
        if (!wasSubmitted) onunconfirmed(false);
        throw new Error('owner_unsaved_changes');
      }
      // Keep the exact helper operation after this boundary; the server may have
      // accepted it even if the response or authoritative read is lost.
      submittedUnknown = true;
      onunconfirmed(true);
      const next =
        operation.kind === 'decision'
          ? await proposals.decide(operation.operation)
          : await proposals.commit(operation.operation);
      owner.assertCurrent(token);
      snapshot = next;
      renderClock = Date.now();
      pending = null;
      submittedUnknown = false;
      onunconfirmed(false);
      status =
        operation.kind === 'commit'
          ? (() => {
              const acknowledgedRevision = next.proposals.find(
                (proposal) => proposal.proposal_id === operation.proposalId,
              )?.result_revision;
              return acknowledgedRevision === null || acknowledgedRevision === undefined
                ? m.ownerNoteProposalCommittedAcknowledged()
                : m.ownerNoteProposalCommitted({ revision: acknowledgedRevision });
            })()
          : m.ownerNoteProposalDecisionRecorded();
      if (operation.kind === 'commit') onapplied();
    } catch (error) {
      if (error instanceof OwnerNoteProposalError && error.definitelyRejected) {
        pending = null;
        submittedUnknown = false;
        onunconfirmed(false);
        snapshot = null;
        try {
          snapshot = await proposals.load();
          renderClock = Date.now();
        } catch {
          snapshot = null;
        }
      } else if (!submittedUnknown) {
        pending = null;
        onunconfirmed(false);
      }
      status =
        error instanceof OwnerNoteProposalError && error.definitelyRejected
          ? m.ownerNoteProposalRejected()
          : failure(error);
      // Unknown outcomes retain the operation object for exact retry.
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () =>
          document.getElementById('owner-note-proposals-retry'),
        );
    }
  }

  async function prepareDecision(proposal: OwnerNoteProposal, approve: boolean) {
    if (!snapshot || !canStart) return;
    if (hasDrafts()) {
      status = m.productUnsavedChanges();
      return;
    }
    const focus = document.activeElement;
    loading = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.verifyAuthority();
      owner.assertCurrent(token);
      const operation = await proposals.prepareDecision(snapshot, proposal.proposal_id, approve);
      owner.assertCurrent(token);
      if (hasDrafts()) {
        status = m.productUnsavedChanges();
        return;
      }
      const prepared: PendingOperation = {
        kind: 'decision',
        proposalId: proposal.proposal_id,
        operation,
      };
      pending = prepared;
      status = '';
      await send(prepared);
    } catch (error) {
      status = failure(error);
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () =>
          document.getElementById('owner-note-proposals-status'),
        );
    }
  }

  async function saveApproved(proposal: OwnerNoteProposal) {
    if (!snapshot || !canStart) return;
    if (
      proposal.target.deleted &&
      !window.confirm(m.ownerNoteProposalRecreateConfirm({ revision: proposal.target.revision }))
    )
      return;
    if (hasDrafts()) {
      status = m.productUnsavedChanges();
      return;
    }
    const focus = document.activeElement;
    loading = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.verifyAuthority();
      owner.assertCurrent(token);
      const operation =
        proposal.operation_id && proposal.candidate
          ? await proposals.recoverCommit(snapshot, proposal.proposal_id)
          : await proposals.prepareCommit(snapshot, proposal.proposal_id);
      owner.assertCurrent(token);
      if (hasDrafts()) {
        status = m.productUnsavedChanges();
        return;
      }
      const prepared: PendingOperation = {
        kind: 'commit',
        proposalId: proposal.proposal_id,
        operation,
      };
      pending = prepared;
      status = '';
      await send(prepared);
    } catch (error) {
      status = failure(error);
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () =>
          document.getElementById('owner-note-proposals-status'),
        );
    }
  }

  function toggle(event: Event) {
    expanded = (event.currentTarget as HTMLDetailsElement).open;
    if (expanded && !snapshot && !loading) void load();
    if (!expanded && !pending) {
      snapshot = null;
      status = '';
    }
  }

  onMount(() => {
    const clear = () => {
      snapshot = null;
      pending = null;
      status = '';
      loading = false;
      onunconfirmed(false);
    };
    owner.scope.signal.addEventListener('abort', clear, { once: true });
    return () => {
      clear();
      owner.scope.signal.removeEventListener('abort', clear);
    };
  });
</script>

<details id="owner-note-proposals" aria-busy={loading} ontoggle={toggle}>
  <summary>{m.agentNoteProposalHeading()}</summary>
  <p>{m.ownerNoteProposalIntro()}</p>
  <div class="product-actions">
    <button
      id="owner-note-proposals-refresh"
      disabled={disabled || loading || pending !== null}
      onclick={load}>{m.ownerNoteProposalRefresh()}</button
    >
  </div>
  {#if snapshot}
    <section aria-labelledby="owner-note-proposals-current-heading">
      <h3 id="owner-note-proposals-current-heading">{m.ownerNoteProposalCurrentHeading()}</h3>
      <p>{m.ownerNoteProposalRevision({ revision: snapshot.head.revision })}</p>
      {#if snapshot.head.value}
        <p><strong>{snapshot.head.value.title}</strong></p>
        <p>{snapshot.head.value.text}</p>
        <p>{m.ownerNoteProposalProvenance({ provenance: snapshot.head.value.provenance.kind })}</p>
      {:else if snapshot.head.deleted}
        <p>{m.ownerNoteProposalDeleted({ revision: snapshot.head.revision })}</p>
      {:else}
        <p>{m.ownerNoteProposalNoSavedNote()}</p>
      {/if}
    </section>
    {#if snapshot.proposals.length === 0}
      <p>{m.ownerNoteProposalEmpty()}</p>
    {:else}
      {#each snapshot.proposals as proposal (proposal.proposal_id)}
        <article id={`owner-note-proposal-${proposal.proposal_id}`}>
          <h3>
            {m.ownerNoteProposalSubmittedBy({
              delegate: proposal.delegate,
              provider: proposal.provider,
            })}
          </h3>
          <p>{m.ownerNoteProposalRevision({ revision: proposal.target.revision })}</p>
          <p>
            {m.ownerNoteProposalExpires({
              expires: new Date(proposal.expires_at * 1000).toLocaleString(),
            })}
          </p>
          <p>
            {m.ownerNoteProposalProvenance({
              provenance: proposal.value?.provenance.kind ?? 'self-asserted',
            })}
          </p>
          {#if proposal.targetCurrent}
            <section>
              <h4>{m.ownerNoteProposalBefore()}</h4>
              {#if snapshot.head.value}
                <p><strong>{snapshot.head.value.title}</strong></p>
                <p>{snapshot.head.value.text}</p>
              {:else if proposal.target.deleted}
                <p>{m.ownerNoteProposalDeleted({ revision: proposal.target.revision })}</p>
              {:else}
                <p>{m.ownerNoteProposalNoSavedNote()}</p>
              {/if}
            </section>
          {:else}
            <p>{m.ownerNoteProposalStale()}</p>
          {/if}
          <section>
            <h4>{m.ownerNoteProposalAfter()}</h4>
            {#if proposal.value}
              <p><strong>{proposal.value.title}</strong></p>
              <p>{proposal.value.text}</p>
              <p>{m.ownerNoteProposalProvenance({ provenance: proposal.value.provenance.kind })}</p>
            {:else}
              <p>{m.ownerNoteProposalNoPayload()}</p>
            {/if}
          </section>
          <p>
            {#if proposal.state === 'pending'}
              {#if proposal.expires_at <= renderClock / 1000}
                {m.ownerNoteProposalExpired()}
              {:else if !proposal.matchingGrantActive}
                {m.ownerNoteProposalGrantInactive()}
              {:else if !proposal.targetCurrent}
                {m.ownerNoteProposalStale()}
              {:else}
                {m.ownerNoteProposalPending()}
              {/if}
            {:else if proposal.state === 'approved'}
              {m.ownerNoteProposalApproved()}
            {:else if proposal.state === 'rejected'}
              {m.ownerNoteProposalRejectedState()}
            {:else if proposal.state === 'committed'}
              {m.ownerNoteProposalCommittedRevision({ revision: proposal.result_revision ?? 0 })}
            {:else}
              {m.ownerNoteProposalInactive()}
            {/if}
          </p>
          {#if proposal.state === 'pending'}
            <div class="product-actions">
              <button
                id={`owner-note-proposal-approve-${proposal.proposal_id}`}
                disabled={!canStart || !actionable(proposal) || !proposal.value}
                onclick={() => prepareDecision(proposal, true)}
                >{m.ownerNoteProposalApprove()}</button
              >
              <button
                id={`owner-note-proposal-reject-${proposal.proposal_id}`}
                disabled={!canStart || !actionable(proposal)}
                onclick={() => prepareDecision(proposal, false)}
                >{m.ownerNoteProposalReject()}</button
              >
            </div>
          {:else if proposal.state === 'approved' && actionable(proposal)}
            <button
              id={`owner-note-proposal-save-${proposal.proposal_id}`}
              disabled={!canStart}
              onclick={() => saveApproved(proposal)}
              >{proposal.operation_id && proposal.candidate
                ? m.ownerNoteProposalResumeSave()
                : m.ownerNoteProposalSave()}</button
            >
          {/if}
        </article>
      {/each}
    {/if}
  {/if}
  {#if pending}
    <button
      id="owner-note-proposals-retry"
      disabled={disabled || loading}
      onclick={() => send(pending!)}>{m.ownerNoteProposalRetry()}</button
    >
  {/if}
  <p id="owner-note-proposals-status" role="status" aria-live="polite">{status}</p>
</details>
