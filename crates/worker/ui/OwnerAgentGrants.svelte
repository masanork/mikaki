<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { restoreActionFocus } from './action-focus.ts';
  import * as m from './paraglide/messages.js';
  import type { OwnerVaultController } from './vault-owner-controller.ts';
  import {
    OwnerAgentGrants,
    OwnerAgentGrantError,
    type OwnerAgentGrantSnapshot,
    type OwnerAgentGrantRecord,
    type PreparedOwnerAgentGrant,
    type PreparedOwnerAgentCapability,
    type PreparedOwnerAgentRevoke,
  } from './vault-owner-agent-grants.ts';

  type PendingOperation =
    | { kind: 'grant'; operation: PreparedOwnerAgentGrant; sourceId: 'name' | 'owner_note' }
    | { kind: 'capability'; operation: PreparedOwnerAgentCapability; grantId: string }
    | { kind: 'revoke'; operation: PreparedOwnerAgentRevoke; grantId: string };

  let {
    owner,
    nameRevision,
    noteRevision,
    disabled,
    hasDrafts,
    refreshEpoch = 0,
    onbusy,
    onunconfirmed,
    onchanged,
  }: {
    owner: OwnerVaultController;
    nameRevision: number;
    noteRevision: number;
    disabled: boolean;
    hasDrafts: () => boolean;
    refreshEpoch?: number;
    onbusy: (value: boolean) => void;
    onunconfirmed: (value: boolean) => void;
    onchanged: () => void | Promise<void>;
  } = $props();

  const grants = untrack(() => new OwnerAgentGrants(owner));
  let expanded = $state(false);
  let loading = $state(false);
  // These identity-bound helper values must remain unproxied for exact retries.
  let snapshot = $state.raw<OwnerAgentGrantSnapshot | null>(null);
  let pending = $state.raw<PendingOperation | null>(null);
  let submittedUnknown = false;
  let shownToken = $state.raw<string | null>(null);
  let shownTokenExpiry = $state(0);
  let shownTokenGrantId = $state('');
  let sourceId = $state<'name' | 'owner_note'>('name');
  let delegate = $state('');
  let provider = $state('');
  let grantLifetime = $state(86400);
  let includePropose = $state(false);
  let grantConsent = $state(false);
  let capabilityConsent = $state('');
  let status = $state('');
  let renderClock = $state(Date.now());
  let observedNameRevision = untrack(() => nameRevision);
  let observedNoteRevision = untrack(() => noteRevision);
  let observedRefreshEpoch = untrack(() => refreshEpoch);
  const canPrepare = $derived(!disabled && !loading && pending === null);

  $effect(() => {
    const currentName = nameRevision;
    const currentNote = noteRevision;
    const previousName = untrack(() => observedNameRevision);
    const previousNote = untrack(() => observedNoteRevision);
    if (currentName === previousName && currentNote === previousNote) return;
    observedNameRevision = currentName;
    observedNoteRevision = currentNote;
    const hadSnapshot = untrack(() => snapshot !== null);
    snapshot = null;
    shownToken = null;
    shownTokenGrantId = '';
    capabilityConsent = '';
    grantConsent = false;
    if (!submittedUnknown) pending = null;
    status = hadSnapshot ? m.ownerAgentGrantSourceChanged() : '';
  });

  $effect(() => {
    const currentEpoch = refreshEpoch;
    const previousEpoch = untrack(() => observedRefreshEpoch);
    if (currentEpoch === previousEpoch) return;
    observedRefreshEpoch = currentEpoch;
    if (expanded && !loading && pending === null && !submittedUnknown) void load();
  });

  $effect(() => {
    if (!snapshot) return;
    const deadlines = snapshot.grants
      .flatMap((grant) => [grant.expires_at, grant.capability.expires_at])
      .filter((expires): expires is number => expires !== null && expires * 1000 > renderClock);
    if (shownToken && shownTokenExpiry * 1000 > renderClock) deadlines.push(shownTokenExpiry);
    if (!deadlines.length) return;
    const next = Math.min(...deadlines) * 1000;
    const timer = setTimeout(
      () => {
        renderClock = Date.now();
        if (shownToken && shownTokenExpiry * 1000 <= renderClock) {
          shownToken = null;
          shownTokenGrantId = '';
          status = m.ownerAgentGrantTokenExpired();
        }
      },
      Math.max(0, Math.min(2_147_483_647, next - renderClock + 1)),
    );
    return () => clearTimeout(timer);
  });

  function failure(error: unknown): string {
    if (error instanceof Error && error.message === 'owner_unsaved_changes')
      return m.productUnsavedChanges();
    if (error instanceof OwnerAgentGrantError) {
      if (error.code === 'source_changed') return m.ownerAgentGrantSourceChanged();
      if (error.code === 'source_unavailable') return m.ownerAgentGrantSourceUnavailable();
      if (error.code === 'recipient_disabled') return m.ownerAgentGrantRecipientDisabled();
    }
    return owner.scope.signal.aborted ? '' : m.ownerAgentGrantFailed();
  }

  function grantIsLive(grant: OwnerAgentGrantRecord): boolean {
    return grant.active && grant.expires_at > renderClock / 1000;
  }

  function capabilityIsLive(grant: OwnerAgentGrantRecord): boolean {
    return (
      grant.capability.state === 'active' &&
      grant.capability.expires_at !== null &&
      grant.capability.expires_at > renderClock / 1000
    );
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
      const next = await grants.load();
      owner.assertCurrent(token);
      snapshot = next;
      renderClock = Date.now();
      const tokenGrant = next.grants.find((grant) => grant.grant_id === shownTokenGrantId);
      if (shownToken && (!tokenGrant?.active || tokenGrant.expires_at * 1000 <= renderClock)) {
        shownToken = null;
        shownTokenGrantId = '';
      }
      if (!next.sources[sourceId].available) {
        sourceId = next.sources.name.available ? 'name' : 'owner_note';
      }
      grantConsent = false;
      capabilityConsent = '';
      status = '';
    } catch (error) {
      status = failure(error);
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () =>
          document.getElementById('owner-agent-grants-refresh'),
        );
    }
  }

  async function send(operation: PendingOperation) {
    const focus = document.activeElement;
    loading = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.scope.verify();
      owner.assertCurrent(token);
      if (hasDrafts()) throw new Error('owner_unsaved_changes');
      submittedUnknown = true;
      onunconfirmed(true);
      if (operation.kind === 'grant') {
        const result = await grants.commitGrant(operation.operation);
        owner.assertCurrent(token);
        snapshot = result.snapshot;
        shownToken = result.token;
        shownTokenExpiry = result.expiresAt;
        shownTokenGrantId = result.grantId;
        status = m.ownerAgentGrantCreated();
      } else if (operation.kind === 'capability') {
        const result = await grants.commitCapability(operation.operation);
        owner.assertCurrent(token);
        snapshot = result.snapshot;
        const currentGrant = result.snapshot.grants.find(
          (grant) => grant.grant_id === result.grantId,
        );
        status =
          currentGrant?.capability.state === 'active'
            ? m.ownerAgentCapabilityCreated({
                expires: new Date(result.expiresAt * 1000).toLocaleString(),
              })
            : m.ownerAgentCapabilityTargetChanged();
      } else {
        snapshot = await grants.revoke(operation.operation);
        owner.assertCurrent(token);
        status = m.ownerAgentGrantRevoked();
      }
      pending = null;
      submittedUnknown = false;
      onunconfirmed(false);
      const currentTokenGrant = snapshot?.grants.find(
        (grant) => grant.grant_id === shownTokenGrantId,
      );
      if (
        shownToken &&
        (!currentTokenGrant?.active || currentTokenGrant.expires_at * 1000 <= Date.now())
      ) {
        shownToken = null;
        shownTokenGrantId = '';
      }
      grantConsent = false;
      capabilityConsent = '';
      renderClock = Date.now();
      await onchanged();
    } catch (error) {
      if (error instanceof OwnerAgentGrantError && error.definitelyRejected) {
        pending = null;
        submittedUnknown = false;
        shownToken = null;
        onunconfirmed(false);
        try {
          snapshot = await grants.load();
          renderClock = Date.now();
        } catch {
          snapshot = null;
        }
      } else if (!submittedUnknown) {
        pending = null;
        onunconfirmed(false);
      }
      status =
        error instanceof OwnerAgentGrantError && error.definitelyRejected
          ? m.ownerAgentGrantRejected()
          : failure(error);
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () => document.getElementById('owner-agent-grants-retry'));
    }
  }

  async function issue() {
    if (!snapshot || !canPrepare) return;
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
      if (hasDrafts()) throw new Error('owner_unsaved_changes');
      const operation = await grants.prepareGrant(snapshot, sourceId, {
        delegate,
        provider,
        operations: includePropose
          ? ['list', 'search', 'read', 'propose']
          : ['list', 'search', 'read'],
        expiresAt: Math.floor(Date.now() / 1000) + grantLifetime,
      });
      owner.assertCurrent(token);
      if (hasDrafts()) throw new Error('owner_unsaved_changes');
      const prepared: PendingOperation = { kind: 'grant', operation, sourceId };
      pending = prepared;
      status = '';
      await send(prepared);
    } catch (error) {
      status = failure(error);
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () => document.getElementById('owner-agent-grants-issue'));
    }
  }

  async function allowCapability(grant: OwnerAgentGrantRecord) {
    if (!snapshot || !canPrepare || capabilityConsent !== grant.grant_id) return;
    if (hasDrafts()) {
      status = m.productUnsavedChanges();
      return;
    }
    const target = snapshot.sources.owner_note.target;
    if (
      target.deleted &&
      !window.confirm(m.ownerAgentCapabilityDeletedConfirm({ revision: target.revision }))
    )
      return;
    if (target.revision === 0 && !window.confirm(m.ownerAgentCapabilityEmptyConfirm())) return;
    const focus = document.activeElement;
    loading = true;
    onbusy(true);
    try {
      const token = owner.checkpoint();
      await owner.verifyAuthority();
      owner.assertCurrent(token);
      if (hasDrafts()) throw new Error('owner_unsaved_changes');
      const operation = await grants.prepareCapability(snapshot, grant.grant_id);
      owner.assertCurrent(token);
      if (hasDrafts()) throw new Error('owner_unsaved_changes');
      const prepared: PendingOperation = {
        kind: 'capability',
        operation,
        grantId: grant.grant_id,
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
        await restoreActionFocus(focus, () => document.getElementById('owner-agent-grants-status'));
    }
  }

  async function revoke(grant: OwnerAgentGrantRecord) {
    if (!snapshot || !canPrepare) return;
    if (
      !window.confirm(
        m.ownerAgentGrantRevokeConfirm({ delegate: grant.delegate, provider: grant.provider }),
      )
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
      if (hasDrafts()) throw new Error('owner_unsaved_changes');
      const operation = await grants.prepareRevoke(snapshot, grant.grant_id);
      owner.assertCurrent(token);
      if (hasDrafts()) throw new Error('owner_unsaved_changes');
      const prepared: PendingOperation = { kind: 'revoke', operation, grantId: grant.grant_id };
      pending = prepared;
      status = '';
      await send(prepared);
    } catch (error) {
      status = failure(error);
    } finally {
      loading = false;
      onbusy(false);
      if (!owner.scope.signal.aborted)
        await restoreActionFocus(focus, () => document.getElementById('owner-agent-grants-status'));
    }
  }

  async function copyToken() {
    if (!shownToken) return;
    try {
      await navigator.clipboard.writeText(shownToken);
      status = m.ownerAgentGrantTokenCopied();
    } catch {
      status = m.ownerAgentGrantCopyUnavailable();
    }
  }

  function toggle(event: Event) {
    expanded = (event.currentTarget as HTMLDetailsElement).open;
    if (expanded && !snapshot && !loading) void load();
    if (!expanded && !pending) {
      snapshot = null;
      shownToken = null;
      shownTokenGrantId = '';
      grantConsent = false;
      capabilityConsent = '';
      status = '';
    }
  }

  onMount(() => {
    const clear = () => {
      snapshot = null;
      pending = null;
      shownToken = null;
      grantConsent = false;
      capabilityConsent = '';
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

<details id="owner-agent-grants" aria-busy={loading} ontoggle={toggle}>
  <summary>{m.ownerAgentGrantsHeading()}</summary>
  <p>{m.ownerAgentGrantsIntro()}</p>
  <div class="product-actions">
    <button
      id="owner-agent-grants-refresh"
      disabled={disabled || loading || pending !== null}
      onclick={load}>{m.ownerAgentGrantsRefresh()}</button
    >
  </div>
  {#if snapshot}
    {@const selectedSource = snapshot.sources[sourceId]}
    <section aria-labelledby="owner-agent-grants-recipient-heading">
      <h3 id="owner-agent-grants-recipient-heading">{m.ownerAgentGrantsRecipient()}</h3>
      <p>{m.ownerAgentGrantsResource({ resource: snapshot.recipient.resource })}</p>
      <p>{m.ownerAgentGrantsKey({ key: snapshot.recipient.key_id })}</p>
      {#if !snapshot.recipient.enabled}<p>{m.ownerAgentGrantRecipientDisabled()}</p>{/if}
    </section>
    <section aria-labelledby="owner-agent-grants-preview-heading">
      <h3 id="owner-agent-grants-preview-heading">{m.ownerAgentGrantPreview()}</h3>
      <label for="owner-agent-grants-source">{m.ownerAgentGrantSelectRecord()}</label>
      <select
        id="owner-agent-grants-source"
        disabled={disabled || loading || pending !== null}
        bind:value={sourceId}
      >
        {#each ['name', 'owner_note'] as source (source)}
          <option
            value={source}
            disabled={!snapshot.sources[source as 'name' | 'owner_note'].available}
            >{source === 'name' ? m.ownerAgentGrantName() : m.ownerAgentGrantOwnerNote()}</option
          >
        {/each}
      </select>
      <p>{m.ownerAgentGrantRevision({ revision: selectedSource.revision })}</p>
      {#if selectedSource.deleted}
        <p>{m.ownerAgentGrantDeletedSource({ revision: selectedSource.revision })}</p>
      {:else if selectedSource.available && selectedSource.id === 'name'}
        <p>{selectedSource.text}</p>
      {:else if selectedSource.available && selectedSource.note}
        <p><strong>{selectedSource.note.title}</strong></p>
        <p>{selectedSource.note.text}</p>
        <p>{m.ownerAgentGrantProvenance({ provenance: selectedSource.note.provenance.kind })}</p>
      {:else}
        <p>{m.ownerAgentGrantUnavailableSource()}</p>
      {/if}
      <label for="owner-agent-grants-delegate">{m.ownerAgentGrantDelegate()}</label>
      <input
        id="owner-agent-grants-delegate"
        maxlength="80"
        autocomplete="off"
        disabled={disabled || loading || pending !== null}
        bind:value={delegate}
      />
      <p>{m.ownerAgentGrantSelfAssertedLabel()}</p>
      <label for="owner-agent-grants-provider">{m.ownerAgentGrantProvider()}</label>
      <input
        id="owner-agent-grants-provider"
        maxlength="160"
        autocomplete="off"
        disabled={disabled || loading || pending !== null}
        bind:value={provider}
      />
      <p>{m.ownerAgentGrantSelfAssertedLabel()}</p>
      <fieldset disabled={disabled || loading || pending !== null}>
        <legend>{m.ownerAgentGrantPermissions()}</legend>
        <p>{m.ownerAgentGrantBasePermissions()}</p>
        <label>
          <input
            id="owner-agent-grants-propose-permission"
            type="checkbox"
            bind:checked={includePropose}
          />
          {m.ownerAgentGrantProposePermission()}
        </label>
        <p>{m.ownerAgentGrantNoExecute()}</p>
      </fieldset>
      <label for="owner-agent-grants-lifetime">{m.ownerAgentGrantLifetime()}</label>
      <select
        id="owner-agent-grants-lifetime"
        bind:value={grantLifetime}
        disabled={disabled || loading || pending !== null}
      >
        <option value={3600}>{m.ownerAgentGrantOneHour()}</option>
        <option value={86400}>{m.ownerAgentGrantOneDay()}</option>
      </select>
      {#if selectedSource.available && snapshot.recipient.enabled}
        <p>
          {m.ownerAgentGrantWillExpire({
            expires: new Date(Date.now() + grantLifetime * 1000).toLocaleString(),
          })}
        </p>
      {/if}
      <p>{m.ownerAgentGrantCopiesCannotBeRecalled()}</p>
      <label>
        <input
          id="owner-agent-grants-consent"
          type="checkbox"
          disabled={disabled || loading || pending !== null}
          bind:checked={grantConsent}
        />
        {m.ownerAgentGrantConsent()}
      </label>
      <button
        id="owner-agent-grants-issue"
        class="product-primary"
        disabled={!canPrepare ||
          !snapshot.recipient.enabled ||
          !selectedSource.available ||
          !delegate.trim() ||
          !provider.trim() ||
          !grantConsent}
        onclick={issue}>{m.ownerAgentGrantIssue()}</button
      >
    </section>
    {#if shownToken}
      <section aria-labelledby="owner-agent-grant-token-heading" aria-live="polite">
        <h3 id="owner-agent-grant-token-heading">{m.ownerAgentGrantTokenHeading()}</h3>
        <p>{m.ownerAgentGrantTokenWarning()}</p>
        <p>
          {m.ownerAgentGrantTokenExpires({
            expires: new Date(shownTokenExpiry * 1000).toLocaleString(),
          })}
        </p>
        <code id="owner-agent-grant-token">{shownToken}</code>
        <div class="product-actions">
          <button id="owner-agent-grant-token-copy" onclick={copyToken}
            >{m.ownerAgentGrantCopyToken()}</button
          >
          <button id="owner-agent-grant-token-dismiss" onclick={() => (shownToken = null)}
            >{m.ownerAgentGrantTokenDone()}</button
          >
        </div>
      </section>
    {/if}
    {#if snapshot.grants.length === 0}
      <p>{m.ownerAgentGrantEmpty()}</p>
    {:else}
      <section aria-labelledby="owner-agent-grant-list-heading">
        <h3 id="owner-agent-grant-list-heading">{m.ownerAgentGrantListHeading()}</h3>
        {#each snapshot.grants as grant (grant.grant_id)}
          <article id={`owner-agent-grant-${grant.grant_id}`}>
            <h4>{grant.delegate} · {grant.provider}</h4>
            <p>{m.ownerAgentGrantsResource({ resource: grant.resource })}</p>
            <p>{m.ownerAgentGrantPermissionsValue({ permissions: grant.operations.join(', ') })}</p>
            <p>{m.ownerAgentGrantDocuments({ documents: grant.document_ids.join(', ') })}</p>
            <p>
              {grantIsLive(grant)
                ? m.ownerAgentGrantActive({
                    expires: new Date(grant.expires_at * 1000).toLocaleString(),
                  })
                : m.ownerAgentGrantInactive()}
            </p>
            {#if grant.active}
              <div class="owner-agent-capability">
                <h5>{m.ownerAgentCapabilityHeading()}</h5>
                {#if !grant.operations.includes('propose')}
                  <p>{m.ownerAgentCapabilityRequiresProposal()}</p>
                {:else if capabilityIsLive(grant) && grant.capability.expires_at}
                  <p>
                    {m.ownerAgentCapabilityCreated({
                      expires: new Date(grant.capability.expires_at * 1000).toLocaleString(),
                    })}
                  </p>
                {:else if grant.capability.state === 'active'}
                  <p>{m.ownerAgentCapabilityStale()}</p>
                {:else if grant.capability.state === 'stale'}
                  <p>{m.ownerAgentCapabilityStale()}</p>
                {:else}
                  <p>{m.ownerAgentCapabilityUnknown()}</p>
                {/if}
                {#if grantIsLive(grant) && grant.operations.includes('propose') && grant.capability.state === 'unknown'}
                  <label>
                    <input
                      id={`owner-agent-capability-consent-${grant.grant_id}`}
                      type="checkbox"
                      disabled={disabled || loading || pending !== null}
                      checked={capabilityConsent === grant.grant_id}
                      onchange={(event) =>
                        (capabilityConsent = event.currentTarget.checked ? grant.grant_id : '')}
                    />
                    {m.ownerAgentCapabilityConsent({
                      revision: snapshot.sources.owner_note.revision,
                    })}
                  </label>
                  <button
                    id={`owner-agent-capability-allow-${grant.grant_id}`}
                    disabled={!canPrepare || capabilityConsent !== grant.grant_id}
                    onclick={() => allowCapability(grant)}>{m.ownerAgentCapabilityAllow()}</button
                  >
                {/if}
              </div>
              <button
                id={`owner-agent-grant-revoke-${grant.grant_id}`}
                class="product-danger"
                disabled={!canPrepare}
                onclick={() => revoke(grant)}>{m.ownerAgentGrantRevoke()}</button
              >
            {:else}
              <p>{m.ownerAgentGrantHistoricalRevokeOnly()}</p>
            {/if}
          </article>
        {/each}
      </section>
    {/if}
  {/if}
  {#if pending}
    <button
      id="owner-agent-grants-retry"
      disabled={disabled || loading}
      onclick={() => send(pending!)}>{m.ownerAgentGrantsRetry()}</button
    >
  {/if}
  <p id="owner-agent-grants-status" role="status" aria-live="polite">{status}</p>
</details>
