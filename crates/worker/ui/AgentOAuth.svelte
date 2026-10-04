<script lang="ts">
  import { vaultScope } from './vault-context.js';
  const scope = vaultScope();
  const fetch = scope.request;
  import { onMount } from 'svelte';
  import * as m from './paraglide/messages.js';
  import {
    equalVaultSource,
    parseVaultRecordAuthority,
    parseVaultRecordSource,
    type VaultRecordAuthority,
    type VaultRecordSource,
  } from './vault-record-source.js';
  let {
    grants,
    onBusy = () => {},
  }: {
    onBusy?: (busy: boolean) => void;
    grants: {
      grant_id: string;
      delegate: string;
      provider: string;
      active: number;
      operations: string;
      source_revision: number;
      storage_version: number;
      resource: string;
      account_id: string;
      source_origin: string | null;
      source_vault_id: string | null;
      source_collection_id: string | null;
      source_record_id: string | null;
      source_kind: string | null;
      source_ciphertext_sha256: string | null;
      source_key_generation: number | null;
      source_owner_key_revision: number | null;
    }[];
  } = $props();
  type Review = {
    request_id: string;
    client_id: string;
    client_name: string;
    redirect_uri: string;
    resource: string;
    scopes: string[];
    authorization_details:
      | {
          type: 'mikaki_agent_snapshot';
          locations: [string];
          actions: string[];
          document_id: 'name' | 'owner_note';
          storage_version: 2;
          source: VaultRecordSource;
          authority: VaultRecordAuthority;
          purpose: string;
        }[]
      | null;
    expires_at: number;
  };
  const ids = new URL(location.href).searchParams.getAll('agent_oauth_request');
  const requestId = ids.length === 1 && /^[A-Za-z0-9_-]{43}$/.test(ids[0] ?? '') ? ids[0] : null;
  let review: Review | null = $state(null),
    busy = $state(false),
    failed = $state(false);
  $effect(() => {
    onBusy(busy);
    return () => onBusy(false);
  });
  let selected = $state(''),
    consent = $state(false);
  const choices = $derived.by(() => {
    if (!review) return [];
    const request = review;
    return grants.flatMap((g) => {
      try {
        if (!g.active || g.storage_version !== 2 || g.resource !== request.resource) return [];
        const source = parseVaultRecordSource({
          storage_version: 2,
          origin: g.source_origin,
          owner_id: g.account_id,
          vault_id: g.source_vault_id,
          collection_id: g.source_collection_id,
          record_id: g.source_record_id,
          kind: g.source_kind,
          revision: g.source_revision,
          ciphertext_sha256: g.source_ciphertext_sha256,
        });
        const authority = parseVaultRecordAuthority({
          key_generation: g.source_key_generation,
          owner_key_revision: g.source_owner_key_revision,
        });
        const detail = request.authorization_details?.[0];
        if (
          detail &&
          (!equalVaultSource(source, detail.source) ||
            authority.key_generation !== detail.authority.key_generation ||
            authority.owner_key_revision !== detail.authority.owner_key_revision)
        )
          return [];
        const operations: unknown = JSON.parse(g.operations);
        if (!Array.isArray(operations) || !request.scopes.every((s) => operations.includes(s)))
          return [];
        return [{ ...g, source, authority }];
      } catch {
        return [];
      }
    });
  });
  function valid(raw: unknown): raw is Review {
    if (typeof raw !== 'object' || raw === null) return false;
    const v = raw as Partial<Review>;
    try {
      const detail = v.authorization_details?.[0];
      if (v.authorization_details !== null) {
        if (
          !Array.isArray(v.authorization_details) ||
          v.authorization_details.length !== 1 ||
          !detail ||
          Object.keys(detail).length !== 8 ||
          detail.type !== 'mikaki_agent_snapshot' ||
          detail.storage_version !== 2 ||
          detail.document_id !== parseVaultRecordSource(detail.source).record_id ||
          !Array.isArray(detail.locations) ||
          detail.locations.length !== 1 ||
          detail.locations[0] !== v.resource ||
          !Array.isArray(detail.actions) ||
          !Array.isArray(v.scopes) ||
          detail.actions.length !== v.scopes.length ||
          new Set(detail.actions).size !== detail.actions.length ||
          !detail.actions.every((action) => v.scopes?.includes(action)) ||
          typeof detail.purpose !== 'string' ||
          !detail.purpose.trim() ||
          detail.purpose.length > 160
        )
          return false;
        parseVaultRecordAuthority(detail.authority);
      }
    } catch {
      return false;
    }
    return (
      v.request_id === requestId &&
      typeof v.client_id === 'string' &&
      typeof v.client_name === 'string' &&
      typeof v.redirect_uri === 'string' &&
      typeof v.resource === 'string' &&
      Number.isSafeInteger(v.expires_at) &&
      Array.isArray(v.scopes) &&
      v.scopes.length > 0 &&
      v.scopes.every((s) => ['list', 'search', 'read', 'propose', 'execute'].includes(s))
    );
  }
  async function load() {
    if (!requestId) return;
    busy = true;
    failed = false;
    try {
      const response = await fetch('/vault/agents/oauth-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_id: requestId }),
      });
      const value: unknown = await response.json();
      if (!response.ok || !valid(value)) throw new Error();
      review = value;
    } catch {
      failed = true;
      review = null;
    } finally {
      busy = false;
    }
  }
  async function decide(approve: boolean) {
    if (busy || !review || (approve && (!consent || !choices.some((g) => g.grant_id === selected))))
      return;
    busy = true;
    try {
      const response = await fetch('/vault/agents/oauth-decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          request_id: review.request_id,
          grant_id: approve ? selected : null,
          approve,
        }),
      });
      const body = (await response.json()) as { redirect?: unknown };
      if (!response.ok || typeof body.redirect !== 'string') throw new Error();
      const target = new URL(body.redirect),
        expected = new URL(review.redirect_uri);
      if (
        target.origin !== expected.origin ||
        target.pathname !== expected.pathname ||
        target.hash ||
        !(
          target.protocol === 'https:' ||
          (target.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(target.hostname))
        )
      )
        throw new Error();
      await scope.ensure();
      location.assign(target.href);
    } catch {
      failed = true;
      consent = false;
    } finally {
      busy = false;
    }
  }
  onMount(() => {
    void load();
  });
</script>

{#if ids.length > 0}
  <section aria-label={m.agentOAuthHeading()}>
    <h3>{m.agentOAuthHeading()}</h3>
    {#if review}
      <p>{review.client_name} · {review.client_id}</p>
      <p>{m.agentOAuthResource()} {review.resource}</p>
      <p>{m.agentOAuthCallback()} {review.redirect_uri}</p>
      <p>{m.agentOAuthScopes()} {review.scopes.join(', ')}</p>
      {#if review.authorization_details}
        <p>{m.agentOAuthPurpose()} {review.authorization_details[0].purpose}</p>
        <p>{m.agentOAuthSourceRevision()} {review.authorization_details[0].source.revision}</p>
      {/if}
      <p>{m.agentOAuthDisclosure()}</p>
      <label
        >{m.agentOAuthGrant()}<select
          bind:value={selected}
          disabled={busy}
          onchange={() => (consent = false)}
        >
          <option value="">{m.agentOAuthChoose()}</option>
          {#each choices as grant (grant.grant_id)}
            <option value={grant.grant_id}
              >{grant.source.kind === 'name' ? m.vaultName() : m.vaultNoteHeading()} ·
              {m.agentSnapshotRevision({ revision: String(grant.source.revision) })} ·
              {grant.delegate} · {grant.provider} · {grant.grant_id}</option
            >
          {/each}
        </select></label
      >
      {#each choices.filter((grant) => grant.grant_id === selected) as grant (grant.grant_id)}
        <p>
          {m.agentOAuthSource()}
          {grant.source.origin} · {grant.source.vault_id} · {grant.source.collection_id}/{grant
            .source.record_id}
        </p>
        <p>{m.agentOAuthOwner()} {grant.source.owner_id}</p>
        <p>{m.agentSnapshotRevision({ revision: String(grant.source.revision) })}</p>
        <p>
          {m.agentOAuthAuthority({
            generation: String(grant.authority.key_generation),
            revision: String(grant.authority.owner_key_revision),
          })}
        </p>
      {/each}
      {#if choices.length === 0}<p>{m.agentOAuthNoGrant()}</p>{/if}
      <label
        ><input
          type="checkbox"
          bind:checked={consent}
          disabled={busy}
        />{m.agentOAuthConsent()}</label
      >
      <button
        class="product-primary"
        type="button"
        disabled={busy || !consent || !choices.some((g) => g.grant_id === selected)}
        onclick={() => decide(true)}>{m.agentOAuthAllow()}</button
      >
      <button class="product-danger" type="button" disabled={busy} onclick={() => decide(false)}
        >{m.agentReject()}</button
      >
    {/if}
    {#if failed || !requestId}<p role="status">{m.agentOAuthFailed()}</p>{/if}
    <button type="button" disabled={busy} onclick={load}>{m.agentRefresh()}</button>
  </section>
{/if}
