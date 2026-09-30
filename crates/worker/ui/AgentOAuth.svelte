<script lang="ts">
  import { vaultScope } from './vault-context.js';
  const scope = vaultScope();
  const fetch = scope.request;
  import { onMount } from 'svelte';
  import * as m from './paraglide/messages.js';
  let {
    grants,
  }: {
    grants: {
      grant_id: string;
      delegate: string;
      provider: string;
      active: number;
      operations: string;
      source_revision: number;
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
          document_id: 'name';
          source_revision: number;
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
  let selected = $state(''),
    consent = $state(false);
  const choices = $derived(
    grants.filter(
      (g) =>
        g.active &&
        (review?.authorization_details === null ||
          g.source_revision === review?.authorization_details?.[0]?.source_revision) &&
        review?.scopes.every((s) => {
          try {
            return (JSON.parse(g.operations) as unknown[]).includes(s);
          } catch {
            return false;
          }
        }),
    ),
  );
  function valid(raw: unknown): raw is Review {
    if (typeof raw !== 'object' || raw === null) return false;
    const v = raw as Partial<Review>;
    return (
      v.request_id === requestId &&
      typeof v.client_id === 'string' &&
      typeof v.client_name === 'string' &&
      typeof v.redirect_uri === 'string' &&
      typeof v.resource === 'string' &&
      Number.isSafeInteger(v.expires_at) &&
      Array.isArray(v.scopes) &&
      v.scopes.length > 0 &&
      v.scopes.every((s) => ['list', 'search', 'read', 'propose', 'execute'].includes(s)) &&
      (v.authorization_details === null ||
        (Array.isArray(v.authorization_details) &&
          v.authorization_details.length === 1 &&
          v.authorization_details[0]?.type === 'mikaki_agent_snapshot' &&
          v.authorization_details[0]?.document_id === 'name' &&
          v.authorization_details[0]?.locations?.[0] === v.resource &&
          Number.isSafeInteger(v.authorization_details[0]?.source_revision) &&
          (v.authorization_details[0]?.source_revision ?? 0) > 0 &&
          typeof v.authorization_details[0]?.purpose === 'string' &&
          v.authorization_details[0].purpose.length > 0))
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
        <p>{m.agentOAuthSourceRevision()} {review.authorization_details[0].source_revision}</p>
      {/if}
      <p>{m.agentOAuthDisclosure()}</p>
      <label
        >{m.agentOAuthGrant()}<select bind:value={selected} disabled={busy}>
          <option value="">{m.agentOAuthChoose()}</option>
          {#each choices as grant (grant.grant_id)}
            <option value={grant.grant_id}
              >{grant.delegate} · {grant.provider} · {grant.grant_id}</option
            >
          {/each}
        </select></label
      >
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
