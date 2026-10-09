<script lang="ts">
  import { onMount } from 'svelte';
  import * as m from './paraglide/messages.js';
  import ProductHeader from './ProductHeader.svelte';
  import type { Locale } from './paraglide/runtime.js';

  let { locale }: { locale: Locale } = $props();
  let busy = $state(false);
  let failed = $state(false);
  let invitation = $state('');
  let expiresAt = $state(0);
  type Entry = {
    id: string;
    email: string;
    created_at: number;
    expires_at: number | null;
    status: string;
    can_resend: number;
  };
  let entries = $state<Entry[]>([]);
  let loading = $state(true);
  let mailReady = $state(false);
  let message = $state('');
  let nextCursor = $state<string | null>(null);
  onMount(() => {
    void reload();
  });
  async function reload(append = false) {
    loading = true;
    failed = false;
    try {
      const response = await fetch(
        `/admin/waitlist${append && nextCursor ? `?cursor=${encodeURIComponent(nextCursor)}` : ''}`,
      );
      if (!response.ok) throw new Error('List failed');
      const result: unknown = await response.json();
      if (
        typeof result !== 'object' ||
        result === null ||
        !('entries' in result) ||
        !Array.isArray(result.entries) ||
        !('mail_ready' in result) ||
        typeof result.mail_ready !== 'boolean'
      )
        throw new Error('Invalid list');
      if (
        !('next_cursor' in result) ||
        !(result.next_cursor === null || typeof result.next_cursor === 'string')
      )
        throw new Error('Invalid cursor');
      const page = result.entries.map((item: unknown) => {
        if (
          typeof item !== 'object' ||
          item === null ||
          !('id' in item) ||
          typeof item.id !== 'string' ||
          !('email' in item) ||
          typeof item.email !== 'string' ||
          !('created_at' in item) ||
          typeof item.created_at !== 'number' ||
          !('expires_at' in item) ||
          !(item.expires_at === null || typeof item.expires_at === 'number') ||
          !('status' in item) ||
          typeof item.status !== 'string' ||
          !('can_resend' in item) ||
          typeof item.can_resend !== 'number'
        )
          throw new Error('Invalid entry');
        return {
          id: item.id,
          email: item.email,
          created_at: item.created_at,
          expires_at: item.expires_at,
          status: item.status,
          can_resend: item.can_resend,
        };
      });
      entries = append ? [...entries, ...page] : page;
      nextCursor = result.next_cursor;
      mailReady = result.mail_ready;
    } catch {
      failed = true;
    } finally {
      loading = false;
    }
  }
  function status(value: string) {
    switch (value) {
      case 'waiting':
        return m.adminWaiting();
      case 'invited':
        return m.adminInvited();
      case 'registered':
        return m.adminRegistered();
      case 'expired':
        return m.adminExpired();
      case 'failed':
        return m.adminMailFailed();
      default:
        return m.adminSending();
    }
  }

  function decode(value: string): Uint8Array<ArrayBuffer> {
    return Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), (char) =>
      char.charCodeAt(0),
    );
  }

  function encode(value: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(value)))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replaceAll('=', '');
  }

  async function issue(target?: { id: string; action: 'invite' | 'resend' }): Promise<void> {
    if (busy) return;
    busy = true;
    failed = false;
    invitation = '';
    message = '';
    try {
      const started = await fetch(target ? '/admin/waitlist/start' : '/admin/invitations/start', {
        method: 'POST',
        ...(target
          ? {
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ waitlist_id: target.id, action: target.action }),
            }
          : {}),
      });
      if (!started.ok) throw new Error('start failed');
      const options: unknown = await started.json();
      if (
        typeof options !== 'object' ||
        options === null ||
        !('operation_id' in options) ||
        typeof options.operation_id !== 'string' ||
        !('challenge' in options) ||
        typeof options.challenge !== 'string' ||
        !('credential_id' in options) ||
        typeof options.credential_id !== 'string' ||
        !('rp_id' in options) ||
        typeof options.rp_id !== 'string'
      )
        throw new Error('invalid options');
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: decode(options.challenge),
          rpId: options.rp_id,
          allowCredentials: [{ id: decode(options.credential_id), type: 'public-key' }],
          userVerification: 'required',
          timeout: 120000,
        },
      });
      if (
        !(credential instanceof PublicKeyCredential) ||
        !(credential.response instanceof AuthenticatorAssertionResponse)
      )
        throw new Error('passkey required');
      const finished = await fetch('/admin/invitations/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operation_id: options.operation_id,
          response: {
            id: credential.id,
            client_data: encode(credential.response.clientDataJSON),
            authenticator_data: encode(credential.response.authenticatorData),
            signature: encode(credential.response.signature),
            user_handle: credential.response.userHandle
              ? encode(credential.response.userHandle)
              : null,
          },
        }),
      });
      if (!finished.ok) throw new Error('finish failed');
      const result: unknown = await finished.json();
      if (target) {
        if (
          typeof result !== 'object' ||
          result === null ||
          !('waitlist_id' in result) ||
          result.waitlist_id !== target.id ||
          !('delivery' in result) ||
          typeof result.delivery !== 'string'
        )
          throw new Error('Invalid delivery');
        message =
          result.delivery === 'sent'
            ? m.adminMailSent()
            : result.delivery === 'failed'
              ? m.adminMailRetry()
              : m.adminSending();
        await reload();
        return;
      }
      if (
        typeof result !== 'object' ||
        result === null ||
        !('invitation' in result) ||
        typeof result.invitation !== 'string' ||
        !('expires_at' in result) ||
        typeof result.expires_at !== 'number'
      )
        throw new Error('invalid result');
      invitation = result.invitation;
      expiresAt = result.expires_at;
    } catch {
      failed = true;
    } finally {
      busy = false;
    }
  }
</script>

<div class="product-material-shell">
  <ProductHeader {locale} material paused={busy} />
  <main id="product-main" tabindex="-1" class="product-main product-admin">
    <div class="product-heading">
      <h1>{m.adminHeading()}</h1>
      <p>{m.adminWaitlistIntro()}</p>
    </div>
    <section class="product-card" aria-label={m.adminWaitingList()}>
      <h2>{m.adminWaitingList()}</h2>
      <button
        type="button"
        disabled={busy || loading}
        onclick={() => {
          void reload();
        }}>{m.adminRefresh()}</button
      >
      {#if loading}<p role="status">{m.busy()}</p>
      {:else}
        {#if !mailReady}<p role="alert">{m.adminMailUnavailable()}</p>{/if}
        {#if entries.length === 0}<p>{m.adminWaitlistEmpty()}</p>{/if}
        <ul class="waitlist-entries">
          {#each entries as entry (entry.id)}<li>
              <div>
                <strong>{entry.email}</strong>
                <p>{status(entry.status)}</p>
                <time datetime={new Date(entry.created_at * 1000).toISOString()}
                  >{new Intl.DateTimeFormat(locale, {
                    dateStyle: 'medium',
                    timeStyle: 'short',
                  }).format(entry.created_at * 1000)}</time
                >
                {#if entry.expires_at && entry.status !== 'registered'}<p>
                    {m.adminExpires()}: {new Intl.DateTimeFormat(locale, {
                      dateStyle: 'medium',
                      timeStyle: 'short',
                    }).format(entry.expires_at * 1000)}
                  </p>{/if}
              </div>
              {#if entry.status === 'waiting' || entry.status === 'expired'}<button
                  class="product-primary"
                  disabled={busy || !mailReady}
                  onclick={() => issue({ id: entry.id, action: 'invite' })}
                  >{m.adminInviteEmail()}</button
                >
              {:else if entry.status === 'invited' || entry.status === 'failed'}<button
                  disabled={busy || !mailReady || !entry.can_resend}
                  onclick={() => issue({ id: entry.id, action: 'resend' })}
                  >{m.adminResend()}</button
                >{/if}
            </li>{/each}
        </ul>
        {#if nextCursor}<button
            disabled={busy || loading}
            onclick={() => {
              void reload(true);
            }}>{m.adminLoadMore()}</button
          >{/if}
      {/if}
      {#if message}<p role="status">{message}</p>{/if}
      {#if failed}<p role="alert">{m.adminError()}</p>{/if}
    </section>
    <section class="product-card" aria-label={m.adminHeading()}>
      <details>
        <summary>{m.adminManual()}</summary>
        <p>{m.adminIntro()}</p>
        <button class="product-primary" type="button" disabled={busy} onclick={() => issue()}
          >{m.adminIssue()}</button
        >
        {#if failed}<p role="alert">{m.adminError()}</p>{/if}
        {#if invitation}
          <p role="status">{m.adminReady()}</p>
          <p>{m.adminInvitation()}: <code>{invitation}</code></p>
          <p>
            {m.adminExpires()}:
            <time datetime={new Date(expiresAt * 1000).toISOString()}
              >{new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(
                expiresAt * 1000,
              )}</time
            >
          </p>
        {/if}
      </details>
    </section>
  </main>
</div>
