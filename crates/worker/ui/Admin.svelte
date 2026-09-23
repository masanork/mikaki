<script lang="ts">
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import type { Locale } from './paraglide/runtime.js';

  let { locale }: { locale: Locale } = $props();
  let busy = $state(false);
  let failed = $state(false);
  let invitation = $state('');
  let expiresAt = $state(0);

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

  async function issue(): Promise<void> {
    if (busy) return;
    busy = true;
    failed = false;
    invitation = '';
    try {
      const started = await fetch('/admin/invitations/start', { method: 'POST' });
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

<main>
  <label
    >{m.language()}
    <select
      aria-label={m.language()}
      value={locale}
      onchange={(event) => switchLocale(event.currentTarget.value)}
    >
      <option value="ja">日本語</option>
      <option value="en">English</option>
    </select>
  </label>
  <h1>{m.adminHeading()}</h1>
  <p>{m.adminIntro()}</p>
  <button type="button" disabled={busy} onclick={issue}>{m.adminIssue()}</button>
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
</main>
