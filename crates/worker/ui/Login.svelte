<script lang="ts">
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import type { Locale } from './paraglide/runtime.js';

  let {
    tx,
    challenge,
    rpId,
    client,
    locale,
  }: {
    tx: string;
    challenge: string;
    rpId: string;
    client: string;
    locale: Locale;
  } = $props();
  let busy = $state(false);
  let failed = $state(false);

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

  async function authenticate(): Promise<void> {
    if (busy) return;
    busy = true;
    failed = false;
    try {
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: decode(challenge),
          rpId,
          userVerification: 'required',
          timeout: 120000,
        },
      });
      if (
        !(credential instanceof PublicKeyCredential) ||
        !(credential.response instanceof AuthenticatorAssertionResponse)
      ) {
        throw new Error('cancelled');
      }
      const response = {
        id: credential.id,
        client_data: encode(credential.response.clientDataJSON),
        authenticator_data: encode(credential.response.authenticatorData),
        signature: encode(credential.response.signature),
        user_handle: credential.response.userHandle ? encode(credential.response.userHandle) : null,
      };
      const result = await fetch('/login/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tx, consent: true, response }),
      });
      if (!result.ok) throw new Error('rejected');
      const body: unknown = await result.json();
      if (
        typeof body !== 'object' ||
        body === null ||
        !('location' in body) ||
        typeof body.location !== 'string'
      ) {
        throw new Error('invalid response');
      }
      location.assign(body.location);
    } catch {
      failed = true;
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
  <h1>{m.login()}</h1>
  <p>{m.app()}: <strong>{client}</strong></p>
  <p>{m.loginConsentDescription()}</p>
  <button id="passkey" type="button" disabled={busy} onclick={authenticate}
    >{m.loginAuthorize()}</button
  >
  {#if failed}<p id="error" role="alert">{m.error()}</p>{/if}
</main>
