<script lang="ts">
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import type { Locale } from './paraglide/runtime.js';

  let {
    tx,
    challenge,
    rpId,
    client,
    enrollment,
    locale,
  }: {
    tx: string;
    challenge: string;
    rpId: string;
    client: string;
    enrollment: boolean;
    locale: Locale;
  } = $props();
  let busy = $state(false);
  let errorKind = $state<'required' | 'operation' | null>(null);
  let invitation = $state('');

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
    errorKind = null;
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
      errorKind = 'operation';
      busy = false;
    }
  }

  async function register(): Promise<void> {
    if (busy) return;
    if (!invitation.trim()) {
      errorKind = 'required';
      return;
    }
    busy = true;
    errorKind = null;
    try {
      const started = await fetch('/register/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tx, invitation }),
      });
      if (!started.ok) throw new Error('invalid invitation');
      const options: unknown = await started.json();
      if (
        typeof options !== 'object' ||
        options === null ||
        !('challenge' in options) ||
        typeof options.challenge !== 'string' ||
        !('user_handle' in options) ||
        typeof options.user_handle !== 'string' ||
        !('rp_id' in options) ||
        typeof options.rp_id !== 'string'
      )
        throw new Error('invalid registration options');
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: decode(options.challenge),
          rp: { id: options.rp_id, name: 'mikaki' },
          user: { id: decode(options.user_handle), name: 'mikaki account', displayName: 'mikaki' },
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
          attestation: 'none',
          timeout: 120000,
          extensions: { credProps: true, prf: {} },
        },
      });
      if (
        !(credential instanceof PublicKeyCredential) ||
        !(credential.response instanceof AuthenticatorAttestationResponse) ||
        credential.getClientExtensionResults().credProps?.rk !== true
      )
        throw new Error('discoverable passkey required');
      const result = await fetch('/register/finish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tx,
          consent: true,
          response: {
            id: credential.id,
            client_data: encode(credential.response.clientDataJSON),
            attestation: encode(credential.response.attestationObject),
          },
        }),
      });
      if (!result.ok) throw new Error('registration failed');
      const body: unknown = await result.json();
      if (
        typeof body !== 'object' ||
        body === null ||
        !('location' in body) ||
        typeof body.location !== 'string'
      )
        throw new Error('invalid response');
      invitation = '';
      location.assign(body.location);
    } catch {
      errorKind = 'operation';
      busy = false;
    }
  }
</script>

<div class="auth-shell">
  <header class="auth-header">
    <div class="auth-brand" aria-label="mikaki">
      <span class="auth-mark" aria-hidden="true"
        ><span></span><span></span><span></span><span></span></span
      >
      mikaki
    </div>
    <label class="auth-language">
      <span>{m.language()}</span>
      <select
        aria-label={m.language()}
        value={locale}
        onchange={(event) => switchLocale(event.currentTarget.value)}
      >
        <option value="ja">日本語</option>
        <option value="en">English</option>
      </select>
    </label>
  </header>
  <main class="auth-layout">
    <section class="auth-intro" aria-labelledby="auth-title">
      <p class="auth-kicker">{m.authKicker()}</p>
      <h1 id="auth-title">{m.authHeroHeadingFirst()}<br />{m.authHeroHeadingSecond()}</h1>
      <p>{m.authHeroDescription()}</p>
    </section>
    <section class="auth-card" aria-labelledby="auth-action-title">
      {#if enrollment}
        <h2 id="auth-action-title">{m.enrollHeading()}</h2>
        <p class="auth-card-lead" id="invite-help">{m.authInviteHelp()}</p>
      {:else}
        <h2 id="auth-action-title">{m.login()}</h2>
        <p class="auth-card-lead">{m.authCheckApp()}</p>
        <div class="auth-client">
          <span class="auth-client-label">{m.app()}</span>
          <strong class="auth-client-name">{client}</strong>
        </div>
        <p class="auth-description">{m.loginConsentDescription()}</p>
        <button
          class="auth-primary"
          id="passkey"
          type="button"
          disabled={busy}
          onclick={authenticate}>{busy ? m.busy() : m.loginAuthorize()}</button
        >
        <hr class="auth-divider" />
        <h3 class="auth-subheading">{m.authRegisterHeading()}</h3>
        <p class="auth-field-help" id="invite-help">{m.authInviteHelp()}</p>
      {/if}
      <label class="auth-field" for="invitation">
        {m.invite()}
        <input
          id="invitation"
          type="text"
          autocomplete="off"
          spellcheck="false"
          aria-describedby={errorKind === 'required' ? 'invite-help invite-error' : 'invite-help'}
          aria-invalid={errorKind === 'required'}
          oninput={() => {
            if (errorKind === 'required') errorKind = null;
          }}
          bind:value={invitation}
        />
      </label>
      {#if errorKind === 'required'}<p class="auth-field-error" id="invite-error" role="alert">
          {m.inviteRequired()}
        </p>{/if}
      <button class="auth-secondary" id="register" type="button" disabled={busy} onclick={register}
        >{busy ? m.busy() : m.register()}</button
      >
      <p class="auth-note">{m.recovery()}</p>
      {#if errorKind === 'operation'}<p class="auth-alert" id="error" role="alert">
          {m.error()}
        </p>{/if}
    </section>
  </main>
  <footer class="auth-footer">mikaki</footer>
</div>
