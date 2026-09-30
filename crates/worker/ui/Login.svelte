<script lang="ts">
  import BrandMark from './BrandMark.svelte';
  import { publishVaultLock } from './session-events.js';
  import { onMount } from 'svelte';
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import SessionCue from './SessionCue.svelte';
  import LivingSeal from './LivingSeal.svelte';
  import type { Locale } from './paraglide/runtime.js';

  let {
    tx,
    challenge,
    rpId,
    rpUri,
    client,
    enrollment,
    ownerLogin,
    locale,
  }: {
    tx: string;
    challenge: string;
    rpId: string;
    rpUri: string;
    client: string;
    enrollment: boolean;
    ownerLogin: boolean;
    locale: Locale;
  } = $props();
  let busy = $state(false);
  let sealSeed = $state('');
  let passkeyPending = $state(false);
  let errorKind = $state<'required' | 'operation' | null>(null);
  let invitation = $state('');
  let authentication: AbortController | null = null;

  onMount(() => {
    if (!enrollment && typeof PublicKeyCredential !== 'undefined') void authenticate(true);
    return () => authentication?.abort();
  });

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

  async function authenticate(automatic = false): Promise<void> {
    if (busy) return;
    if (automatic && authentication) return;
    authentication?.abort();
    const controller = new AbortController();
    authentication = controller;
    passkeyPending = true;
    if (!automatic) busy = true;
    errorKind = null;
    try {
      const credential = await navigator.credentials.get({
        signal: controller.signal,
        publicKey: {
          challenge: decode(challenge),
          rpId,
          userVerification: 'required',
          timeout: 120000,
        },
      });
      if (authentication !== controller) return;
      passkeyPending = false;
      busy = true;
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
      publishVaultLock();
      location.assign(body.location);
    } catch {
      if (authentication !== controller) return;
      passkeyPending = false;
      authentication = null;
      if (!automatic && !controller.signal.aborted) errorKind = 'operation';
      busy = false;
    }
  }

  async function deny(): Promise<void> {
    if (busy || enrollment || ownerLogin) return;
    authentication?.abort();
    authentication = null;
    passkeyPending = false;
    busy = true;
    errorKind = null;
    try {
      const result = await fetch('/login/deny', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tx }),
      });
      if (!result.ok) throw new Error('rejected');
      const body: unknown = await result.json();
      if (
        typeof body !== 'object' ||
        body === null ||
        !('location' in body) ||
        typeof body.location !== 'string'
      )
        throw new Error('invalid response');
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
    authentication?.abort();
    authentication = null;
    passkeyPending = false;
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
      publishVaultLock();
      location.assign(body.location);
    } catch {
      errorKind = 'operation';
      busy = false;
    }
  }
</script>

<div class="auth-shell">
  <section class="auth-story" aria-labelledby="auth-title">
    <header class="auth-header">
      <div class="auth-brand" aria-label="mikaki">
        <BrandMark />
        mikaki
      </div>
      <span class="auth-header-tag" aria-hidden="true">IDENTITY</span>
    </header>
    <div class="auth-intro">
      <p class="auth-kicker">
        <span class="auth-kicker-line" aria-hidden="true"></span>{m.authKicker()}
      </p>
      <h1 id="auth-title">{m.authHeroHeadingFirst()}<br />{m.authHeroHeadingSecond()}</h1>
      <p class="auth-hero-description">{m.authHeroDescription()}</p>
      <SessionCue
        seed={tx}
        cueUrl={`/login/cue?tx=${encodeURIComponent(tx)}`}
        pageUri={location.href}
        {rpUri}
        pageLabel={m.authOriginLabel()}
        rpLabel={m.authRpOriginLabel()}
        hint={m.authOriginHint()}
        onSeed={(value) => {
          if (!busy && !passkeyPending) sealSeed = value;
        }}
      />
    </div>
    <LivingSeal
      seed={sealSeed || tx}
      pageOrigin={location.origin}
      rpOrigin={new URL(rpUri).origin}
      paused={busy || passkeyPending}
    />
    <p class="auth-story-footer">MIKAKI <span aria-hidden="true">/</span> PASSKEY IDENTITY</p>
  </section>

  <div class="auth-workspace">
    <div class="auth-toolbar">
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
    </div>

    <main class="auth-layout">
      <section class="auth-card" aria-labelledby="auth-action-title">
        <div class="auth-card-overline">
          <span class="auth-card-overline-dot"></span> MIKAKI ACCOUNT
        </div>
        {#if enrollment}
          <h2 id="auth-action-title">{m.enrollHeading()}</h2>
          <p class="auth-card-lead" id="invite-help">{m.authInviteHelp()}</p>
        {:else}
          <h2 id="auth-action-title">{m.login()}</h2>
          <p class="auth-card-lead">{ownerLogin ? m.agentOwnerLoginLead() : m.authCheckApp()}</p>
          <div class="auth-client">
            <span class="auth-client-icon" aria-hidden="true"
              >{client.slice(0, 1).toUpperCase()}</span
            >
            <span class="auth-client-details">
              <span class="auth-client-label">{m.app()}</span>
              <strong class="auth-client-name">{client}</strong>
            </span>
          </div>
          <p class="auth-description">
            {ownerLogin ? m.agentOwnerLoginDescription() : m.loginConsentDescription()}
          </p>
          <button
            class="auth-primary"
            id="passkey"
            type="button"
            disabled={busy}
            onclick={() => authenticate()}
          >
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle cx="9" cy="9" r="4" stroke="currentColor" stroke-width="2" />
              <path
                d="m12 12 8 8m-3-3 2-2"
                stroke="currentColor"
                stroke-width="2"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
            <span
              >{busy ? m.busy() : ownerLogin ? m.agentOwnerLoginAction() : m.loginAuthorize()}</span
            >
            <span class="auth-button-arrow" aria-hidden="true">→</span>
          </button>
          {#if !ownerLogin}
            <button class="auth-secondary" id="deny" type="button" disabled={busy} onclick={deny}>
              <span>{m.loginDeny()}</span><span aria-hidden="true">→</span>
            </button>
          {/if}
          <div class="auth-separator" aria-hidden="true"><span></span><i></i><span></span></div>
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
        <button
          class="auth-secondary"
          id="register"
          type="button"
          disabled={busy}
          onclick={register}
          ><span>{busy ? m.busy() : m.register()}</span><span aria-hidden="true">↗</span></button
        >
        <p class="auth-note">{m.recovery()}</p>
        {#if errorKind === 'operation'}<p class="auth-alert" id="error" role="alert">
            {m.error()}
          </p>{/if}
      </section>
    </main>
    <footer class="auth-footer">© mikaki</footer>
  </div>
</div>
