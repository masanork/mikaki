<script lang="ts">
  import { restoreActionFocus } from './action-focus.js';
  import { publishVaultLock } from './session-events.js';
  import { onMount } from 'svelte';
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import WovenGate from './WovenGate.svelte';
  import { weaveProfile } from './woven-gate.js';
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
  const page = new URL(location.href);
  const destination = $derived(new URL(rpUri));
  const pageProfile = weaveProfile(page.origin);
  const rpProfile = $derived(weaveProfile(destination.origin));
  let passkeyPending = $state(false);
  let errorKind = $state<'required' | 'operation' | null>(null);
  let invitation = $state('');
  let registrationOpen = $state(false);
  let authentication: AbortController | null = null;

  onMount(() => {
    registrationOpen = enrollment;
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
    const previousFocus = document.activeElement;
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
      if (!automatic && !controller.signal.aborted)
        await restoreActionFocus(previousFocus, () => document.getElementById('passkey'));
    }
  }

  async function register(): Promise<void> {
    if (busy) return;
    const previousFocus = document.activeElement;
    if (!invitation.trim()) {
      errorKind = 'required';
      await restoreActionFocus(previousFocus, () => document.getElementById('invitation'));
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
      await restoreActionFocus(previousFocus, () => document.getElementById('register'));
    }
  }
</script>

{#snippet invitationForm()}
  <label class="invite" for="invitation"
    >{m.invite()}
    <input
      id="invitation"
      type="text"
      autocomplete="off"
      spellcheck="false"
      aria-describedby={errorKind === 'required' ? 'invite-error' : undefined}
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
  <button class="quiet" id="register" type="button" disabled={busy} onclick={register}
    >{busy ? m.busy() : m.register()}</button
  >
  <p class="recovery">{m.recovery()}</p>
{/snippet}

<div
  class="auth-shell"
  class:busy
  class:enrollment
  style={`--page-hue:${pageProfile.hue};--rp-hue:${rpProfile.hue}`}
>
  <div class="shade" aria-hidden="true"></div>
  <div class="plate">
    <div class="item"><span>{m.app()}</span><strong>{client}</strong></div>
    <div
      class="item origin"
      style={`--grain-step:${pageProfile.spacing / 2}px;--grain-angle:${pageProfile.grainAngle}deg`}
    >
      <span>{m.authOriginLabel()}</span><strong>{page.host}</strong>
    </div>
    <div
      class="item origin destination"
      style={`--grain-step:${rpProfile.spacing / 2}px;--grain-angle:${rpProfile.grainAngle}deg`}
    >
      <span>{m.authRpOriginLabel()}</span><strong>{destination.host}</strong>
    </div>
  </div>
  <main class="entry">
    <h1 class="sr-only">{enrollment ? m.enrollHeading() : m.login()}</h1>
    {#if enrollment}
      <section class="registration enrollment-form" aria-label={m.enrollHeading()}>
        {@render invitationForm()}
        <a class="quiet" href={`/waitlist?lang=${locale}`}>{m.waitlistHeading()}</a>
      </section>
    {:else}
      <div class="bolt">
        <span class="saddle left" aria-hidden="true"></span><span
          class="saddle right"
          aria-hidden="true"
        ></span>
        <button
          class="passkey auth-primary"
          id="passkey"
          type="button"
          disabled={busy}
          onclick={() => authenticate()}>{busy ? m.busy() : m.loginAuthorize()}</button
        >
      </div>
    {/if}
    {#if errorKind === 'operation'}<p class="auth-alert" id="error" role="alert">
        {m.error()}
      </p>{/if}
  </main>
  <footer>
    {#if !enrollment && ownerLogin}<a class="quiet" href={`/enroll?lang=${locale}`}
        >{m.homeEnroll()}</a
      >
    {:else if !enrollment}<details class="registration" bind:open={registrationOpen}>
        <summary>{m.authRegisterHeading()}</summary>
        {@render invitationForm()}
      </details>{/if}
    <WovenGate
      pageOrigin={page.origin}
      rpOrigin={destination.origin}
      paused={busy || passkeyPending}
    />
    <select
      class="language"
      aria-label={m.language()}
      value={locale}
      onchange={(event) => switchLocale(event.currentTarget.value)}
      ><option value="ja">日本語</option><option value="en">English</option></select
    >
  </footer>
</div>
