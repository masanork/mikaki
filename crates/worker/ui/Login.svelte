<script lang="ts">
  import { restoreActionFocus } from './action-focus.js';
  import { publishVaultLock } from './session-events.js';
  import { onMount, tick } from 'svelte';
  import * as m from './paraglide/messages.js';
  import { switchLocale } from './locale.js';
  import WovenGate from './WovenGate.svelte';
  import ConnectionReview from './ConnectionReview.svelte';
  import { weaveProfile } from './woven-gate.js';
  import type { Locale } from './paraglide/runtime.js';
  import {
    loginCredential,
    loginDestination,
    loginScope,
    readLoginHistory,
    recognizeLogin,
    rememberLogin,
    type LoginConnection,
    type LoginHistory,
    type LoginRecognition,
  } from './login-history.js';

  let {
    tx,
    challenge,
    rpId,
    rpUri,
    client,
    enrollment,
    ownerLogin,
    scope = 'openid',
    expiresInMs = 300_000,
    locale,
  }: {
    tx: string;
    challenge: string;
    rpId: string;
    rpUri: string;
    client: string;
    enrollment: boolean;
    ownerLogin: boolean;
    scope?: string;
    expiresInMs?: number;
    locale: Locale;
  } = $props();
  let busy = $state(false);
  let linkedToken = /^#invite=([A-Za-z0-9_-]{43})$/.exec(location.hash)?.[1];
  const invalidFragment = !!location.hash && !linkedToken;
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  const page = new URL(location.href);
  const destination = $derived(new URL(rpUri));
  const pageProfile = weaveProfile(page.origin);
  const rpProfile = $derived(weaveProfile(destination.origin));
  const connection = $derived<LoginConnection>({
    issuer: page.origin,
    client,
    destination: loginDestination(rpUri),
    scope: loginScope(scope),
  });
  const transactionStarted = performance.now();
  const transactionDeadline = $derived(
    transactionStarted + Math.max(0, Math.min(expiresInMs, 300_000)),
  );
  let recognition = $state<LoginRecognition>({ kind: 'first' });
  let disposed = false;
  let reviewTimer: ReturnType<typeof setTimeout> | undefined;
  type Pending = {
    endpoint: '/login/finish' | '/register/finish';
    response: Record<string, string | null>;
    credential: string | null;
    deadline: number;
  };
  let pending = $state<Pending | null>(null);
  let passkeyPending = $state(false);
  let errorKind = $state<'required' | 'operation' | 'link' | 'expired' | null>(null);
  let invitation = $state('');
  let linkedInvitation = $state(false);
  let checkingInvitation = $state(false);
  let registrationOpen = $state(false);
  let authentication: AbortController | null = null;

  onMount(() => {
    recognition = recognizeLogin(readHistory(), connection);
    registrationOpen = enrollment;
    if (enrollment) void prepareInvitation();
    else if (typeof PublicKeyCredential !== 'undefined') void authenticate(true);
    const discard = () => {
      disposed = true;
      authentication?.abort();
      clearTimeout(reviewTimer);
      pending = null;
    };
    const resume = (event: PageTransitionEvent) => {
      if (event.persisted) {
        disposed = false;
        authentication = null;
        busy = false;
        passkeyPending = false;
        errorKind = 'expired';
      }
    };
    window.addEventListener('pagehide', discard);
    window.addEventListener('pageshow', resume);
    return () => {
      disposed = true;
      discard();
      window.removeEventListener('pagehide', discard);
      window.removeEventListener('pageshow', resume);
    };
  });

  function readHistory(): LoginHistory {
    try {
      return readLoginHistory(localStorage);
    } catch {
      return { available: false, records: [] };
    }
  }

  function historyLabel(): string {
    if (recognition.kind === 'unavailable') return m.loginHistoryUnavailable();
    if (recognition.kind === 'first') return m.loginHistoryFirst();
    if (recognition.kind === 'changed') return m.loginHistoryChanged();
    const date = new Date(recognition.previous!.last).toLocaleString(locale, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
    return m.loginHistoryKnown({ date });
  }

  async function complete(p: Pending): Promise<void> {
    clearTimeout(reviewTimer);
    pending = null;
    if (performance.now() >= p.deadline) {
      busy = false;
      errorKind = 'expired';
      return;
    }
    busy = true;
    try {
      const result = await fetch(p.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tx, consent: true, response: p.response }),
      });
      if (!result.ok) throw new Error('rejected');
      const body: unknown = await result.json();
      if (
        !body ||
        typeof body !== 'object' ||
        !('location' in body) ||
        typeof body.location !== 'string'
      )
        throw new Error('invalid response');
      const next = new URL(body.location);
      if (next.origin !== page.origin || next.username || next.password)
        throw new Error('invalid continuation');
      if (disposed) return;
      // Storage failure affects recognition only, never authentication or Vault keys.
      try {
        if (p.credential) rememberLogin(localStorage, connection, p.credential);
      } catch {
        /* unavailable */
      }
      invitation = '';
      publishVaultLock();
      location.assign(next.href);
    } catch {
      if (disposed) return;
      authentication = null;
      busy = false;
      errorKind = 'operation';
      await restoreActionFocus(null, () =>
        document.getElementById(enrollment ? 'register' : 'passkey'),
      );
    }
  }

  async function prepareCompletion(
    endpoint: Pending['endpoint'],
    response: Pending['response'],
    id: string,
  ): Promise<void> {
    let fingerprint: string | null = null;
    try {
      fingerprint = await loginCredential(page.origin, id);
    } catch {
      /* recognition is optional */
    }
    if (disposed) return;
    // Re-read after Passkey selection: a different Passkey on a shared browser
    // must not inherit another credential's recognition or skip its review.
    recognition = fingerprint
      ? recognizeLogin(readHistory(), connection, fingerprint)
      : { kind: 'unavailable' };
    const proof: Pending = {
      endpoint,
      response,
      credential: fingerprint,
      deadline: Math.min(transactionDeadline, performance.now() + 120_000),
    };
    if (!enrollment && !ownerLogin && recognition.kind !== 'known') {
      pending = proof;
      busy = false;
      registrationOpen = false;
      reviewTimer = setTimeout(
        () => {
          pending = null;
          errorKind = 'expired';
          void restoreActionFocus(null, () => document.getElementById('passkey'));
        },
        Math.max(0, proof.deadline - performance.now()),
      );
      await tick();
      document.getElementById('connection-review-title')?.focus();
    } else await complete(proof);
  }

  async function cancelConnection(): Promise<void> {
    clearTimeout(reviewTimer);
    pending = null;
    authentication?.abort();
    busy = true;
    try {
      // Consume the existing transaction without sending the retained proof.
      await fetch('/login/deny', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tx }),
      });
    } catch {
      // The discarded proof cannot be submitted; any unconsumed transaction expires.
    } finally {
      // Stay with mikaki; do not send a suspicious connection back to its RP.
      location.assign(`/?lang=${locale}`);
    }
  }

  async function prepareInvitation(): Promise<void> {
    checkingInvitation = true;
    try {
      if (invalidFragment) throw new Error('Invalid invitation link');
      const response = await fetch('/register/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tx, ...(linkedToken ? { invitation: linkedToken } : {}) }),
      });
      if (response.status === 204 && !linkedToken) return;
      if (!response.ok) throw new Error('Invalid invitation link');
      linkedInvitation = true;
    } catch {
      errorKind = 'link';
    } finally {
      linkedToken = undefined;
      checkingInvitation = false;
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

  async function authenticate(automatic = false): Promise<void> {
    if (busy || pending) return;
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
      await prepareCompletion('/login/finish', response, credential.id);
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
    if (busy || pending) return;
    const previousFocus = document.activeElement;
    if (!linkedInvitation && !invitation.trim()) {
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
        body: JSON.stringify({ tx, ...(!linkedInvitation ? { invitation } : {}) }),
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
      await prepareCompletion(
        '/register/finish',
        {
          id: credential.id,
          client_data: encode(credential.response.clientDataJSON),
          attestation: encode(credential.response.attestationObject),
        },
        credential.id,
      );
    } catch {
      errorKind = 'operation';
      busy = false;
      await restoreActionFocus(previousFocus, () => document.getElementById('register'));
    }
  }
</script>

{#snippet invitationForm()}
  {#if checkingInvitation}<p role="status">{m.busy()}</p>
  {:else if errorKind !== 'link'}
    {#if linkedInvitation}<p>{m.enrollLinkIntro()}</p>
    {:else}<label class="invite" for="invitation"
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
      </label>{/if}
    {#if errorKind === 'required'}<p class="auth-field-error" id="invite-error" role="alert">
        {m.inviteRequired()}
      </p>{/if}
    <button class="quiet" id="register" type="button" disabled={busy} onclick={register}
      >{busy ? m.busy() : linkedInvitation ? m.enrollStart() : m.register()}</button
    >
    <p class="recovery">{m.recovery()}</p>
  {/if}
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
      <span>{m.authRpOriginLabel()}</span><strong
        >{destination.host || connection.destination}</strong
      >
    </div>
  </div>
  {#if !enrollment}
    <div class="connection-memory" data-recognition={recognition.kind}>
      <p>{historyLabel()}</p>
      <p class="connection-hint">{m.loginAddressHint()}</p>
    </div>
  {/if}
  <main class="entry">
    <h1 class="sr-only">{enrollment ? m.enrollHeading() : m.login()}</h1>
    {#if pending}
      <ConnectionReview
        {connection}
        {recognition}
        label={historyLabel()}
        {busy}
        onapprove={() => {
          if (pending) void complete(pending);
        }}
        oncancel={cancelConnection}
      />
    {:else if enrollment}
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
    {#if errorKind === 'expired'}<p class="auth-alert" role="alert">
        {m.loginReviewExpired()}
      </p>{/if}
    {#if errorKind === 'link'}<p class="auth-alert" role="alert">{m.enrollLinkUnavailable()}</p>
      <a class="quiet" href={`/signin?lang=${locale}`}>{m.enrollSignIn()}</a>{/if}
  </main>
  <footer>
    {#if !pending && !enrollment && ownerLogin}<a class="quiet" href={`/enroll?lang=${locale}`}
        >{m.homeEnroll()}</a
      >
    {:else if !pending && !enrollment}<details class="registration" bind:open={registrationOpen}>
        <summary>{m.authRegisterHeading()}</summary>
        {@render invitationForm()}
      </details>{/if}
    <WovenGate
      pageOrigin={page.origin}
      rpOrigin={destination.origin}
      paused={busy || passkeyPending || pending !== null}
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
