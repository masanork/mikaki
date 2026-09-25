<script lang="ts">
  import { onMount } from 'svelte';
  import * as m from './paraglide/messages.js';
  import { getLocale, setLocale, type Locale } from './paraglide/runtime.js';
  let invitation = $state(''),
    consent = $state(false),
    busy = $state(false),
    error = $state(false),
    expired = $state(false);
  let context = $state<{ tx: string; csrf: string; client: string; signed_in: boolean } | null>(
    null,
  );
  const tx = new URL(location.href).searchParams.get('tx');
  const decode = (s: string) =>
    Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0));
  const encode = (b: ArrayBuffer) =>
    btoa(String.fromCharCode(...new Uint8Array(b)))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replaceAll('=', '');
  async function post(path: string, data: object) {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...context, ...data }),
    });
    if (!r.ok) throw new Error('operation_failed');
    return r.json();
  }
  onMount(async () => {
    const r = await fetch(`/login/context?tx=${encodeURIComponent(tx ?? '')}`);
    if (r.ok) context = await r.json();
    else expired = true;
  });
  async function run(purpose: 'register' | 'authenticate' | 'consent') {
    if (!consent || !context || busy) return;
    busy = true;
    error = false;
    try {
      if (purpose === 'consent') {
        const r = await post('/consent', { consent });
        location.assign(r.location);
        return;
      }
      const start = await post('/ceremony/start', { purpose, invitation });
      const options = start.publicKey;
      options.challenge = decode(options.challenge);
      if (options.user) options.user.id = decode(options.user.id);
      if (purpose === 'register') options.extensions = { ...options.extensions, prf: {} };
      const credential = (await (purpose === 'register'
        ? navigator.credentials.create({ publicKey: options })
        : navigator.credentials.get({ publicKey: options }))) as PublicKeyCredential | null;
      if (!credential) throw new Error('cancelled');
      // Client compatibility signal only; this is not signed authenticator evidence.
      if (purpose === 'register' && credential.getClientExtensionResults().credProps?.rk !== true)
        throw new Error('discoverable_credential_required');
      const clientData = encode(credential.response.clientDataJSON);
      const response =
        purpose === 'register'
          ? {
              id: credential.id,
              client_data: clientData,
              attestation: encode(
                (credential.response as AuthenticatorAttestationResponse).attestationObject,
              ),
            }
          : {
              id: credential.id,
              client_data: clientData,
              authenticator_data: encode(
                (credential.response as AuthenticatorAssertionResponse).authenticatorData,
              ),
              signature: encode((credential.response as AuthenticatorAssertionResponse).signature),
              user_handle: encode(
                (credential.response as AuthenticatorAssertionResponse).userHandle!,
              ),
            };
      const r = await post('/ceremony/finish', { ceremony: start.ceremony, response, consent });
      invitation = '';
      location.assign(r.location);
    } catch {
      error = true;
    } finally {
      busy = false;
    }
  }
  $effect(() => {
    document.documentElement.lang = getLocale();
  });
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
        value={getLocale()}
        onchange={(event) => setLocale(event.currentTarget.value as Locale)}
        ><option value="ja">日本語</option><option value="en">English</option></select
      >
    </label>
  </header>
  <main class="auth-layout">
    <section class="auth-intro" aria-labelledby="auth-title">
      <p class="auth-kicker">{m.authKicker()}</p>
      <h1 id="auth-title">{m.authHeroHeadingFirst()}<br />{m.authHeroHeadingSecond()}</h1>
      <p>{m.authHeroDescription()}</p>
    </section>
    <section class="auth-card" aria-labelledby="auth-action-title">
      <h2 id="auth-action-title">{m.login()}</h2>
      <p class="auth-card-lead">{m.authCheckApp()}</p>
      {#if expired}
        <p class="auth-alert" role="alert">{m.expired()}</p>
      {:else if context}
        <div class="auth-client">
          <span class="auth-client-label">{m.app()}</span>
          <strong class="auth-client-name">{context.client}</strong>
        </div>
        <p class="auth-description">{m.loginConsentDescription()}</p>
        <label class="auth-consent"
          ><input type="checkbox" bind:checked={consent} />{m.consent()}</label
        >
        {#if context.signed_in}
          <button class="auth-primary" disabled={!consent || busy} onclick={() => run('consent')}
            >{busy ? m.busy() : m.continue()}</button
          >
        {:else}
          <button
            class="auth-primary"
            disabled={!consent || busy}
            onclick={() => run('authenticate')}>{busy ? m.busy() : m.login()}</button
          >
          <hr class="auth-divider" />
          <h3 class="auth-subheading">{m.authRegisterHeading()}</h3>
          <p class="auth-field-help" id="invite-help">{m.authInviteHelp()}</p>
          <label class="auth-field" for="invitation">
            {m.invite()}
            <input
              id="invitation"
              bind:value={invitation}
              autocomplete="off"
              spellcheck="false"
              aria-describedby="invite-help"
            />
          </label>
          <button
            class="auth-secondary"
            disabled={!consent || !invitation || busy}
            onclick={() => run('register')}>{busy ? m.busy() : m.register()}</button
          >
          <p class="auth-note">{m.recovery()}</p>
        {/if}
      {/if}
      {#if error}<p class="auth-alert" role="alert">{m.error()}</p>{/if}
    </section>
  </main>
  <footer class="auth-footer">mikaki · {m.local()}</footer>
</div>
