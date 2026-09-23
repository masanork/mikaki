<script lang="ts">
  import { onMount } from 'svelte';
  import { messages } from './messages';
  let lang = $state<'ja' | 'en'>(navigator.language.startsWith('ja') ? 'ja' : 'en');
  const m = $derived(messages[lang]);
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
    document.documentElement.lang = lang;
  });
</script>

<main>
  <header>
    <strong>mikaki</strong><label
      ><span class="sr">Language</span><select aria-label="Language" bind:value={lang}
        ><option value="ja">日本語</option><option value="en">English</option></select
      ></label
    >
  </header>
  <p class="tag">{m.local}</p>
  <h1>{m.title}</h1>
  <p>{m.intro}</p>
  {#if expired}<p role="alert">{m.expired}</p>{:else if context}
    <p>{m.app}: <strong>{context.client}</strong></p>
    <label class="consent"><input type="checkbox" bind:checked={consent} />{m.consent}</label>
    {#if context.signed_in}
      <button disabled={!consent || busy} onclick={() => run('consent')}
        >{busy ? m.busy : m.continue}</button
      >
    {:else}
      <button disabled={!consent || busy} onclick={() => run('authenticate')}
        >{busy ? m.busy : m.login}</button
      >
      <hr />
      <label for="invitation">{m.invite}</label><input
        id="invitation"
        bind:value={invitation}
        autocomplete="off"
        spellcheck="false"
      />
      <p class="notice">{m.recovery}</p>
      <button
        class="secondary"
        disabled={!consent || !invitation || busy}
        onclick={() => run('register')}>{busy ? m.busy : m.register}</button
      >
    {/if}
  {/if}
  {#if error}<p role="alert">{m.error}</p>{/if}
</main>

<style>
  :global(body) {
    margin: 0;
    background: #f2f5f4;
    color: #182b28;
    font:
      16px/1.6 system-ui,
      sans-serif;
  }
  main {
    max-width: 30rem;
    margin: 7vh auto;
    padding: 2rem;
    background: white;
    border-radius: 1rem;
    box-shadow: 0 8px 32px #173b2910;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  h1 {
    font-size: 1.6rem;
  }
  input:not([type='checkbox']),
  button {
    box-sizing: border-box;
    width: 100%;
    padding: 0.8rem;
    border: 1px solid #78938b;
    border-radius: 0.4rem;
    font: inherit;
  }
  button {
    margin-top: 1rem;
    background: #155e50;
    color: white;
    cursor: pointer;
  }
  .secondary {
    background: white;
    color: #155e50;
  }
  button:disabled {
    opacity: 0.55;
    cursor: default;
  }
  .consent {
    display: flex;
    gap: 0.7rem;
    align-items: center;
    padding: 0.5rem 0;
  }
  .notice,
  .tag {
    font-size: 0.85rem;
    color: #526b64;
  }
  hr {
    margin: 2rem 0;
    border: 0;
    border-top: 1px solid #d9e3df;
  }
  [role='alert'] {
    color: #9f2424;
  }
  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
  }
  @media (max-width: 40rem) {
    main {
      margin: 1rem;
      padding: 1.5rem;
    }
  }
</style>
