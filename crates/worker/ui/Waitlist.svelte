<script lang="ts">
  import * as m from './paraglide/messages.js';
  import ProductHeader from './ProductHeader.svelte';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
  let email = $state('');
  let busy = $state(false);
  let failed = $state(false);
  let limited = $state(false);
  let submitted = $state(false);
  let confirmed = $state(false);
  let confirmation = $state('');
  // The bearer stays out of HTTP URLs, referrers and browser history. GET never consumes it.
  const match = /^#confirm=([A-Za-z0-9_-]{43})$/.exec(location.hash);
  if (match) confirmation = match[1];
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  async function send(confirm = false) {
    if (busy) return;
    busy = true;
    failed = false;
    limited = false;
    try {
      const response = await fetch(confirm ? '/waitlist/confirm' : '/waitlist/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(confirm ? { token: confirmation } : { email, locale }),
      });
      if (!response.ok) {
        limited = response.status === 429;
        throw new Error('Request failed');
      }
      if (confirm) {
        confirmed = true;
        confirmation = '';
      } else {
        submitted = true;
        email = '';
      }
    } catch {
      failed = true;
    } finally {
      busy = false;
    }
  }
</script>

<div class="product-material-shell">
  <ProductHeader {locale} session={false} material paused={busy} />
  <main id="product-main" tabindex="-1" class="product-main product-admin">
    <div class="product-heading">
      <h1>{m.waitlistHeading()}</h1>
      <p>{m.waitlistIntro()}</p>
    </div>
    <section class="product-card" aria-label={m.waitlistHeading()}>
      {#if confirmed}<p role="status">{m.waitlistConfirmed()}</p>
      {:else if confirmation}<p>{m.waitlistConfirmIntro()}</p>
        <button class="product-primary" disabled={busy} onclick={() => send(true)}
          >{m.waitlistConfirm()}</button
        >
      {:else if submitted}<p role="status">{m.waitlistSubmitted()}</p>
        <button
          type="button"
          onclick={() => {
            submitted = false;
          }}>{m.waitlistAnother()}</button
        >
      {:else}<form
          onsubmit={(event) => {
            event.preventDefault();
            void send();
          }}
        >
          <label for="waitlist-email">{m.waitlistEmail()}</label>
          <input
            id="waitlist-email"
            type="email"
            autocomplete="email"
            maxlength="254"
            required
            bind:value={email}
            disabled={busy}
          />
          <p>{m.waitlistContactOnly()}</p>
          <button class="product-primary" type="submit" disabled={busy}
            >{busy ? m.busy() : m.waitlistSubmit()}</button
          >
        </form>
      {/if}
      {#if failed}<p role="alert">{limited ? m.waitlistLimited() : m.waitlistError()}</p>{/if}
      <p><a href={`/enroll?lang=${locale}`}>{m.homeEnroll()}</a></p>
    </section>
  </main>
</div>
