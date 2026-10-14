<script lang="ts">
  import * as m from './paraglide/messages.js';
  import type { LoginConnection, LoginRecognition } from './login-history.js';

  let {
    connection,
    recognition,
    label,
    busy,
    onapprove,
    oncancel,
  }: {
    connection: LoginConnection;
    recognition: LoginRecognition;
    label: string;
    busy: boolean;
    onapprove: () => void;
    oncancel: () => Promise<void>;
  } = $props();
</script>

<section class="connection-review" aria-labelledby="connection-review-title">
  <h2 id="connection-review-title" tabindex="-1">{m.loginReviewTitle()}</h2>
  <p>{label}</p>
  <dl>
    <div>
      <dt>{m.app()}</dt>
      <dd>{connection.client}</dd>
    </div>
    {#if recognition.kind === 'changed' && recognition.previous?.destination !== connection.destination}
      <div>
        <dt>{m.loginPreviousDestination()}</dt>
        <dd>{recognition.previous?.destination}</dd>
      </div>
    {/if}
    <div>
      <dt>{m.authRpOriginLabel()}</dt>
      <dd>{connection.destination}</dd>
    </div>
    <div>
      <dt>{m.loginConnectionPurpose()}</dt>
      <dd>
        {connection.scope.includes('profile') ? m.loginPurposeProfile() : m.loginPurposeSignIn()}
      </dd>
    </div>
  </dl>
  {#if recognition.kind === 'changed' && recognition.previous?.scope !== connection.scope}
    <p class="connection-change">{m.loginScopeChanged()}</p>
  {/if}
  <p>{m.loginReviewHint()}</p>
  <div class="connection-actions">
    <button
      class="connection-continue"
      id="connection-approve"
      type="button"
      disabled={busy}
      onclick={onapprove}>{m.loginReviewApprove()}</button
    >
    <button class="quiet" id="connection-cancel" type="button" disabled={busy} onclick={oncancel}
      >{m.loginReviewCancel()}</button
    >
  </div>
</section>
