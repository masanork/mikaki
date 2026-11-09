<script lang="ts">
  import { onMount } from 'svelte';
  import type { Locale } from './paraglide/runtime.js';
  let { locale }: { locale: Locale } = $props();
  type Status = {
    email: null | { email: string };
    clients: { client_id: string; released: number }[];
  };
  let available = $state(false),
    busy = $state(false),
    status = $state<Status | null>(null);
  let address = $state(''),
    code = $state(''),
    message = $state('');
  const ja = $derived(locale === 'ja');
  const abort = new AbortController();
  async function refresh() {
    const response = await fetch('/account/email', {
      credentials: 'same-origin',
      cache: 'no-store',
      signal: abort.signal,
    });
    if (response.status === 404) {
      available = false;
      return;
    }
    if (!response.ok) throw new Error('status');
    status = (await response.json()) as Status;
    available = true;
  }
  async function post(path: string, body: object) {
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: abort.signal,
    });
    if (!response.ok) throw new Error('request');
  }
  async function run(action: () => Promise<void>, success: string) {
    if (busy) return;
    busy = true;
    message = '';
    try {
      await action();
      await refresh();
      message = success;
    } catch {
      if (!abort.signal.aborted)
        message = ja
          ? '処理を確認できませんでした。状態を確認して再試行してください。'
          : 'Could not confirm the result. Check the state and try again.';
    } finally {
      busy = false;
    }
  }
  onMount(() => {
    void refresh().catch(() => {
      available = false;
    });
    return () => abort.abort();
  });
</script>

{#if available && status}
  <details id="owner-email">
    <summary>{ja ? 'メールアドレスと連携先' : 'Email and connected apps'}</summary>
    <p>
      {ja
        ? '確認済みのメールは mikaki に保存され、許可した連携先にだけ提供されます。'
        : 'Mikaki stores your verified email and shares it only with apps you approve.'}
    </p>
    <p>
      {ja
        ? '提供を停止しても、連携先の既存セッションは残る場合があります。'
        : 'Existing app sessions may remain active after sharing stops.'}
    </p>
    <p>{ja ? '確認済み' : 'Verified'}: {status.email?.email ?? (ja ? '未登録' : 'None')}</p>
    {#if status.email}
      <button
        type="button"
        disabled={busy}
        onclick={() => {
          if (
            confirm(
              ja
                ? '確認済みメールを削除し、連携先への提供を停止しますか？'
                : 'Remove the verified email and stop sharing it with apps?',
            )
          )
            void run(
              () => post('/account/email/remove', {}),
              ja ? 'メールを削除しました。' : 'Email removed.',
            );
        }}>{ja ? '確認済みメールを削除' : 'Remove verified email'}</button
      >
    {/if}
    <form
      onsubmit={(event) => {
        event.preventDefault();
        void run(
          () => post('/account/email/start', { email: address }),
          ja
            ? '確認コードの送信を受け付けました。メールを確認してください。'
            : 'The confirmation email was accepted for sending. Check your inbox.',
        );
      }}
    >
      <label for="owner-email-address">{ja ? 'メールアドレス' : 'Email address'}</label>
      <input
        id="owner-email-address"
        type="email"
        autocomplete="email"
        bind:value={address}
        maxlength="254"
        required
        disabled={busy}
      />
      <button type="submit" disabled={busy}
        >{ja ? '確認コードを送る' : 'Send confirmation code'}</button
      >
    </form>
    <form
      onsubmit={(event) => {
        event.preventDefault();
        void run(
          async () => {
            await post('/account/email/confirm', { token: code });
            code = '';
            address = '';
          },
          ja ? 'メールを確認しました。' : 'Email verified.',
        );
      }}
    >
      <label for="owner-email-code">{ja ? '確認コード' : 'Confirmation code'}</label>
      <input
        id="owner-email-code"
        type="text"
        autocomplete="one-time-code"
        bind:value={code}
        maxlength="43"
        required
        disabled={busy}
      />
      <button type="submit" disabled={busy}>{ja ? '確認する' : 'Verify'}</button>
    </form>
    {#each status.clients as client (client.client_id)}
      <p>
        {client.client_id}: {client.released
          ? ja
            ? '提供中'
            : 'Sharing'
          : ja
            ? '提供しない'
            : 'Not sharing'}
        <button
          type="button"
          disabled={busy || !status.email}
          onclick={() =>
            void run(
              () =>
                post('/account/email/release', {
                  client_id: client.client_id,
                  action: client.released ? 'revoke' : 'grant',
                }),
              ja ? '連携先の設定を更新しました。' : 'App sharing updated.',
            )}
          >{client.released
            ? ja
              ? '提供を取り消す'
              : 'Stop sharing'
            : ja
              ? '提供を許可'
              : 'Allow sharing'}</button
        >
      </p>
    {/each}
    <p role="status" aria-live="polite">{message}</p>
  </details>
{/if}
