<script lang="ts">
  import { onMount } from 'svelte';
  import { vaultContext } from './vault-context.js';
  import type { OwnerVaultController } from './vault-owner-controller.ts';
  import type { MessagingMount } from './messaging-module.ts';
  import type { Locale } from './paraglide/runtime.js';
  let {
    owner,
    locale,
    disabled,
  }: {
    owner: OwnerVaultController;
    locale: Locale;
    disabled: boolean;
  } = $props();
  const context = vaultContext();
  let root: HTMLDivElement;
  let busy = $state(true),
    status = $state('');
  let mounted: { dispose(): void } | undefined;
  let disposed = false;
  let dirty = $state(false);
  async function open() {
    try {
      const token = owner.checkpoint();
      if (disabled || locale !== 'ja') {
        status =
          locale === 'ja'
            ? '設定の確認が終わってからChatを開いてください。'
            : 'Chat is currently available in Japanese.';
        return;
      }
      const response = await owner.scope.request('/vault/messaging-config', { cache: 'no-store' });
      if (!response.ok) throw new Error('unavailable');
      const settings: unknown = await response.json();
      owner.assertCurrent(token);
      if (disposed) return;
      if (
        !settings ||
        typeof settings !== 'object' ||
        !('enabled' in settings) ||
        settings.enabled !== true
      ) {
        status = 'この接続先ではChatをまだ利用できません。';
        return;
      }
      const url = new URL('/messaging/client.js', location.origin).href;
      const module = (await import(/* @vite-ignore */ url)) as MessagingMount;
      owner.assertCurrent(token);
      if (disposed) return;
      const result = await module.mount(owner, root, {
        onDraft: (value) => {
          dirty = value;
        },
      });
      if (disposed) result.dispose();
      else {
        try {
          owner.assertCurrent(token);
        } catch (error) {
          result.dispose();
          throw error;
        }
        mounted = result;
      }
    } catch {
      if (!disposed) status = 'Chatを開けませんでした。接続を確認し、画面を開き直してください。';
    } finally {
      if (!disposed) busy = false;
    }
  }
  onMount(() => {
    const unregister = context.registerDraft(() => dirty);
    void open();
    return () => {
      disposed = true;
      unregister();
      mounted?.dispose();
      dirty = false;
    };
  });
</script>

<section class="product-card" aria-label="Chat" aria-busy={busy}>
  {#if busy}<p role="status">{locale === 'ja' ? 'Chatを開いています…' : 'Opening Chat…'}</p>{/if}
  {#if status}<h2>Chat</h2>
    <p role="status">{status}</p>{/if}
  <div class="messaging-host" bind:this={root}></div>
</section>
