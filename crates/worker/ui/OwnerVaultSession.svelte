<script lang="ts">
  import VaultSession from './VaultSession.svelte';
  import { untrack } from 'svelte';
  import ProductWorkspace from './ProductWorkspace.svelte';
  import type { Locale } from './paraglide/runtime.js';
  import type { OwnerLoginPrf } from './vault-login-prf.ts';
  let { locale, loginPrf }: { locale: Locale; loginPrf?: OwnerLoginPrf } = $props();
  // The parent outlives scope remounts. Reopening a locked scope cannot reuse
  // the login ticket or trigger an automatic authenticator ceremony.
  let pendingLogin = untrack(() => loginPrf);
  const takeLogin = () => {
    const initial = pendingLogin;
    pendingLogin = undefined;
    return initial;
  };
</script>

<VaultSession {locale}><ProductWorkspace {locale} {takeLogin} /></VaultSession>
