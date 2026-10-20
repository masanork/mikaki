import { mount } from 'svelte';
import OwnerVaultSession from './RetiredOwnerSession.svelte';
import { initializeLocale } from '../../../crates/worker/ui/locale.ts';
import type { Locale } from '../../../crates/worker/ui/paraglide/runtime.js';
import type { OwnerLoginPrf } from '../../../crates/worker/ui/vault-login-prf.ts';

export function mountSignedInVault(
  target: HTMLElement,
  locale: Locale,
  loginPrf: OwnerLoginPrf,
): void {
  // Each separately built entry has its own locale runtime.
  if (initializeLocale() !== locale) throw new Error('Vault locale changed');
  mount(OwnerVaultSession, { target, props: { locale, loginPrf } });
}

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid Vault page');

// Importing this entry from Login must not mount over the still active screen.
if (target.dataset['page'] !== 'login')
  mount(OwnerVaultSession, { target, props: { locale: initializeLocale() } });
