import { mount } from 'svelte';
import VaultSession from './VaultSession.svelte';
import OwnerVaultSession from './OwnerVaultSession.svelte';
import { initializeLocale } from './locale.js';

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid Vault page');

// Preserve the explicit name/note qualification preview. The default presentation
// is server-selected by VaultRouter; neither choice changes API authorization.
const component =
  new URL(location.href).searchParams.get('storage') === 'owner-v2'
    ? OwnerVaultSession
    : VaultSession;
mount(component, { target, props: { locale: initializeLocale() } });
