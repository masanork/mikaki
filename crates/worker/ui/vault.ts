import { mount } from 'svelte';
import VaultSession from './VaultSession.svelte';
import OwnerVaultSession from './OwnerVaultSession.svelte';
import { initializeLocale } from './locale.js';

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid Vault page');

// Explicit qualification preview; the existing default stays isolated until v2
// disclosure/proposal/transfer adapters are independently qualified.
const component =
  new URL(location.href).searchParams.get('storage') === 'owner-v2'
    ? OwnerVaultSession
    : VaultSession;
mount(component, { target, props: { locale: initializeLocale() } });
