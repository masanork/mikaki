import { mount } from 'svelte';
import OwnerVaultSession from './OwnerVaultSession.svelte';
import { initializeLocale } from './locale.js';

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid Vault page');

mount(OwnerVaultSession, { target, props: { locale: initializeLocale() } });
