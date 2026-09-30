import { mount } from 'svelte';
import VaultSession from './VaultSession.svelte';
import { initializeLocale } from './locale.js';

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid Vault page');

mount(VaultSession, { target, props: { locale: initializeLocale() } });
