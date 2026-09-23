import { mount } from 'svelte';
import Vault from './Vault.svelte';
import { initializeLocale } from './locale.js';

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid Vault page');

mount(Vault, { target, props: { locale: initializeLocale() } });
