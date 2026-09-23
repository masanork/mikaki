import { mount } from 'svelte';
import Admin from './Admin.svelte';
import { initializeLocale } from './locale.js';

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid admin page');

mount(Admin, { target, props: { locale: initializeLocale() } });
