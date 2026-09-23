import { mount } from 'svelte';
import Complete from './Complete.svelte';
import { initializeLocale } from './locale.js';

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid registration completion page');

mount(Complete, {
  target,
  props: { locale: initializeLocale(), admin: target.dataset['admin'] === 'true' },
});
