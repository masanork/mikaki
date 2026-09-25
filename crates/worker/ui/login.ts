import { mount } from 'svelte';
import Login from './Login.svelte';
import { initializeLocale } from './locale.js';
import './auth.css';

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid login page');
const { tx, challenge, rpId, client, enrollment } = target.dataset;
if (!tx || !challenge || !rpId || !client) throw new Error('Invalid login transaction');

mount(Login, {
  target,
  props: {
    tx,
    challenge,
    rpId,
    client,
    enrollment: enrollment === 'true',
    locale: initializeLocale(),
  },
});
