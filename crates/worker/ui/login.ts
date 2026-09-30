import { mount } from 'svelte';
import Login from './Login.svelte';
import { initializeLocale } from './locale.js';
import './auth.css';

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid login page');
const { tx, challenge, rpId, rpUri, client, enrollment, ownerLogin } = target.dataset;
if (!tx || !challenge || !rpId || !rpUri || !client) throw new Error('Invalid login transaction');

mount(Login, {
  target,
  props: {
    tx,
    challenge,
    rpId,
    rpUri,
    client,
    enrollment: enrollment === 'true',
    ownerLogin: ownerLogin === 'true',
    locale: initializeLocale(),
  },
});
