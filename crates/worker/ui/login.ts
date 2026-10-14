import { mount } from 'svelte';
import Login from './Login.svelte';
import Home from './Home.svelte';
import { initializeLocale } from './locale.js';
import './auth.css';
import './login-connection.css';

const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid login page');
if (target.dataset['page'] === 'home') {
  const locale = initializeLocale();
  target.replaceChildren();
  mount(Home, { target, props: { locale } });
} else {
  const {
    tx,
    challenge,
    rpId,
    rpUri,
    client,
    enrollment,
    ownerLogin,
    loginScope,
    expiresInMs,
    connectionReviewRequired,
  } = target.dataset;
  if (!tx || !challenge || !rpId || !rpUri || !client) throw new Error('Invalid login transaction');
  const lifetime = expiresInMs === undefined ? 300_000 : Number(expiresInMs);
  if (!Number.isFinite(lifetime) || lifetime < 0) throw new Error('Invalid login lifetime');

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
      scope: loginScope ?? 'openid',
      expiresInMs: lifetime,
      reviewRequired: connectionReviewRequired === 'true',
      locale: initializeLocale(),
    },
  });
}
