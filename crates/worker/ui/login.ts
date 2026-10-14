import { mount, unmount } from 'svelte';
import Login from './Login.svelte';
import Home from './Home.svelte';
import { initializeLocale } from './locale.js';
import './auth.css';
import './login-connection.css';
import type { OwnerLoginPrf } from './vault-login-prf.ts';
import type { Locale } from './paraglide/runtime.js';

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
    vaultLogin,
    loginScope,
    expiresInMs,
    connectionReviewRequired,
  } = target.dataset;
  if (!tx || !challenge || !rpId || !rpUri || !client) throw new Error('Invalid login transaction');
  const lifetime = expiresInMs === undefined ? 300_000 : Number(expiresInMs);
  if (!Number.isFinite(lifetime) || lifetime < 0) throw new Error('Invalid login lifetime');

  target.dataset['page'] = 'login';
  const locale = initializeLocale();
  const login = mount(Login, {
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
      vaultLogin: vaultLogin === 'true',
      onOwnerLogin: async (destination: string, ticket: OwnerLoginPrf) => {
        const url = new URL(destination, location.origin);
        if (
          url.origin !== location.origin ||
          url.pathname !== '/vault' ||
          url.hash ||
          [...url.searchParams].some(
            ([key, value]) => key !== 'lang' || !['ja', 'en'].includes(value),
          ) ||
          [...url.searchParams].length > 1
        ) {
          ticket.dispose();
          throw new Error('Invalid owner continuation');
        }
        try {
          // Fetch presentation only after verified login. Keep the same document
          // so PRF output never crosses a URL, storage, server or another tab.
          const response = await fetch(url, { cache: 'no-store', redirect: 'error' });
          if (!response.ok) throw new Error('Vault page unavailable');
          const page = new DOMParser().parseFromString(await response.text(), 'text/html');
          const app = page.getElementById('app');
          if (!app) throw new Error('Invalid Vault page');
          const vaultLocale = page.documentElement.lang;
          if (vaultLocale !== 'ja' && vaultLocale !== 'en') throw new Error('Invalid Vault locale');
          const moduleUrl = '/vault/vault.js';
          const vault: {
            mountSignedInVault: (
              target: HTMLElement,
              locale: Locale,
              ticket: OwnerLoginPrf,
            ) => void;
          } = await import(/* @vite-ignore */ moduleUrl);
          const stylesheet = document.createElement('link');
          stylesheet.rel = 'stylesheet';
          stylesheet.href = '/ui/product.css';
          await new Promise<void>((resolve, reject) => {
            stylesheet.onload = () => resolve();
            stylesheet.onerror = () => reject(new Error('Vault stylesheet unavailable'));
            document.head.append(stylesheet);
          });
          await unmount(login);
          target.replaceChildren();
          for (const key of Object.keys(target.dataset)) delete target.dataset[key];
          target.dataset['workSourceReview'] =
            app.dataset['workSourceReview'] === 'true' ? 'true' : 'false';
          target.dataset['workPreparationReview'] =
            app.dataset['workPreparationReview'] === 'true' ? 'true' : 'false';
          document.querySelector('link[href="/login/login.css"]')?.remove();
          document.title = page.title;
          document.documentElement.lang = vaultLocale;
          history.replaceState(null, '', url);
          vault.mountSignedInVault(target, vaultLocale, ticket);
        } catch {
          ticket.dispose();
          // Login already succeeded. A presentation failure returns to the
          // normal locked page, never reports a failed authentication/replays it.
          location.assign(url.href);
        }
      },
      locale,
    },
  });
}
