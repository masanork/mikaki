import { mount } from 'svelte';
import App from './App.svelte';
import { setLocale } from './paraglide/runtime.js';
import '../../../crates/worker/ui/auth.css';
const requestedLocale = new URL(location.href).searchParams.get('lang');
if (requestedLocale === 'ja' || requestedLocale === 'en') {
  setLocale(requestedLocale, { reload: false });
}
mount(App, { target: document.getElementById('app')! });
