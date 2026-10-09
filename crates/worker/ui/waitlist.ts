import { mount } from 'svelte';
import Waitlist from './Waitlist.svelte';
import { initializeLocale } from './locale.js';
const target = document.getElementById('app');
if (!target) throw new Error('Missing app root');
mount(Waitlist, { target, props: { locale: initializeLocale() } });
