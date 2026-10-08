import { mount } from 'svelte';
import WorkSourceSession from './WorkSourceSession.svelte';
import { initializeLocale } from './locale.js';
import './product.css';
const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid source review page');
mount(WorkSourceSession, { target, props: { locale: initializeLocale() } });
