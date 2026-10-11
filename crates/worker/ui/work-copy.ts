import { mount } from 'svelte';
import WorkCopySession from './WorkCopySession.svelte';
import { initializeLocale } from './locale.js';
import './product.css';
const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid copy page');
mount(WorkCopySession, { target, props: { locale: initializeLocale() } });
