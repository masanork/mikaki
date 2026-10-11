import { mount } from 'svelte';
import WorkPreparationSession from './WorkPreparationSession.svelte';
import { initializeLocale } from './locale.js';
import './product.css';
const target = document.getElementById('app');
if (!(target instanceof HTMLElement)) throw new Error('Invalid preparation review page');
mount(WorkPreparationSession, { target, props: { locale: initializeLocale() } });
