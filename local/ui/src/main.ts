import { mount } from 'svelte';
import App from './App.svelte';
import '../../../crates/worker/ui/auth.css';
mount(App, { target: document.getElementById('app')! });
