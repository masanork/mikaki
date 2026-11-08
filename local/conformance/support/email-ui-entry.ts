import { mount } from 'svelte';
import OwnerEmail from '../../../crates/worker/ui/OwnerEmail.svelte';
mount(OwnerEmail, { target: document.body, props: { locale: 'en' } });
