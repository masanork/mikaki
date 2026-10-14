/** On-demand sample UI. No owner port, storage, service or work operation. */
import { mount, unmount } from 'svelte';
import WorkJourneyDemo from './WorkJourneyDemo.svelte';
import { initializeLocale } from './locale.js';

export function mountDemo(target: HTMLElement): () => void {
  initializeLocale();
  const instance = mount(WorkJourneyDemo, { target });
  return () => {
    // Remove input nodes immediately; dispose effects without retaining a view.
    target.replaceChildren();
    void unmount(instance);
  };
}
