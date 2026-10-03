import { tick } from 'svelte';

/** Restore an action's focus after disabled/removed controls change, without stealing it. */
export async function restoreActionFocus(
  previous: Element | null,
  destination: () => HTMLElement | null,
): Promise<void> {
  await tick();
  if (document.visibilityState !== 'visible') return;
  const current = document.activeElement;
  if (current !== previous && current !== document.body && current !== null) return;
  const next = destination();
  if (
    next?.isConnected &&
    !next.matches(':disabled, [inert]') &&
    !next.closest('[hidden], [inert]')
  )
    next.focus();
}
