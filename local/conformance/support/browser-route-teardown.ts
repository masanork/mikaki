import type { Page } from '@playwright/test';

// Release any test-owned request barriers before calling this. Keep the page
// and Worker alive until callbacks finish, including allHeaders/cookie updates.
// `wait` preserves callback failures; `ignoreErrors` would hide regressions.
export async function drainBrowserRoutes(page?: Pick<Page, 'unrouteAll'>): Promise<void> {
  await page?.unrouteAll({ behavior: 'wait' });
}
