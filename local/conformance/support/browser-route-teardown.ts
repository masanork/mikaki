import type { Page } from '@playwright/test';

// For finite local fixtures: release request barriers and stop initiating work
// before calling this. Keep interception installed until asset traffic settles.
// In Playwright 1.64, finishing one callback during unrouteAll can remove the
// server handler while another callback is still preparing its response.
// Keep the page and Worker alive, and preserve callback errors with `wait`.
export async function drainBrowserRoutes(
  page?: Pick<Page, 'waitForLoadState' | 'unrouteAll'>,
): Promise<void> {
  await page?.waitForLoadState('networkidle', { timeout: 10_000 });
  await page?.unrouteAll({ behavior: 'wait' });
}
