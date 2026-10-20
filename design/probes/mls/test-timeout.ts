/** Optional budget for a busy local host. Protocol/lease expiry and Playwright
 * assertions are unchanged; CI keeps the original deadlines by default. */
const configured = process.env.MIKAKI_MLS_TEST_TIMEOUT_MULTIPLIER ?? '1';
if (!/^[1-4]$/.test(configured)) throw new Error('invalid_mls_test_timeout_multiplier');
const multiplier = Number(configured);
export function qualificationTimeout(milliseconds: number): number {
  return milliseconds * multiplier;
}
