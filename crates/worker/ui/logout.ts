import { publishVaultLock } from './session-events.js';
// Submitting confirmation locks other tabs even if logout later fails. Revocation stays server-owned.
document.querySelector('form')?.addEventListener('submit', publishVaultLock);
if (document.body.dataset['sessionState'] === 'ended') publishVaultLock();
