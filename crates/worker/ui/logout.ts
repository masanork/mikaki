import { publishVaultLock } from './session-events.js';
import { createWovenGate, weaveProfile } from './woven-gate.js';

let renderer: ReturnType<typeof createWovenGate> = null;
// Submitting confirmation locks other tabs even if logout later fails. Revocation stays server-owned.
document.querySelector('form')?.addEventListener('submit', () => {
  publishVaultLock();
  renderer?.pause(true);
});
if (document.body.dataset['sessionState'] === 'ended') publishVaultLock();

const scene = document.querySelector<HTMLElement>('.product-material');
const canvas = scene?.querySelector<HTMLCanvasElement>('canvas');
const background = scene?.querySelector<HTMLElement>('.gate-background');
function initializeMaterial() {
  if (!scene || !canvas || !background || renderer) return;
  const origin = location.origin;
  const profile = weaveProfile(origin);
  const surface = document.querySelector<HTMLElement>('.product-material-shell') ?? document.body;
  surface.style.setProperty('--page-hue', String(profile.hue));
  surface.style.setProperty('--rp-hue', String(profile.hue));
  surface.style.setProperty('--grain-step', `${profile.spacing / 2}px`);
  surface.style.setProperty('--grain-angle', `${profile.grainAngle}deg`);
  renderer = createWovenGate(scene, canvas, origin, origin, 'fence');
  background.dataset['renderer'] = renderer ? 'canvas' : 'css';
}
initializeMaterial();
canvas?.addEventListener('contextlost', () => {
  renderer?.destroy();
  renderer = null;
  if (background) background.dataset['renderer'] = 'css';
});
window.addEventListener('pagehide', () => {
  renderer?.destroy();
  renderer = null;
  if (background) background.dataset['renderer'] = 'css';
});
window.addEventListener('pageshow', (event) => {
  if (event.persisted) initializeMaterial();
});
