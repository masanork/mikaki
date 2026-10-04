import { createWovenGate, weaveProfile } from '../crates/worker/ui/woven-gate';
const scene = document.querySelector<HTMLElement>('.scene');
const canvas = scene?.querySelector<HTMLCanvasElement>('canvas');
const control = scene?.querySelector<HTMLButtonElement>('.motion-control');
if (scene && canvas) {
  const profile = weaveProfile(location.origin);
  scene.style.setProperty('--hue', String(profile.hue));
  scene.style.setProperty('--step', `${profile.spacing / 2}px`);
  scene.style.setProperty('--angle', `${profile.grainAngle}deg`);
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  let paused = false;
  try {
    paused = sessionStorage.getItem('mikaki-site-motion') === 'paused';
  } catch {
    // Storage may be unavailable; the current-page control still works.
  }
  let renderer: ReturnType<typeof createWovenGate> = null;
  const update = () => {
    renderer?.pause(paused || reduced.matches);
    if (control) {
      control.hidden = !renderer;
      control.disabled = reduced.matches;
      control.setAttribute('aria-pressed', String(paused || reduced.matches));
      control.textContent = control.dataset['pauseLabel'] ?? '';
      if (reduced.matches)
        control.textContent +=
          document.documentElement.lang === 'ja' ? '（端末設定）' : ' (device setting)';
    }
  };
  const initialize = () => {
    renderer = createWovenGate(scene, canvas, location.origin, location.origin, 'fence');
    scene.dataset['renderer'] = renderer ? 'canvas' : 'css';
    update();
  };
  control?.addEventListener('click', () => {
    paused = !paused;
    try {
      sessionStorage.setItem('mikaki-site-motion', paused ? 'paused' : 'playing');
    } catch {
      // No persistence is required for pausing.
    }
    update();
  });
  reduced.addEventListener('change', update);
  initialize();
  const dispose = () => {
    renderer?.destroy();
    renderer = null;
    scene.dataset['renderer'] = 'css';
    update();
  };
  canvas.addEventListener('contextlost', dispose);
  addEventListener('pagehide', dispose);
  addEventListener('pageshow', (event) => {
    if (event.persisted) initialize();
  });
}
