import { createWovenGate, weaveProfile } from '../crates/worker/ui/woven-gate';
const scene = document.querySelector<HTMLElement>('.scene');
const canvas = document.querySelector<HTMLCanvasElement>('canvas');
if (scene && canvas) {
  const profile = weaveProfile(location.origin);
  scene.style.setProperty('--hue', String(profile.hue));
  scene.style.setProperty('--step', `${profile.spacing / 2}px`);
  scene.style.setProperty('--angle', `${profile.grainAngle}deg`);
  let renderer: ReturnType<typeof createWovenGate> = null;
  const initialize = () => {
    renderer = createWovenGate(scene, canvas, location.origin, location.origin, 'fence');
    scene.dataset['renderer'] = renderer ? 'canvas' : 'css';
  };
  initialize();
  const dispose = () => {
    renderer?.destroy();
    renderer = null;
    scene.dataset['renderer'] = 'css';
  };
  canvas.addEventListener('contextlost', dispose);
  addEventListener('pagehide', dispose);
  addEventListener('pageshow', (event) => {
    if (event.persisted) initialize();
  });
}
