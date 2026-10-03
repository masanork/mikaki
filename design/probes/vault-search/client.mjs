let worker;
let generation = 0;
let rejectPending;
export function lock() {
  generation++;
  worker?.terminate();
  worker = undefined;
  rejectPending?.(new Error('locked'));
  rejectPending = undefined;
  document.querySelector('#result').textContent = '';
}
export async function probe(size, scope = ['human', 'ai']) {
  lock();
  const current = generation;
  worker = new Worker('/worker.mjs', { type: 'module' });
  const result = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      lock();
    }, 30000);
    const fail = (error) => {
      clearTimeout(timer);
      reject(error);
    };
    rejectPending = fail;
    worker.onerror = (event) => fail(new Error(event.message));
    worker.onmessage = ({ data }) => {
      if (current !== generation) return;
      clearTimeout(timer);
      data.error ? fail(new Error(data.error)) : resolve(data.result);
    };
    worker.postMessage({ size, scope });
  });
  if (current !== generation) throw new Error('locked');
  rejectPending = undefined;
  document.querySelector('#result').textContent = JSON.stringify(result, null, 2);
  return result;
}
document.querySelector('#lock').onclick = lock;
document.addEventListener('visibilitychange', () => {
  if (document.hidden) lock();
});
window.addEventListener('pagehide', lock);
window.probe = probe;
window.lockProbe = lock;
