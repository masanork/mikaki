// Android can deliver a completed Credential Manager result before onResume.
// Keep that result in this document until the selected workspace is foreground.
(() => {
  'use strict';
  window.__MIKAKI_WORKSPACE_SELECTED__ = true;
  const prototype = window.CredentialsContainer?.prototype;
  const descriptor = prototype && Object.getOwnPropertyDescriptor(prototype, 'get');
  if (!descriptor || typeof descriptor.value !== 'function') return;
  const original = descriptor.value;
  const foreground = () =>
    document.visibilityState === 'visible' &&
    window.__MIKAKI_WORKSPACE_SELECTED__ === true &&
    window.__MIKAKI_WORKSPACE_VISIBLE__ === true;
  const cancelled = () => new DOMException('Passkey return was cancelled', 'NotAllowedError');
  function discard(credential) {
    // No PRF output crosses the native bridge, a URL, storage or another document.
    try {
      const results = credential.getClientExtensionResults().prf?.results;
      for (const buffer of new Set([results?.first, results?.second]))
        if (buffer instanceof ArrayBuffer) new Uint8Array(buffer).fill(0);
    } catch {
      // A missing extension cannot grant access to an owner key.
    }
  }
  function returned(credential, signal) {
    if (signal?.aborted || window.__MIKAKI_WORKSPACE_SELECTED__ !== true) {
      discard(credential);
      throw signal?.aborted ? signal.reason : cancelled();
    }
    if (foreground()) return credential;
    return new Promise((resolve, reject) => {
      let finished = false;
      let timer;
      const cleanup = () => {
        clearTimeout(timer);
        document.removeEventListener('visibilitychange', visibility);
        window.removeEventListener('mikaki-workspace-visibility', activity);
        window.removeEventListener('pagehide', pagehide);
        signal?.removeEventListener('abort', aborted);
      };
      const fail = (error) => {
        if (finished) return;
        finished = true;
        cleanup();
        discard(credential);
        reject(error);
      };
      const activity = () => {
        if (window.__MIKAKI_WORKSPACE_SELECTED__ !== true) fail(cancelled());
        else if (foreground() && !finished) {
          finished = true;
          cleanup();
          resolve(credential);
        }
      };
      const visibility = () => {
        if (document.visibilityState === 'hidden') fail(cancelled());
        else activity();
      };
      const pagehide = () => fail(cancelled());
      const aborted = () => fail(signal.reason);
      document.addEventListener('visibilitychange', visibility);
      window.addEventListener('mikaki-workspace-visibility', activity);
      window.addEventListener('pagehide', pagehide);
      signal?.addEventListener('abort', aborted, { once: true });
      // Only the completion of an already requested platform ceremony can wait.
      // No event can extend this deadline or retain a result for a later visit.
      timer = setTimeout(() => fail(cancelled()), 1000);
      activity();
    });
  }
  Object.defineProperty(prototype, 'get', {
    ...descriptor,
    value: function get(options, ...extra) {
      const result = Reflect.apply(original, this, [options, ...extra]);
      return Promise.resolve(result).then((credential) => {
        if (
          typeof window.PublicKeyCredential !== 'function' ||
          !(credential instanceof window.PublicKeyCredential)
        )
          return credential;
        return returned(credential, options?.signal);
      });
    },
  });
})();
