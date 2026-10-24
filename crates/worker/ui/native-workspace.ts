// A fixed, origin-bound lifecycle bridge. It carries no account IDs, tokens,
// PRF output, credentials, or signer requests.
declare global {
  interface Window {
    __MIKAKI_NATIVE_SHELL__?: boolean;
    __MIKAKI_NATIVE_PAGE__?: 'chat' | 'account';
    __MIKAKI_WORKSPACE_VISIBLE__?: boolean;
    MikakiWorkspace?: { postMessage(value: string): void };
  }
}
export const nativeWorkspace = () => window.__MIKAKI_NATIVE_SHELL__ === true;
export const workspaceVisible = () =>
  document.visibilityState === 'visible' && window.__MIKAKI_WORKSPACE_VISIBLE__ !== false;
export function workspaceReady(): void {
  if (nativeWorkspace()) window.MikakiWorkspace?.postMessage('ready');
}
