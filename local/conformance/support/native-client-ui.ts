import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import type { Browser, Page } from '@playwright/test';

export interface NativeUiScenario {
  platform?: 'mobile' | 'desktop';
  signedIn?: boolean;
  preview?: boolean;
  phase?: string;
}

declare global {
  interface Window {
    __nativeUiTest: {
      phase: string;
      subject: string | null;
      attribute: string | null;
      failures: Record<string, string>;
      calls: string[];
      hold: (command: string) => void;
      release: (command: string) => void;
      complete: (phase?: string) => void;
    };
  }
}

export async function startNativeUiServer() {
  const directory = new URL('../../../apps/mikaki-client/ui/', import.meta.url);
  const config = JSON.parse(
    readFileSync(new URL('../src-tauri/tauri.conf.json', directory), 'utf8'),
  );
  const assets = new Map(
    ['index.html', 'style.css', 'app.js'].map((name) => [
      name,
      readFileSync(new URL(name, directory)),
    ]),
  );
  const server = createServer((request, response) => {
    const name = new URL(request.url ?? '/', 'http://localhost').pathname.slice(1) || 'index.html';
    const data = assets.get(name);
    if (!data) {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, {
      'Content-Type': name.endsWith('.js')
        ? 'text/javascript'
        : name.endsWith('.css')
          ? 'text/css'
          : 'text/html',
      'Content-Security-Policy': config.app.security.csp,
    });
    response.end(data);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing UI server');
  return {
    url: `http://127.0.0.1:${address.port}/`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

export async function createNativeUiPage(
  browser: Browser,
  url: string,
  scenario: NativeUiScenario = {},
) {
  const page = await browser.newPage({ viewport: { width: 375, height: 812 } });
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript((initial) => {
    const blocked = new Set<string>();
    const gates = new Map<string, Array<() => void>>();
    let generation = 0;
    const mock: Window['__nativeUiTest'] = {
      phase: initial.phase ?? (initial.signedIn ? 'complete' : 'idle'),
      subject: initial.signedIn ? 'synthetic-user' : null,
      attribute: null,
      failures: {},
      calls: [],
      hold(command) {
        blocked.add(command);
      },
      release(command) {
        blocked.delete(command);
        for (const release of gates.get(command) ?? []) release();
        gates.delete(command);
      },
      complete(phase = 'complete') {
        if (mock.phase !== 'pending' && mock.phase !== 'exchanging') return;
        mock.phase = phase;
        if (phase === 'complete') mock.subject = 'synthetic-user';
        if (phase === 'vault_complete') mock.attribute = 'owner_note';
      },
    };
    window.__nativeUiTest = mock;
    async function invoke(command: string) {
      mock.calls.push(command);
      if (mock.failures[command]) throw new Error(mock.failures[command]);
      const currentGeneration = generation;
      let result: unknown;
      switch (command) {
        case 'native_platform':
          result = initial.platform ?? 'mobile';
          break;
        case 'native_session':
          result = mock.subject ? { subject: mock.subject } : null;
          break;
        case 'mobile_auth_status':
          result = {
            phase: mock.phase,
            subject: mock.subject,
            vault_attribute: mock.attribute,
            vault_preview_available: initial.preview ?? false,
          };
          break;
        case 'start_mobile_login':
          mock.subject = null;
          mock.phase = 'pending';
          break;
        case 'start_mobile_vault_read':
          mock.attribute = null;
          mock.phase = 'pending';
          break;
        case 'start_desktop_login':
          result = { subject: 'synthetic-user' };
          break;
        case 'cancel_native_login':
          generation++;
          mock.phase = mock.subject ? 'complete' : 'idle';
          break;
        case 'clear_native_session':
          generation++;
          mock.subject = null;
          mock.attribute = null;
          mock.phase = 'idle';
          break;
        case 'check_mobile_vault_key':
          break;
        case 'read_mobile_vault_ciphertext':
          result = { revision: 1, format_version: 1 };
          break;
        default:
          throw new Error('Unknown synthetic command: ' + command);
      }
      if (blocked.has(command))
        await new Promise<void>((resolve) => {
          const queue = gates.get(command) ?? [];
          queue.push(resolve);
          gates.set(command, queue);
        });
      if (command === 'start_desktop_login' && currentGeneration === generation)
        mock.subject = 'synthetic-user';
      return result;
    }
    Object.defineProperty(window, '__TAURI__', {
      value: {
        core: { invoke },
        app: { getVersion: async () => '0.1.0', setTheme: async () => {} },
      },
    });
  }, scenario);
  await page.goto(url);
  await page.waitForFunction(
    () =>
      !document.querySelector<HTMLButtonElement>('#login')?.disabled ||
      !document.querySelector('#home')?.hasAttribute('hidden') ||
      !document.querySelector('#waiting')?.hasAttribute('hidden'),
  );
  return { page, errors };
}

export async function resumeNativeUi(page: Page) {
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
}
