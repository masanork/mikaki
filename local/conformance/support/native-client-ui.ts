import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import type { Browser, Page } from '@playwright/test';

export interface NativeUiScenario {
  platform?: 'mobile' | 'desktop';
  signedIn?: boolean;
  phase?: string;
  identityReader?: boolean;
  identityWallet?: boolean;
  passportIssuance?: boolean;
  passportHaip?: boolean;
  identityWalletPhase?: string;
  identityInvocation?: boolean;
  identityCompletion?: string;
  identityFormat?: string;
  identityNoClaims?: boolean;
  identityBatch?: boolean;
  identityAge?: boolean;
  identityAgeValue?: boolean;
  identityAgeDocument?: string;
  identityAgeSingleUse?: boolean;
  identityDocuments?: Array<{
    id: string;
    saved_at: number;
    passport?: { document_number: string; mrz: string };
    passport_authentication?: NativeUiScenario['identityPassportAuthentication'];
    preview: {
      name: string;
      address: string;
      birth_date: string;
      gender: string;
      verification: string;
      document_type: string;
      expiry_date?: string | null;
      backend_verifiable: boolean;
    };
  }>;
  identityInventory?: Array<{
    id: string;
    title: string;
    issuer: string;
    format: string;
    expires_at: number;
    fields: Record<string, string>;
  }>;
  identityFailure?: { code: string; remaining_retries?: number };
  identityPassportAuthentication?: {
    state: string;
    checked_data_groups: number[];
    issuer_trust: string;
    revocation?: string;
    checked_at?: number;
    valid_until?: number;
  };
}

declare global {
  interface Window {
    __nativeUiTest: {
      phase: string;
      subject: string | null;
      failures: Record<string, string>;
      calls: string[];
      arguments: { command: string; args?: Record<string, unknown> }[];
      hold: (command: string) => void;
      release: (command: string) => void;
      emit: (event: string, payload: string) => void;
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
    ['index.html', 'style.css', 'app.js', 'wallet-model.js', 'brand-icon.svg'].map((name) => [
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
          : name.endsWith('.svg')
            ? 'image/svg+xml'
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
  const context = await browser.newContext({ viewport: { width: 375, height: 812 } });
  const page = await context.newPage();
  page.setDefaultTimeout(10_000);
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.stack ?? error.message));
  await page.addInitScript((initial) => {
    const blocked = new Set<string>();
    const gates = new Map<string, Array<() => void>>();
    let generation = 0;
    let invocation: string | null = initial.identityInvocation ? 'fixture-invocation' : null;
    let walletPhase = initial.identityWalletPhase ?? 'idle';
    let pendingRead: NonNullable<NativeUiScenario['identityDocuments']>[number]['preview'] | null =
      null;
    let pendingPassport: { document_number: string; mrz: string } | null = null;
    let documents = initial.identityDocuments ?? [];
    let eventChannel: { onmessage?: (e: { event: string; id?: string }) => void } | undefined;
    const mock: Window['__nativeUiTest'] = {
      phase: initial.phase ?? (initial.signedIn ? 'complete' : 'idle'),
      subject: initial.signedIn ? 'synthetic-user' : null,
      failures: {},
      calls: [],
      arguments: [],
      hold(command) {
        blocked.add(command);
      },
      release(command) {
        blocked.delete(command);
        for (const release of gates.get(command) ?? []) release();
        gates.delete(command);
      },
      emit(event, payload) {
        if (event === 'identity-issuance-updated') walletPhase = payload;
        if (event === 'identity-presentation-ready') invocation = payload;
        if (['identity-presentation-ready', 'identity-issuance-updated'].includes(event))
          eventChannel?.onmessage?.({ event });
        else if (event === 'identity-proximity-ended')
          eventChannel?.onmessage?.({ event, id: payload });
      },
      complete(phase = 'complete') {
        if (mock.phase !== 'pending' && mock.phase !== 'exchanging') return;
        mock.phase = phase;
        if (phase === 'complete') mock.subject = 'synthetic-user';
      },
    };
    window.__nativeUiTest = mock;
    async function invoke(command: string, args?: Record<string, unknown>) {
      mock.calls.push(command);
      mock.arguments.push({ command, args });
      if (mock.failures[command]) throw new Error(mock.failures[command]);
      const currentGeneration = generation;
      let result: unknown;
      switch (command) {
        case 'identity_wallet_issuance_status':
          result = { available: initial.identityWallet ?? false, phase: walletPhase };
          break;
        case 'start_identity_wallet_issuance':
          walletPhase = 'pending';
          result = { available: true, phase: 'pending' };
          break;
        case 'cancel_identity_wallet_issuance':
          walletPhase = 'cancelled';
          break;
        case 'receive_identity_wallet_credential':
          result =
            walletPhase === 'pending'
              ? { state: 'pending' }
              : {
                  state: 'received',
                  credential_count:
                    mock.arguments
                      .slice()
                      .reverse()
                      .find((c) => c.command === 'start_identity_wallet_issuance')?.args
                      ?.credentialCount ?? 1,
                  format: initial.identityFormat ?? 'dc+sd-jwt',
                  expires_at: Math.floor(Date.now() / 1000) + 300,
                };
          if (walletPhase === 'ready') walletPhase = 'received';
          break;
        case 'subscribe_identity_updates':
          eventChannel = args?.onEvent as typeof eventChannel;
          break;
        case 'identity_wallet_inventory':
          result = initial.identityInventory ?? [];
          break;
        case 'identity_reader_supported':
          result = initial.identityReader ?? false;
          break;
        case 'read_identity_card':
          pendingPassport = null;
          if (initial.identityFailure) throw initial.identityFailure;
          result = {
            name: '試験 太郎',
            address: '東京都',
            birth_date: '1990-02-28',
            gender: '1',
            verification: 'unverified',
            document_type: args?.documentType ?? 'my_number_card',
            expiry_date: args?.documentType === 'driving_license' ? '2030-01-01' : null,
            backend_verifiable: args?.documentType !== 'driving_license' || !!args?.pin2,
          };
          pendingRead = result as typeof pendingRead;
          break;
        case 'read_identity_passport':
          if (initial.identityFailure) throw initial.identityFailure;
          result = {
            name: 'ERIKSSON ANNA MARIA',
            address: '',
            birth_date: args?.birthDate,
            gender: '2',
            verification: 'unverified',
            document_type: 'passport',
            expiry_date: args?.expiryDate,
            backend_verifiable: false,
            passport_authentication: initial.identityPassportAuthentication,
          };
          {
            const { passport_authentication: _report, ...preview } = result as Record<
              string,
              unknown
            >;
            pendingRead = preview as typeof pendingRead;
          }
          {
            const digit = (field: string) =>
              String(
                [...field].reduce(
                  (sum, c, i) =>
                    sum +
                    (c === '<' ? 0 : c >= 'A' ? c.charCodeAt(0) - 55 : Number(c)) *
                      [7, 3, 1][i % 3],
                  0,
                ) % 10,
              );
            const number = String(args?.documentNumber),
              n = number.padEnd(9, '<');
            const b = String(args?.birthDate).replaceAll('-', '').slice(2),
              e = String(args?.expiryDate).replaceAll('-', '').slice(2);
            const line =
              n + digit(n) + 'UTO' + b + digit(b) + 'F' + e + digit(e) + '<'.repeat(14) + '0';
            pendingPassport = {
              document_number: number,
              mrz:
                'P<UTOERIKSSON<<ANNA<MARIA'.padEnd(44, '<') +
                line +
                digit(line.slice(0, 10) + line.slice(13, 20) + line.slice(21, 43)),
            };
          }
          break;
        case 'passport_issuance_available':
          result = initial.passportIssuance ?? false;
          break;
        case 'review_passport_issuance':
          result = {
            review_id: 'fixture-passport-review',
            issuer: 'https://auth.mikaki.org/identity/issuer',
            holder_thumbprint: 'fixture-passport-holder',
            claims: {
              name_mrz: 'ERIKSSON ANNA MARIA',
              issuing_state: 'UTO',
              nationality: 'UTO',
              birth_date_mrz: '690806',
              expiry_date_mrz: '940623',
              sex_mrz: 'F',
            },
            expires_at: Math.floor(Date.now() / 1000) + 300,
          };
          break;
        case 'confirm_passport_issuance':
          result = args?.approve
            ? {
                holder_thumbprint: 'fixture-passport-holder',
                expires_in: 600,
                haip: initial.passportHaip ?? false,
              }
            : null;
          if (initial.passportHaip && args?.approve) walletPhase = 'pending';
          break;
        case 'cancel_passport_issuance_review':
          break;
        case 'start_identity_link':
          result = {
            holder_thumbprint: 'synthetic-holder-key',
            holder_thumbprints: Array.from(
              { length: Number(args?.credentialCount ?? 1) },
              (_, i) => `synthetic-holder-key-${i + 1}`,
            ),
            credential_count: args?.credentialCount ?? 1,
            expires_in: 600,
          };
          break;
        case 'receive_identity_credential':
          result = {
            state: 'received',
            credential_count:
              mock.arguments
                .slice()
                .reverse()
                .find((c) => c.command === 'start_identity_link')?.args?.credentialCount ?? 1,
            format: initial.identityFormat ?? 'dc+sd-jwt',
            expires_at: Math.floor(Date.now() / 1000) + 300,
          };
          break;
        case 'start_identity_proximity':
          result = {
            session_id: 'fixture-proximity',
            engagement: args?.engagement ?? 'qr',
            qr_modules: Array.from({ length: 21 }, () => Array(21).fill(true)),
            expires_at: Math.floor(Date.now() / 1000) + 120,
          };
          break;
        case 'review_identity_proximity':
          result = {
            review_id: 'fixture-proximity-review',
            reader_name: '試験読み手',
            values: initial.identityAge
              ? { age_over_18: initial.identityAgeValue ?? true }
              : { name: '試験 太郎', birthdate: '1990-02-28' },
            ...(initial.identityAge
              ? {
                  source: {
                    document_type: initial.identityAgeDocument ?? 'my_number_card',
                    predicate_source: 'birthdate',
                    single_use: initial.identityAgeSingleUse ?? true,
                  },
                }
              : {}),
            retained_fields: ['name'],
            expires_at: Math.floor(Date.now() / 1000) + 120,
          };
          break;
        case 'confirm_identity_proximity':
          result = { state: args?.approve ? 'presented' : 'denied' };
          break;
        case 'cancel_identity_proximity':
          break;
        case 'pending_identity_invocation':
          result = invocation;
          break;
        case 'cancel_identity_presentation':
          break;
        case 'review_identity_invocation':
          invocation = null;
        // Both commands return the same native-validated consent description.
        case 'review_identity_presentation':
          result = {
            ...(initial.identityBatch
              ? {
                  credentials: [
                    {
                      query_id: 'name',
                      format: 'dc+sd-jwt',
                      values: { name: '試験 太郎' },
                      retained_fields: [],
                    },
                    {
                      query_id: 'birth',
                      format: 'mso_mdoc',
                      values: { birthdate: '1990-02-28' },
                      retained_fields: ['birthdate'],
                    },
                  ],
                }
              : {}),
            review_id: 'fixture-review',
            verifier_name: '試験提示先',
            response_uri: 'https://verifier.example/response',
            values: initial.identityNoClaims
              ? {}
              : initial.identityAge
                ? { age_over_18: initial.identityAgeValue ?? true }
                : { name: '試験 太郎', birthdate: '1990-02-28' },
            ...(initial.identityAge
              ? {
                  source: {
                    document_type: initial.identityAgeDocument ?? 'my_number_card',
                    predicate_source: 'birthdate',
                    single_use: initial.identityAgeSingleUse ?? true,
                  },
                }
              : {}),
            retained_fields:
              !initial.identityNoClaims && initial.identityFormat === 'mso_mdoc' ? ['name'] : [],
            expires_at: Math.floor(Date.now() / 1000) + 120,
          };
          break;
        case 'confirm_identity_presentation':
          result = {
            state: args?.approve ? 'presented' : 'denied',
            completion: initial.identityCompletion ?? 'not_requested',
          };
          break;
        case 'identity_document_inventory':
          result = {
            documents: documents.map(({ passport, ...summary }) => ({
              ...summary,
              passport_saved: !!passport,
              ...(summary.preview.document_type === 'passport' &&
              initial.identityPassportAuthentication
                ? { passport_authentication: initial.identityPassportAuthentication }
                : {}),
            })),
            storage: 'device_encrypted',
          };
          break;
        case 'identity_passport_details': {
          const d = documents.find((d) => d.id === 'passport');
          if (!mock.subject || !d?.passport) throw Error('passport_details_unavailable');
          result = {
            ...d.passport,
            birth_date: d.preview.birth_date,
            expiry_date: d.preview.expiry_date,
          };
          break;
        }
        case 'save_identity_document':
          if (!pendingRead) throw Error('read_required');
          documents = documents.filter((d) => d.id !== pendingRead?.document_type);
          documents.push({
            id: pendingRead.document_type,
            saved_at: Math.floor(Date.now() / 1000),
            preview: pendingRead,
            ...(pendingPassport ? { passport: pendingPassport } : {}),
          });
          pendingRead = null;
          pendingPassport = null;
          break;
        case 'remove_identity_document':
          documents = documents.filter((d) => d.id !== args?.documentId);
          break;
        case 'identity_wallet_inventory':
          result = initial.identityInventory ?? [];
          break;
        case 'open_product_chat':
          break;
        case 'identity_credential_status':
          result = { state: 'empty' };
          break;
        case 'clear_identity_evidence':
        case 'clear_identity_credential':
        case 'cancel_identity_card':
          pendingRead = null;
          pendingPassport = null;
          break;
        case 'open_mikaki_web':
          break;
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
          };
          break;
        case 'start_mobile_login':
          mock.subject = null;
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
          mock.phase = 'idle';
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
        core: {
          invoke,
          Channel: class {
            onmessage?: (e: { event: string; id?: string }) => void;
          },
        },
        event: {
          listen: async () => {
            throw Error('Generic event listening denied');
          },
        },
        app: { getVersion: async () => '0.1.0', setTheme: async () => {} },
      },
    });
  }, scenario);
  await page.goto(url);
  await page
    .locator('.screen:not([hidden])')
    .first()
    .waitFor({ state: 'visible' })
    .catch((error) => {
      throw new Error('Native UI did not start: ' + errors.join('; '), { cause: error });
    });
  await page.waitForFunction(() => window.__nativeUiTest.calls.includes('native_platform'));
  return { page, errors };
}

export async function resumeNativeUi(page: Page) {
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
}
