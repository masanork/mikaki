/** Read-only prerequisites for the fixed-origin Android Wallet. Never logs identifiers or OAuth/card data. */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

type Check = { name: string; status: 'pass' | 'blocked'; reason?: string };
type Options = {
  sdk: string;
  online?: boolean;
  apk?: string;
  configuration?: string;
  serial?: string;
};
type Dependencies = {
  run(command: string, args: string[], input?: string): string;
  read(path: string): Buffer;
  list(path: string): string[];
  fetch: typeof fetch;
};
const defaults: Dependencies = {
  run: (command, args, input) =>
    execFileSync(command, args, {
      encoding: 'utf8',
      input,
      timeout: 60000,
      maxBuffer: 256 * 1024,
      stdio: ['pipe', 'pipe', 'pipe'],
    }),
  read: readFileSync,
  list: readdirSync,
  fetch,
};
const root = 'https://auth.mikaki.org';
const callbackHost = 'https://app.mikaki.org';
export function selectDevice(output: string, serial?: string): string {
  const rows = output
    .split('\n')
    .filter((s) => s.trim() && !s.startsWith('List of devices'))
    .map((s) => s.trim().split(/\s+/));
  const choices = serial ? rows.filter((r) => r[0] === serial) : rows;
  if (!choices.length) throw new Error('device_not_connected');
  if (choices.length !== 1) throw new Error('device_ambiguous');
  if (choices[0][1] !== 'device') throw new Error('device_not_authorized_or_offline');
  return choices[0][0];
}
export function verifiedLinks(output: string): boolean {
  if (
    !/^\s*app\.mikaki\.org:\s*verified\s*$/m.test(output) ||
    !/^\s*Verification link handling allowed:\s*true\s*$/m.test(output)
  )
    return false;
  const disabled = output.split(/\bDisabled:\s*\n/)[1];
  return !disabled || !disabled.split(/\n\s*\w[^\n]*:/)[0].includes('app.mikaki.org');
}
export async function walletDevicePreflight(options: Options, deps: Dependencies = defaults) {
  const checks: Check[] = [];
  const pass = (name: string) => checks.push({ name, status: 'pass' });
  const blocked = (name: string, reason: string) =>
    checks.push({ name, status: 'blocked', reason });
  const publicGet = async (url: string, limit: number, json = true) => {
    const response = await deps.fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(6000),
      headers: { Accept: json ? 'application/json' : 'text/html' },
    });
    if (response.status !== 200) {
      await response.body?.cancel();
      throw new Error(`public_endpoint_http_${response.status}`);
    }
    if (
      json &&
      response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !==
        'application/json'
    ) {
      await response.body?.cancel();
      throw new Error('public_endpoint_unavailable');
    }
    const chunks: Uint8Array[] = [];
    let size = 0;
    if (!response.body) throw new Error('empty_response');
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > limit) {
        throw new Error('oversized_response');
      }
      chunks.push(chunk);
    }
    return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
  };
  let configuration: string | undefined;
  if (options.configuration) {
    try {
      const bytes = deps.read(options.configuration);
      if (bytes.length > 49152) throw new Error();
      configuration = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      blocked('configuration_file', 'configuration_unreadable_or_oversized');
    }
  }
  const profile: Record<string, string | undefined> = { configuration };
  let association: unknown;
  if (options.online) {
    for (const [name, url, limit] of [
      ['metadata', `${root}/.well-known/openid-credential-issuer/identity/issuer`, 49152],
      ['oauth', `${root}/.well-known/oauth-authorization-server/identity/issuer`, 16384],
      ['jwks', `${root}/identity/issuer/jwks`, 8192],
    ] as const) {
      try {
        profile[name] = await publicGet(url, limit);
        pass(`public_${name}`);
      } catch (error) {
        blocked(
          `public_${name}`,
          error instanceof Error && /^public_endpoint_http_\d{3}$/.test(error.message)
            ? error.message
            : 'endpoint_unavailable_or_invalid',
        );
      }
    }
    try {
      association = JSON.parse(
        await publicGet(`${callbackHost}/.well-known/assetlinks.json`, 8192),
      );
      if (!Array.isArray(association) || association.length === 0) throw new Error();
      pass('public_association');
    } catch {
      blocked('public_association', 'association_unavailable_or_invalid');
    }
    try {
      // No query/code/state and no browser redirect follow. Probe callback-host isolation only.
      const response = await deps.fetch(`${callbackHost}/identity/issuance/callback`, {
        redirect: 'manual',
        signal: AbortSignal.timeout(6000),
      });
      await response.body?.cancel();
      if (
        response.status !== 303 ||
        response.headers.get('location') !== '/native-link-help' ||
        !/\bno-store\b/.test(response.headers.get('cache-control') ?? '') ||
        response.headers.get('referrer-policy') !== 'no-referrer'
      )
        throw new Error();
      pass('callback_fallback');
    } catch {
      blocked('callback_fallback', 'callback_route_or_isolation_unqualified');
    }
  } else {
    blocked('public_endpoints', 'online_check_not_requested');
  }
  try {
    const result = JSON.parse(
      deps.run(
        'cargo',
        [
          'run',
          '--quiet',
          '-p',
          'mikaki-identity',
          '--example',
          'wallet_device_preflight',
          '--locked',
          '--offline',
        ],
        JSON.stringify(profile),
      ),
    );
    if (!Array.isArray(result.checks) || result.checks.length !== 5) throw new Error();
    for (const c of result.checks) {
      if (
        typeof c.name !== 'string' ||
        !['pass', 'blocked'].includes(c.status) ||
        (c.reason !== undefined && typeof c.reason !== 'string')
      )
        throw new Error();
      checks.push(c);
    }
  } catch {
    blocked('native_profile', 'profile_validation_failed');
  }
  let artifact: { sha256: string; signing_fingerprint: string } | undefined;
  if (options.apk) {
    try {
      const version = deps
        .list(join(options.sdk, 'build-tools'))
        .filter((s) => /^\d+\.\d+\.\d+$/.test(s))
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
        .at(-1);
      if (!version) throw new Error();
      const output = deps.run(join(options.sdk, 'build-tools', version, 'apksigner'), [
        'verify',
        '--print-certs',
        options.apk,
      ]);
      const fingerprints = [
        ...output.matchAll(/^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]{64})\s*$/gim),
      ];
      if (fingerprints.length !== 1) throw new Error();
      const fingerprint = fingerprints[0][1].toUpperCase().match(/../g)!.join(':');
      const id = deps.run(join(options.sdk, 'cmdline-tools', 'latest', 'bin', 'apkanalyzer'), [
        'manifest',
        'application-id',
        options.apk,
      ]);
      if (id.trim() !== 'app.tossa.mikaki') throw new Error();
      const apk = deps.read(options.apk);
      artifact = {
        sha256: createHash('sha256').update(apk).digest('hex'),
        signing_fingerprint: fingerprint,
      };
      pass('apk_signature_and_package');
      if (
        !Array.isArray(association) ||
        !association.some(
          (a) =>
            Array.isArray(a.relation) &&
            a.relation.includes('delegate_permission/common.handle_all_urls') &&
            a.target?.namespace === 'android_app' &&
            a.target?.package_name === 'app.tossa.mikaki' &&
            Array.isArray(a.target?.sha256_cert_fingerprints) &&
            a.target.sha256_cert_fingerprints.includes(fingerprint),
        )
      )
        throw new Error('association_mismatch');
      pass('apk_association');
    } catch {
      blocked('apk_association', 'apk_signature_package_or_association_unqualified');
    }
  } else {
    blocked('apk', 'apk_not_supplied');
  }
  let deviceStage = 'android_device';
  let deviceReason = 'adb_unavailable';
  try {
    const adb = join(options.sdk, 'platform-tools', 'adb');
    const devices = deps.run(adb, ['devices', '-l']);
    deviceReason = 'device_unavailable_or_ambiguous';
    const serial = selectDevice(devices, options.serial);
    pass('android_device');
    const prefix = ['-s', serial, 'shell'];
    deviceStage = 'installed_package';
    deviceReason = 'package_missing_or_unreadable';
    const paths = deps
      .run(adb, [...prefix, 'pm', 'path', 'app.tossa.mikaki'])
      .trim()
      .split(/\r?\n/);
    // Restrict every character passed through adb shell; never report device paths.
    if (
      !paths.length ||
      paths.some((p) => !/^package:\/data\/app\/[A-Za-z0-9_+/=.-]+\.apk$/.test(p))
    )
      throw new Error();
    pass('installed_package');
    deviceStage = 'installed_artifact';
    deviceReason = 'selected_apk_not_verified';
    if (!artifact) throw new Error();
    deviceReason = 'installed_split_apks_require_separate_qualification';
    if (paths.length !== 1) throw new Error();
    deviceReason = 'installed_apk_hash_unavailable';
    const installedPath = paths[0].slice('package:'.length);
    const digest = deps.run(adb, [...prefix, 'sha256sum', installedPath]).trim();
    const match = /^([0-9a-f]{64})\s+(.+)$/i.exec(digest);
    if (!match || match[2] !== installedPath) throw new Error();
    deviceReason = 'installed_apk_differs_from_selected_artifact';
    if (match[1].toLowerCase() !== artifact.sha256) throw new Error();
    pass('installed_artifact');
    deviceStage = 'device_app_links';
    deviceReason = 'app_links_unverified_or_disabled';
    if (
      !verifiedLinks(
        deps.run(adb, [...prefix, 'pm', 'get-app-links', '--user', '0', 'app.tossa.mikaki']),
      )
    )
      throw new Error();
    pass('device_app_links');
  } catch (error) {
    const reason =
      error instanceof Error &&
      ['device_not_connected', 'device_ambiguous', 'device_not_authorized_or_offline'].includes(
        error.message,
      )
        ? error.message
        : deviceReason;
    blocked(deviceStage, reason);
  }
  return {
    version: 1,
    observed_at: new Date().toISOString(),
    prerequisites_ready: checks.every((c) => c.status === 'pass'),
    qualification: 'not_run',
    checks,
    ...(artifact ? { artifact } : {}),
  };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const { values } = parseArgs({
    options: {
      online: { type: 'boolean' },
      apk: { type: 'string' },
      'wallet-config': { type: 'string' },
      sdk: { type: 'string' },
      serial: { type: 'string' },
      report: { type: 'string' },
    },
  });
  const report = await walletDevicePreflight({
    sdk: values.sdk ?? process.env.ANDROID_HOME ?? join(homedir(), 'Library/Android/sdk'),
    online: values.online,
    apk: values.apk,
    configuration: values['wallet-config'],
    serial: values.serial,
  });
  console.log(JSON.stringify(report, null, 2));
  if (values.report) writeFileSync(values.report, JSON.stringify(report, null, 2) + '\n');
  process.exitCode = report.prerequisites_ready ? 0 : 1;
}
