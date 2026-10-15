import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

export function preparePasskeySigning() {
  const profilePath = process.env.MIKAKI_MACOS_PROVISIONING_PROFILE;
  const identity = process.env.APPLE_SIGNING_IDENTITY?.trim();
  if (!profilePath || !identity || identity === '-') {
    throw new Error(
      'Passkeys require MIKAKI_MACOS_PROVISIONING_PROFILE and APPLE_SIGNING_IDENTITY. Personal Team/ad-hoc signing cannot enable Associated Domains.',
    );
  }
  const profile = resolve(profilePath);
  const xml = execFileSync('/usr/bin/security', ['cms', '-D', '-i', profile], { timeout: 10000 });
  const extract = (key, format = 'raw') =>
    execFileSync('/usr/bin/plutil', ['-extract', key, format, '-o', '-', '-'], {
      input: xml,
      encoding: 'utf8',
      timeout: 10000,
    }).trim();
  const entitlements = JSON.parse(extract('Entitlements', 'json'));
  const team = entitlements['com.apple.developer.team-identifier'];
  const appId = entitlements['com.apple.application-identifier'];
  const domains = entitlements['com.apple.developer.associated-domains'];
  const expires = Date.parse(extract('ExpirationDate'));
  const platforms = JSON.parse(extract('Platform', 'json'));
  const certificates = [
    ...extract('DeveloperCertificates', 'xml1').matchAll(/<data>([\s\S]*?)<\/data>/g),
  ].map((match) =>
    createHash('sha1')
      .update(Buffer.from(match[1].replace(/\s/g, ''), 'base64'))
      .digest('hex')
      .toUpperCase(),
  );
  const installed = execFileSync(
    '/usr/bin/security',
    ['find-identity', '-v', '-p', 'codesigning'],
    { encoding: 'utf8', timeout: 10000 },
  );
  const selected = [...installed.matchAll(/\b([A-F0-9]{40}) "([^"\n]+)"/g)].find(
    (match) => match[1] === identity.toUpperCase() || match[2] === identity,
  );
  if (!selected || !certificates.includes(selected[1]))
    throw new Error(
      'The signing identity must be installed and included in the provisioning profile.',
    );
  if (
    !Array.isArray(platforms) ||
    !platforms.includes('OSX') ||
    !Number.isFinite(expires) ||
    expires <= Date.now()
  )
    throw new Error('A current macOS provisioning profile is required.');
  if (!/^[A-Z0-9]{10}$/.test(team ?? '') || appId !== `${team}.app.tossa.mikaki.dev`)
    throw new Error('The profile must authorize <TEAM_ID>.app.tossa.mikaki.dev.');
  if (
    !Array.isArray(domains) ||
    !domains.some((d) => d === '*' || d === 'webcredentials:auth.mikaki.org')
  )
    throw new Error('The profile must authorize Associated Domains for auth.mikaki.org.');
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-passkey-signing-'));
  const entitlementPath = join(directory, 'Entitlements.plist');
  writeFileSync(
    entitlementPath,
    `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>com.apple.application-identifier</key><string>${appId}</string><key>com.apple.developer.team-identifier</key><string>${team}</string><key>com.apple.developer.associated-domains</key><array><string>webcredentials:auth.mikaki.org</string></array></dict></plist>`,
    { mode: 0o600 },
  );
  console.log(`Passkey signing: configure MIKAKI_APPLE_TEAM_ID=${team} on the issuer.`);
  return {
    identity: selected[1],
    config: {
      bundle: {
        macOS: {
          minimumSystemVersion: '13.3',
          signingIdentity: selected[1],
          entitlements: entitlementPath,
          files: { 'embedded.provisionprofile': profile },
        },
      },
    },
    cleanup: () => rmSync(directory, { recursive: true, force: true }),
  };
}
