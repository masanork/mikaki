import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseHaipIssuerSelection,
  resolveOfficialHaipFormats,
  selectOfficialHaipModules,
} from './haip-issuer-selection.ts';

test('omitted selectors preserve the legacy defaults for both formats', () => {
  const selection = parseHaipIssuerSelection([]);
  assert.deepEqual(selection, { legacyFlags: [], moduleNames: [], formats: [] });
  assert.deepEqual(resolveOfficialHaipFormats(selection.formats), ['sd_jwt_vc', 'mdoc']);
});

test('legacy --positive retains its old selection mode and both-format default', () => {
  const selection = parseHaipIssuerSelection(['--positive']);
  assert.deepEqual(selection, { legacyFlags: ['--positive'], moduleNames: [], formats: [] });
  assert.deepEqual(resolveOfficialHaipFormats(selection.formats), ['sd_jwt_vc', 'mdoc']);
});

test('targeted modules are validated and preserve official plan ordering', () => {
  const selection = parseHaipIssuerSelection([
    '--module=oid4vci-1_0-issuer-case-b',
    '--module=oid4vci-1_0-issuer-case-a',
  ]);
  const available = [
    { testModule: 'oid4vci-1_0-issuer-case-a' },
    { testModule: 'oid4vci-1_0-issuer-case-b' },
    { testModule: 'oid4vci-1_0-issuer-case-c' },
  ];
  assert.deepEqual(selection.moduleNames, [
    'oid4vci-1_0-issuer-case-b',
    'oid4vci-1_0-issuer-case-a',
  ]);
  assert.deepEqual(selectOfficialHaipModules(available, selection.moduleNames), [
    { testModule: 'oid4vci-1_0-issuer-case-a' },
    { testModule: 'oid4vci-1_0-issuer-case-b' },
  ]);
});

test('each official format can be selected independently', () => {
  assert.deepEqual(
    resolveOfficialHaipFormats(parseHaipIssuerSelection(['--format=sd_jwt_vc']).formats),
    ['sd_jwt_vc'],
  );
  assert.deepEqual(
    resolveOfficialHaipFormats(parseHaipIssuerSelection(['--format=mdoc']).formats),
    ['mdoc'],
  );
});

test('unknown, duplicate, empty, and conflicting selectors fail closed', () => {
  assert.throws(() => parseHaipIssuerSelection(['--format=unsupported']), /Unsupported --format/);
  assert.throws(() => parseHaipIssuerSelection(['--format=mdoc', '--format=mdoc']), /Duplicate/);
  assert.throws(
    () =>
      parseHaipIssuerSelection([
        '--module=oid4vci-1_0-issuer-case-a',
        '--module=oid4vci-1_0-issuer-case-a',
      ]),
    /Duplicate/,
  );
  assert.throws(() => parseHaipIssuerSelection(['--module=']), /Invalid/);
  assert.throws(() => parseHaipIssuerSelection(['--module=../token']), /Invalid/);
  assert.throws(() => parseHaipIssuerSelection(['--unknown']), /Unsupported/);
  assert.throws(
    () => parseHaipIssuerSelection(['--module=oid4vci-1_0-issuer-case-a', '--positive']),
    /cannot be combined/,
  );
  assert.throws(
    () =>
      selectOfficialHaipModules(
        [{ testModule: 'oid4vci-1_0-issuer-case-a' }],
        ['oid4vci-1_0-issuer-missing'],
      ),
    /not found/,
  );
});
