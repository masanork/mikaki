export const officialHaipIssuerFormats = ['sd_jwt_vc', 'mdoc'] as const;

export type OfficialHaipIssuerFormat = (typeof officialHaipIssuerFormats)[number];

export type HaipIssuerSelection = {
  legacyFlags: string[];
  moduleNames: string[];
  formats: OfficialHaipIssuerFormat[];
};

const legacyFlags = new Set([
  '--negative',
  '--fapi',
  '--lifecycle',
  '--resource',
  '--key-attestation',
  '--encrypted',
  '--positive',
]);
const officialModuleName =
  /^(?:oid4vci-1_0-issuer|fapi2-security-profile-final)-[a-z0-9_]+(?:-[a-z0-9_]+)*$/;

export function parseHaipIssuerSelection(args: readonly string[]): HaipIssuerSelection {
  const parsed: HaipIssuerSelection = { legacyFlags: [], moduleNames: [], formats: [] };
  const modules = new Set<string>();
  const formats = new Set<OfficialHaipIssuerFormat>();

  for (const arg of args) {
    if (legacyFlags.has(arg)) {
      parsed.legacyFlags.push(arg);
      continue;
    }
    if (arg.startsWith('--module=')) {
      const moduleName = arg.slice('--module='.length);
      if (!officialModuleName.test(moduleName)) throw new Error('Invalid --module name');
      if (modules.has(moduleName)) throw new Error('Duplicate --module');
      modules.add(moduleName);
      parsed.moduleNames.push(moduleName);
      continue;
    }
    if (arg.startsWith('--format=')) {
      const format = arg.slice('--format='.length);
      if (!officialHaipIssuerFormats.includes(format as OfficialHaipIssuerFormat))
        throw new Error('Unsupported --format');
      if (formats.has(format as OfficialHaipIssuerFormat)) throw new Error('Duplicate --format');
      formats.add(format as OfficialHaipIssuerFormat);
      parsed.formats.push(format as OfficialHaipIssuerFormat);
      continue;
    }
    throw new Error(`Unsupported HAIP issuer argument: ${arg}`);
  }

  if (parsed.moduleNames.length && parsed.legacyFlags.length)
    throw new Error('--module cannot be combined with legacy selection flags');

  return parsed;
}

export function selectOfficialHaipModules<T extends { testModule: string }>(
  modules: readonly T[],
  requestedNames: readonly string[],
): T[] {
  if (requestedNames.length === 0) throw new Error('At least one official module is required');
  const available = new Set(modules.map((module) => module.testModule));
  const unknown = requestedNames.filter((name) => !available.has(name));
  if (unknown.length) throw new Error(`Official HAIP module not found: ${unknown.join(', ')}`);
  const requested = new Set(requestedNames);
  return modules.filter((module) => requested.has(module.testModule));
}

export function resolveOfficialHaipFormats(
  requestedFormats: readonly OfficialHaipIssuerFormat[],
): OfficialHaipIssuerFormat[] {
  return requestedFormats.length
    ? officialHaipIssuerFormats.filter((format) => requestedFormats.includes(format))
    : [...officialHaipIssuerFormats];
}
