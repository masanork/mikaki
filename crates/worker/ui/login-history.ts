// A local recognition aid, never an authorization grant or proof of authenticity.
export const LOGIN_HISTORY_KEY = 'mikaki.login-history.v1';
const MAX_RECORDS = 32;

export interface LoginConnection {
  issuer: string;
  client: string;
  destination: string;
  scope: string;
}

export interface LoginRecord extends LoginConnection {
  credential: string;
  last: number;
}

export interface LoginHistory {
  available: boolean;
  records: LoginRecord[];
}

export type LoginRecognition = {
  kind: 'first' | 'known' | 'changed' | 'unavailable';
  previous?: LoginRecord;
};

export function loginDestination(uri: string): string {
  const url = new URL(uri);
  // Private-use app schemes have an opaque origin. Keep their registered URI
  // visible and distinct instead of collapsing unrelated apps to "null".
  if (url.origin !== 'null') return url.origin;
  url.search = '';
  url.hash = '';
  return url.href;
}

export function loginScope(scope: string): string {
  return [...new Set(scope.split(/\s+/).filter(Boolean))].sort().join(' ');
}

function isRecord(value: unknown): value is LoginRecord {
  if (!value || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  return (
    ['issuer', 'client', 'destination', 'scope'].every(
      (key) => typeof record[key] === 'string' && record[key].length <= 2048,
    ) &&
    typeof record['credential'] === 'string' &&
    /^[a-f0-9]{64}$/.test(record['credential']) &&
    typeof record['last'] === 'number' &&
    Number.isSafeInteger(record['last']) &&
    record['last'] > 0 &&
    record['last'] <= Date.now() + 60_000
  );
}

export function readLoginHistory(storage: Pick<Storage, 'getItem'>): LoginHistory {
  try {
    const raw = storage.getItem(LOGIN_HISTORY_KEY);
    if (raw === null) return { available: true, records: [] };
    if (raw.length > 65_536) throw new Error('Oversized history');
    const data: unknown = JSON.parse(raw);
    if (
      !data ||
      typeof data !== 'object' ||
      !('version' in data) ||
      data.version !== 1 ||
      !('records' in data) ||
      !Array.isArray(data.records) ||
      data.records.length > MAX_RECORDS ||
      !data.records.every(isRecord)
    )
      throw new Error('Invalid history');
    return { available: true, records: data.records.sort((a, b) => b.last - a.last) };
  } catch {
    return { available: false, records: [] };
  }
}

export function recognizeLogin(
  history: LoginHistory,
  connection: LoginConnection,
  credential?: string,
): LoginRecognition {
  if (!history.available) return { kind: 'unavailable' };
  const previous = history.records.find(
    (record) =>
      record.issuer === connection.issuer &&
      record.client === connection.client &&
      (credential === undefined || record.credential === credential),
  );
  if (!previous) return { kind: 'first' };
  return {
    kind:
      previous.destination === connection.destination && previous.scope === connection.scope
        ? 'known'
        : 'changed',
    previous,
  };
}

export async function loginCredential(issuer: string, id: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`mikaki-login-history-v1\0${issuer}\0${id}`),
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

// Call only after the finish endpoint accepts the ceremony. Merge the current
// snapshot to retain other tabs' recent entries when possible; this is not a CAS.
export function rememberLogin(
  storage: Pick<Storage, 'getItem' | 'setItem'>,
  connection: LoginConnection,
  credential: string,
): boolean {
  try {
    const records = readLoginHistory(storage).records.filter(
      (record) =>
        record.issuer !== connection.issuer ||
        record.client !== connection.client ||
        record.credential !== credential,
    );
    records.unshift({ ...connection, credential, last: Date.now() });
    records.splice(MAX_RECORDS);
    let raw = JSON.stringify({ version: 1, records });
    while (raw.length > 65_536 && records.length > 1) {
      records.pop();
      raw = JSON.stringify({ version: 1, records });
    }
    if (!isRecord(records[0]) || raw.length > 65_536) return false;
    storage.setItem(LOGIN_HISTORY_KEY, raw);
    return true;
  } catch {
    return false;
  }
}
