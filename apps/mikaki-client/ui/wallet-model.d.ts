/** Display boundary only. Native custody and protocol validation remain authoritative. */
export interface NativeDocument {
  id: string;
  saved_at: number;
  passport_saved?: boolean;
  passport_authentication?: PassportAuthentication;
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
}
export interface PassportAuthentication {
  state: string;
  checked_data_groups: number[];
  issuer_trust: string;
  revocation?: string;
  checked_at?: number;
  valid_until?: number;
}
export interface NativeCredential {
  id: string;
  title: string;
  issuer: string;
  format: string;
  expires_at: number;
  fields: Record<string, unknown>;
}
export interface WalletReadDocument {
  id: string;
  title: string;
  subtitle: string;
  icon: string;
  theme: string;
  source: 'card_read';
  documentType: string;
  displayName: string;
  status: string;
  savedAt: number;
  passportSaved: boolean;
  passportAuthentication?: PassportAuthentication | null;
  expiry?: string | null;
  fields: Record<string, unknown>;
  presentation: { formats: []; available: false };
}
export interface WalletIssuedCredential extends NativeCredential {
  source: 'issued_credential';
  theme: string;
  icon: string;
  subtitle: string;
  displayName: string;
  presentation: { formats: string[]; available: true };
}
export const documentTypes: Readonly<
  Record<string, { title: string; subtitle: string; theme: string; icon: string }>
>;
export function walletDocument(record: NativeDocument, at?: number): WalletReadDocument;
export function passportAuthenticationNote(
  report?: PassportAuthentication | null,
  at?: number,
): string;
export function walletCredential(record: NativeCredential): WalletIssuedCredential;
