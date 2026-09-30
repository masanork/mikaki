import { getContext } from 'svelte';
import type { VaultScope } from './vault-lifecycle.js';
export const VAULT_CONTEXT = Symbol('Vault lifecycle');
export type VaultContext = {
  current: () => VaultScope;
  registerDraft: (dirty: () => boolean) => () => void;
  lock: () => void;
};
export function vaultContext(): VaultContext {
  return getContext<VaultContext>(VAULT_CONTEXT);
}
export function vaultScope(): VaultScope {
  return vaultContext().current();
}
