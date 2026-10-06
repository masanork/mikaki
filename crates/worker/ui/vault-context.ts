import { getContext } from 'svelte';
import type { VaultScope } from './vault-lifecycle.js';
export const VAULT_CONTEXT = Symbol('Vault lifecycle');
export type VaultContext = {
  current: () => VaultScope;
  registerDraft: (dirty: () => boolean) => () => void;
  registerResume: (check: () => Promise<void>) => () => void;
  hasDrafts?: () => boolean;
  lock: () => void;
};
export function vaultContext(): VaultContext {
  return getContext<VaultContext>(VAULT_CONTEXT);
}
export function vaultScope(): VaultScope {
  return vaultContext().current();
}

// Deliberately separate from the unchanged format-1 panel context.
import type { OwnerVaultController } from './vault-owner-controller.ts';
export const OWNER_VAULT_CONTEXT = Symbol('Owner Vault lease');
export type OwnerVaultContext = {
  current: () => OwnerVaultController;
  registerDraft: (dirty: () => boolean) => () => void;
  lock: () => void;
};
export function ownerVaultContext(): OwnerVaultContext {
  return getContext<OwnerVaultContext>(OWNER_VAULT_CONTEXT);
}
