import type { OwnerVaultController } from './vault-owner-controller.ts';

export type MessagingOptions = { onDraft?: (dirty: boolean) => void };

export type MessagingMount = {
  mount(
    owner: OwnerVaultController,
    root: HTMLElement,
    options?: MessagingOptions,
  ): Promise<{ dispose(): void }>;
};
