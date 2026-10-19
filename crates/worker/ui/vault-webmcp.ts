import { WebMcpFailure, type WebMcpTool } from './webmcp.ts';
import type { OwnerVaultController } from './vault-owner-controller.ts';
import type { OwnerWorkspaceStore } from './vault-owner-workspace-store.ts';
import { decodeOwnerNote, newOwnerNote } from './vault-note.ts';
import { parseThreadArchive } from './vault-thread-archive.ts';
import type { SearchArchive, SearchResult } from './vault-thread-search.ts';
import { threadSearchTerms } from './vault-thread-search-query.ts';

export type WebMcpSelection = {
  name: number | null;
  note: number | null;
  threads: { id: string; revision: number; title: string }[];
};
export type WebMcpDraft = { revision: number; status: 'review_required' };
export const WEBMCP_REVIEW_ACTIONS = [
  'unlock',
  'save_name',
  'save_note',
  'delete_name',
  'delete_note',
  'share_name',
  'agent_grants',
  'note_proposals',
  'local_export',
  'passkeys',
  'import_thread',
  'lock',
] as const;
export type WebMcpReviewAction = (typeof WEBMCP_REVIEW_ACTIONS)[number];
export type VaultWebMcpHost = {
  owner: () => OwnerVaultController | null;
  store: () => OwnerWorkspaceStore | null;
  selection: () => WebMcpSelection;
  blocked: () => boolean;
  hasDrafts: () => boolean;
  visible: () => boolean;
  search: (records: SearchArchive[], query: string, signal: AbortSignal) => Promise<SearchResult>;
  openThread: (id: string, revision: number, signal: AbortSignal) => Promise<void>;
  prepareName: (name: string, revision: number, signal: AbortSignal) => Promise<WebMcpDraft>;
  prepareNote: (
    title: string,
    text: string,
    revision: number,
    signal: AbortSignal,
  ) => Promise<WebMcpDraft>;
  review: (action: WebMcpReviewAction, signal: AbortSignal) => Promise<void>;
};
function input(value: unknown, keys: string[]): Record<string, unknown> {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !keys.includes(key))
  )
    throw new WebMcpFailure('invalid_input');
  return value as Record<string, unknown>;
}
function string(value: unknown, max: number): string {
  if (
    typeof value !== 'string' ||
    !value.trim() ||
    value.length > max ||
    /[\uD800-\uDFFF]/u.test(value)
  )
    throw new WebMcpFailure('invalid_input');
  return value;
}
function integer(value: unknown, fallback: number, max: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max)
    throw new WebMcpFailure('invalid_input');
  return value as number;
}
function bounded(text: string, limit: number): string {
  return Array.from(text).slice(0, limit).join('');
}
function schema(properties: Record<string, unknown>, required: string[] = []) {
  return { type: 'object', properties, required, additionalProperties: false };
}
function selected(host: VaultWebMcpHost): WebMcpSelection {
  const selection = host.selection();
  if (
    selection.threads.length > 16 ||
    new Set(selection.threads.map((thread) => thread.id)).size !== selection.threads.length
  )
    throw new WebMcpFailure('selection_limit');
  return structuredClone(selection);
}
export function createVaultWebMcpTools(host: VaultWebMcpHost): WebMcpTool[] {
  async function guarded<T>(
    signal: AbortSignal,
    run: (store: OwnerWorkspaceStore, selection: WebMcpSelection) => T | Promise<T>,
  ): Promise<T> {
    signal.throwIfAborted();
    if (!host.visible() || host.blocked()) throw new WebMcpFailure('unavailable');
    const owner = host.owner(),
      store = host.store();
    if (!owner || !store) throw new WebMcpFailure('locked');
    const token = owner.checkpoint(),
      selection = selected(host),
      identity = JSON.stringify(selection);
    await owner.verifyAuthority();
    signal.throwIfAborted();
    owner.assertCurrent(token);
    if (
      !host.visible() ||
      host.blocked() ||
      host.owner() !== owner ||
      identity !== JSON.stringify(selected(host))
    )
      throw new WebMcpFailure('selection_changed');
    const result = await run(store, selection);
    await owner.verifyAuthority();
    signal.throwIfAborted();
    owner.assertCurrent(token);
    if (
      !host.visible() ||
      host.blocked() ||
      host.owner() !== owner ||
      identity !== JSON.stringify(selected(host))
    )
      throw new WebMcpFailure('selection_changed');
    return result;
  }
  async function read(
    store: OwnerWorkspaceStore,
    collection: string,
    id: string,
    kind: string,
    revision: number,
  ) {
    const record = await store.read(collection, id, kind);
    if (record.revision !== revision) {
      record.plaintext?.fill(0);
      throw new WebMcpFailure('record_changed');
    }
    return record;
  }
  async function thread(
    store: OwnerWorkspaceStore,
    selection: WebMcpSelection,
    id: string,
  ): Promise<SearchArchive> {
    const approved = selection.threads.find((item) => item.id === id);
    if (!approved) throw new WebMcpFailure('not_selected');
    const record = await read(store, 'threads', id, 'thread-archive', approved.revision);
    try {
      if (!record.plaintext) throw new WebMcpFailure('record_changed');
      return {
        id,
        revision: record.revision,
        archive: parseThreadArchive(
          JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(record.plaintext)),
        ),
      };
    } finally {
      record.plaintext?.fill(0);
    }
  }
  function tool(
    name: string,
    description: string,
    inputSchema: Record<string, unknown>,
    execute: WebMcpTool['execute'],
    readOnly = true,
    untrusted = true,
  ): WebMcpTool {
    return {
      name,
      description,
      inputSchema,
      annotations: { readOnlyHint: readOnly, untrustedContentHint: untrusted },
      execute,
    };
  }
  const textSchema = { type: 'string', minLength: 1, maxLength: 256 };
  return [
    tool(
      'mikaki_get_vault_state',
      'Get Vault state and selected permissions.',
      schema({}),
      async (args, { signal }) => {
        input(args, []);
        signal.throwIfAborted();
        if (!host.visible()) throw new WebMcpFailure('unavailable');
        const owner = host.owner();
        if (owner) await owner.verifyAuthority();
        signal.throwIfAborted();
        const selection = selected(host);
        return {
          unlocked: !!owner,
          busy: host.blocked(),
          unsaved_changes: host.hasDrafts(),
          selected: {
            name: selection.name !== null,
            note: selection.note !== null,
            threads: selection.threads.length,
          },
        };
      },
      true,
      false,
    ),
    tool('mikaki_list_selected', 'List selected records.', schema({}), async (args, { signal }) => {
      input(args, []);
      return guarded(signal, (_store, selection) => ({
        records: [
          ...(selection.name === null ? [] : [{ target: 'name', revision: selection.name }]),
          ...(selection.note === null ? [] : [{ target: 'owner_note', revision: selection.note }]),
          ...selection.threads.map((item) => ({
            target: 'thread',
            thread_id: item.id,
            revision: item.revision,
            title: bounded(item.title, 160),
          })),
        ],
      }));
    }),
    tool(
      'mikaki_search_selected',
      'Search selected conversations locally.',
      schema({ query: textSchema }, ['query']),
      async (args, { signal }) => {
        const value = input(args, ['query']),
          query = string(value['query'], 256);
        try {
          threadSearchTerms(query);
        } catch {
          throw new WebMcpFailure('invalid_input');
        }
        return guarded(signal, async (store, selection) => {
          if (!selection.threads.length) throw new WebMcpFailure('not_selected');
          const records: SearchArchive[] = [];
          for (const item of selection.threads) {
            signal.throwIfAborted();
            records.push(await thread(store, selection, item.id));
          }
          const result = await host.search(records, query, signal);
          return {
            hits: result.hits.slice(0, 10).map((hit) => ({ ...hit, text: bounded(hit.text, 240) })),
            truncated: result.truncated || result.hits.length > 10,
          };
        });
      },
    ),
    tool(
      'mikaki_read_selected',
      'Read selected text or five messages.',
      schema(
        {
          target: { type: 'string', enum: ['name', 'owner_note', 'thread'] },
          thread_id: { type: 'string', maxLength: 128 },
          message_start: { type: 'integer', minimum: 0, maximum: 100000 },
          max_characters: { type: 'integer', minimum: 1, maximum: 4000 },
        },
        ['target'],
      ),
      async (args, { signal }) => {
        const value = input(args, ['target', 'thread_id', 'message_start', 'max_characters']);
        const target = value['target'],
          start = integer(value['message_start'], 0, 100000),
          limit = integer(value['max_characters'], 1500, 4000);
        if (
          !['name', 'owner_note', 'thread'].includes(String(target)) ||
          limit < 1 ||
          (target !== 'thread' &&
            (value['thread_id'] !== undefined || value['message_start'] !== undefined))
        )
          throw new WebMcpFailure('invalid_input');
        return guarded(signal, async (store, selection) => {
          if (target === 'thread') {
            const archive = await thread(store, selection, string(value['thread_id'], 128));
            let remaining = limit,
              truncated = false;
            const messages = [];
            for (const [index, message] of archive.archive.messages.entries()) {
              if (index < start) continue;
              if (messages.length === 5 || remaining === 0) {
                truncated = true;
                break;
              }
              const text = bounded(message.text, remaining);
              remaining -= Array.from(text).length;
              truncated ||= text !== message.text;
              messages.push({
                index,
                speaker: message.speaker,
                actor: message.actor,
                timestamp: message.timestamp,
                text,
              });
            }
            return {
              target,
              thread_id: archive.id,
              revision: archive.revision,
              title: archive.archive.title,
              messages,
              truncated,
            };
          }
          const revision = target === 'name' ? selection.name : selection.note;
          if (revision === null) throw new WebMcpFailure('not_selected');
          const record = await read(
            store,
            'personal',
            target === 'name' ? 'name' : 'owner_note',
            String(target),
            revision,
          );
          try {
            if (!record.plaintext) return { target, revision, empty: true };
            if (target === 'name') {
              const name = new TextDecoder('utf-8', { fatal: true }).decode(record.plaintext);
              if (!name.length || name.length > 256) throw new WebMcpFailure('unavailable');
              return {
                target,
                revision,
                text: bounded(name, limit),
                truncated: Array.from(name).length > limit,
              };
            }
            const note = decodeOwnerNote(record.plaintext);
            return {
              target,
              revision,
              title: note.title,
              text: bounded(note.text, limit),
              truncated: Array.from(note.text).length > limit,
            };
          } finally {
            record.plaintext?.fill(0);
          }
        });
      },
    ),
    tool(
      'mikaki_open_selected_thread',
      'Display a selected conversation.',
      schema({ thread_id: { type: 'string', maxLength: 128 } }, ['thread_id']),
      async (args, { signal }) => {
        const value = input(args, ['thread_id']),
          id = string(value['thread_id'], 128);
        return guarded(signal, async (store, selection) => {
          const record = await thread(store, selection, id);
          signal.throwIfAborted();
          await host.openThread(id, record.revision, signal);
          return { status: 'displayed', thread_id: id, revision: record.revision };
        });
      },
      false,
    ),
    tool(
      'mikaki_prepare_name_edit',
      'Draft a name for user review.',
      schema({ name: textSchema }, ['name']),
      async (args, { signal }) => {
        const value = input(args, ['name']),
          name = string(value['name'], 256);
        if (/[\u0000-\u001f\u007f]/.test(name)) throw new WebMcpFailure('invalid_input');
        return guarded(signal, async (store, selection) => {
          if (selection.name === null) throw new WebMcpFailure('not_selected');
          if (host.hasDrafts()) throw new WebMcpFailure('unsaved_changes');
          const record = await read(store, 'personal', 'name', 'name', selection.name);
          record.plaintext?.fill(0);
          signal.throwIfAborted();
          return host.prepareName(name, selection.name, signal);
        });
      },
      false,
      false,
    ),
    tool(
      'mikaki_prepare_note_edit',
      'Draft a note for user review.',
      schema({ title: textSchema, text: { type: 'string', minLength: 1, maxLength: 4096 } }, [
        'title',
        'text',
      ]),
      async (args, { signal }) => {
        const value = input(args, ['title', 'text']),
          title = string(value['title'], 256),
          text = string(value['text'], 4096);
        try {
          newOwnerNote(title, text);
        } catch {
          throw new WebMcpFailure('invalid_input');
        }
        return guarded(signal, async (store, selection) => {
          if (selection.note === null) throw new WebMcpFailure('not_selected');
          if (host.hasDrafts()) throw new WebMcpFailure('unsaved_changes');
          const record = await read(store, 'personal', 'owner_note', 'owner_note', selection.note);
          record.plaintext?.fill(0);
          signal.throwIfAborted();
          return host.prepareNote(title, text, selection.note, signal);
        });
      },
      false,
      false,
    ),
    tool(
      'mikaki_review_vault_action',
      'Focus a Vault action for user review.',
      schema({ action: { type: 'string', enum: WEBMCP_REVIEW_ACTIONS } }, ['action']),
      async (args, { signal }) => {
        const value = input(args, ['action']);
        if (!WEBMCP_REVIEW_ACTIONS.includes(value['action'] as WebMcpReviewAction))
          throw new WebMcpFailure('invalid_input');
        signal.throwIfAborted();
        if (!host.visible() || host.blocked()) throw new WebMcpFailure('unavailable');
        await host.review(value['action'] as WebMcpReviewAction, signal);
        return { status: 'review_required', action: value['action'] };
      },
      false,
      false,
    ),
  ];
}
