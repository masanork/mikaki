/** Browser adapter over the same owner-screen actions. Projections grant no authority. */
import { WebMcpFailure, type WebMcpTool } from './webmcp.ts';
import type { SourceRead } from './work-source-view.ts';

export type WorkAssistantAction =
  | 'refresh'
  | 'more'
  | 'select_files'
  | 'select_code'
  | 'inspect'
  | 'prepare'
  | 'open_preparation'
  | 'review';
export type WorkReviewAction = 'approve_copy' | 'withdraw_copy' | 'start_copy' | 'stop_copy';
export type WorkAssistantSnapshot = {
  page: 'sources' | 'preparations' | 'copy';
  version: string;
  selection: string;
  busy: boolean;
  loaded: boolean;
  items: {
    id: string;
    label?: string;
    role?: string;
    revision?: number;
    commit?: string;
    state?: string;
    expires_at?: number;
    files?: { path: string; bytes: number }[];
  }[];
  files: { source_id: string; path: string; bytes: number }[];
  selected: string | null;
  prepared: string | null;
  copy: {
    status?: string;
    state?: string;
    done?: number;
    total?: number;
    can_start?: boolean;
    cleanup_pending?: boolean;
  } | null;
};
export type WorkWebMcpHost = {
  page: WorkAssistantSnapshot['page'];
  snapshot(): WorkAssistantSnapshot;
  visible(): boolean;
  verify(): Promise<void>;
  available(action: WorkAssistantAction): boolean;
  invoke(
    action: WorkAssistantAction,
    args: Record<string, unknown>,
    signal: AbortSignal,
  ): Promise<void>;
  contents(): SourceRead[];
};
const reviews: WorkReviewAction[] = ['approve_copy', 'withdraw_copy', 'start_copy', 'stop_copy'];
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
function id(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.:-]{1,128}$/.test(value))
    throw new WebMcpFailure('invalid_input');
  return value;
}
function schema(properties: Record<string, unknown>, required: string[] = []) {
  return { type: 'object', properties, required, additionalProperties: false };
}
function publicState(snapshot: WorkAssistantSnapshot) {
  const { version: _version, selection: _selection, ...state } = snapshot;
  const result = structuredClone({
    ...state,
    items: state.items.slice(-20),
    items_truncated: state.items.length > 20,
    files: state.files.slice(0, 32),
  });
  if (new TextEncoder().encode(JSON.stringify(result)).length > 128 * 1024)
    throw new WebMcpFailure('result_limit');
  return result;
}
function adapter(host: WorkWebMcpHost, contentPermission: () => string | null) {
  async function guarded<T>(signal: AbortSignal, run: () => Promise<T>): Promise<T> {
    signal.throwIfAborted();
    if (!host.visible()) throw new WebMcpFailure('unavailable');
    const { version, busy } = host.snapshot();
    if (busy) throw new WebMcpFailure('busy');
    await host.verify();
    signal.throwIfAborted();
    if (!host.visible()) throw new WebMcpFailure('unavailable');
    if (host.snapshot().version !== version) throw new WebMcpFailure('selection_changed');
    const result = await run();
    signal.throwIfAborted();
    const after = host.snapshot().version;
    await host.verify();
    signal.throwIfAborted();
    if (!host.visible()) throw new WebMcpFailure('unavailable');
    if (host.snapshot().version !== after) throw new WebMcpFailure('selection_changed');
    return result;
  }
  async function act(
    action: WorkAssistantAction,
    args: Record<string, unknown>,
    signal: AbortSignal,
  ) {
    if (!host.available(action)) throw new WebMcpFailure('unavailable');
    try {
      await host.invoke(action, args, signal);
    } catch (error) {
      // The screen and lazy helper have distinct module instances. Translate only
      // the screen's closed refusal codes; do not forward messages or payloads.
      if (
        error instanceof Error &&
        'code' in error &&
        ['not_selected', 'selection_limit', 'unavailable'].includes(String(error.code))
      )
        throw new WebMcpFailure(String(error.code));
      throw error;
    }
    signal.throwIfAborted();
    return publicState(host.snapshot());
  }
  function tool(
    name: string,
    description: string,
    inputSchema: Record<string, unknown>,
    execute: WebMcpTool['execute'],
    readOnly = false,
  ): WebMcpTool {
    return {
      name,
      description,
      inputSchema,
      execute,
      annotations: { readOnlyHint: readOnly, untrustedContentHint: true },
    };
  }
  return { host, contentPermission, guarded, act, tool };
}
type Adapter = ReturnType<typeof adapter>;
const identifier = { type: 'string', pattern: '^[A-Za-z0-9_.:-]{1,128}$' };
function commonTools({ host, guarded, act, tool }: Adapter): WebMcpTool[] {
  return [
    tool(
      'mikaki_get_work_state',
      'Read the current Work screen projection; this is not authorization.',
      schema({}),
      async (args, { signal }) => {
        input(args, []);
        return guarded(signal, async () => publicState(host.snapshot()));
      },
      true,
    ),
    tool(
      'mikaki_refresh_work',
      'Refresh this Work screen. Existing selections and acknowledgments may be cleared.',
      schema({ more: { type: 'boolean' } }),
      async (args, { signal }) => {
        const value = input(args, ['more']);
        if (value['more'] !== undefined && typeof value['more'] !== 'boolean')
          throw new WebMcpFailure('invalid_input');
        return guarded(signal, () => act(value['more'] === true ? 'more' : 'refresh', {}, signal));
      },
    ),
  ];
}
function sourceTools({ guarded, act, tool }: Adapter): WebMcpTool[] {
  return [
    tool(
      'mikaki_select_work_files',
      'Select exact files from a displayed context source. Changing selection clears content-sharing permission.',
      schema(
        {
          source_id: identifier,
          paths: {
            type: 'array',
            maxItems: 32,
            uniqueItems: true,
            items: { type: 'string', minLength: 1, maxLength: 256 },
          },
        },
        ['source_id', 'paths'],
      ),
      async (args, { signal }) => {
        const value = input(args, ['source_id', 'paths']),
          source = id(value['source_id']),
          paths = value['paths'];
        if (
          !Array.isArray(paths) ||
          paths.length > 32 ||
          new Set(paths).size !== paths.length ||
          paths.some((path) => typeof path !== 'string' || !path || path.length > 256)
        )
          throw new WebMcpFailure('invalid_input');
        return guarded(signal, () => act('select_files', { source_id: source, paths }, signal));
      },
    ),
    tool(
      'mikaki_select_work_code',
      'Choose a displayed code source for a copy preparation.',
      schema({ source_id: identifier }, ['source_id']),
      async (args, { signal }) => {
        const value = input(args, ['source_id']),
          source = id(value['source_id']);
        return guarded(signal, () => act('select_code', { source_id: source }, signal));
      },
    ),
    tool(
      'mikaki_prepare_work_copy',
      'Create the reviewed copy preparation using the current selection and expiry. This does not approve or execute a copy.',
      schema({}),
      async (args, { signal }) => {
        input(args, []);
        return guarded(signal, () => act('prepare', {}, signal));
      },
    ),
  ];
}
function inspectionTools({ host, contentPermission, guarded, act, tool }: Adapter): WebMcpTool[] {
  return [
    tool(
      'mikaki_inspect_work_selection',
      'Inspect the current selection in the existing Work screen. Returns metadata, not file contents.',
      schema({}),
      async (args, { signal }) => {
        input(args, []);
        return guarded(signal, () => act('inspect', {}, signal));
      },
    ),
    tool(
      'mikaki_read_work_file',
      'Read one selected file after the user permits content sharing for this exact selection. Rechecks current source authority.',
      schema(
        {
          file_index: { type: 'integer', minimum: 0, maximum: 31 },
          max_characters: { type: 'integer', minimum: 1, maximum: 4000 },
        },
        ['file_index'],
      ),
      async (args, { signal }) => {
        const value = input(args, ['file_index', 'max_characters']),
          index = value['file_index'],
          limit = value['max_characters'] ?? 1500;
        if (
          !Number.isInteger(index) ||
          (index as number) < 0 ||
          (index as number) > 31 ||
          !Number.isInteger(limit) ||
          (limit as number) < 1 ||
          (limit as number) > 4000
        )
          throw new WebMcpFailure('invalid_input');
        const permission = contentPermission();
        const result = await guarded(signal, async () => {
          const selected = host.snapshot();
          if (!selected.files.length || permission !== selected.selection)
            throw new WebMcpFailure('content_not_permitted');
          const expected = selected.files[index as number];
          if (!expected) throw new WebMcpFailure('not_selected');
          await act('inspect', {}, signal);
          if (host.snapshot().selection !== permission || contentPermission() !== permission)
            throw new WebMcpFailure('selection_changed');
          const files = host.contents().flatMap((read) =>
            read.files.map((file) => ({
              source_id: read.source.source_id,
              ...file,
            })),
          );
          const file = files.find(
            (file) => file.source_id === expected.source_id && file.path === expected.path,
          );
          if (!file || file.bytes !== expected.bytes) throw new WebMcpFailure('record_changed');
          const content = Array.from(file.content)
            .slice(0, limit as number)
            .join('');
          return { ...expected, content, truncated: content !== file.content };
        });
        if (contentPermission() !== permission || host.snapshot().selection !== permission)
          throw new WebMcpFailure('selection_changed');
        return result;
      },
      true,
    ),
    tool(
      'mikaki_open_work_preparation',
      'Open a displayed preparation for review. Opening does not approve a copy.',
      schema({ preparation_id: identifier }, ['preparation_id']),
      async (args, { signal }) => {
        const value = input(args, ['preparation_id']),
          preparation = id(value['preparation_id']);
        return guarded(signal, () =>
          act('open_preparation', { preparation_id: preparation }, signal),
        );
      },
    ),
  ];
}
function reviewTools({ guarded, act, tool }: Adapter): WebMcpTool[] {
  return [
    tool(
      'mikaki_review_work_action',
      'Focus the existing approve, withdraw, start or stop control for user review. Does not execute it or check an acknowledgment.',
      schema({ action: { type: 'string', enum: reviews } }, ['action']),
      async (args, { signal }) => {
        const value = input(args, ['action']);
        if (!reviews.includes(value['action'] as WorkReviewAction))
          throw new WebMcpFailure('invalid_input');
        return guarded(signal, async () => {
          await act('review', value, signal);
          // Presentation follows the Native refresh. No click or acknowledgment
          // is synthesized; Node-only adapter tests have no document to focus.
          if (typeof document !== 'undefined') {
            const control = document.querySelector<HTMLButtonElement>(
              '[data-work-action="' + String(value['action']) + '"]',
            );
            if (!control) throw new WebMcpFailure('unavailable');
            const confirmation = document.querySelector<HTMLInputElement>(
              '[data-work-confirmation="start_copy"]',
            );
            const inspection = document.querySelector<HTMLButtonElement>(
              '[data-work-action="inspect_copy"]',
            );
            if (control.disabled && confirmation && !confirmation.disabled) confirmation.focus();
            else if (control.disabled && inspection) inspection.focus();
            else control.focus();
            control.scrollIntoView({ block: 'center' });
          }
          return { status: 'review_required', action: value['action'] };
        });
      },
    ),
  ];
}

export type WorkToolFactory = (
  host: WorkWebMcpHost,
  permission: () => string | null,
) => WebMcpTool[];
export const createSourceWebMcpTools: WorkToolFactory = (host, permission) => {
  const a = adapter(host, permission);
  return [...commonTools(a), ...sourceTools(a), ...inspectionTools(a)];
};
export const createPreparationWebMcpTools: WorkToolFactory = (host, permission) => {
  const a = adapter(host, permission);
  return [...commonTools(a), ...inspectionTools(a), ...reviewTools(a)];
};
export const createCopyWebMcpTools: WorkToolFactory = (host, permission) => {
  const a = adapter(host, permission);
  return [...commonTools(a), ...reviewTools(a)];
};
export const createWorkWebMcpTools: WorkToolFactory = (host, permission) =>
  host.page === 'sources'
    ? createSourceWebMcpTools(host, permission)
    : host.page === 'preparations'
      ? createPreparationWebMcpTools(host, permission)
      : createCopyWebMcpTools(host, permission);
