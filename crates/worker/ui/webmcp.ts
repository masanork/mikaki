// Native WebMCP only. Unsupported browsers keep the ordinary UI.
export type WebMcpTool = {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: {
    readOnlyHint?: boolean;
    untrustedContentHint?: boolean;
    consequentialHint?: boolean;
  };
  execute: (input: unknown, options: { signal: AbortSignal }) => Promise<unknown>;
};
export type WebMcpContext = {
  registerTool: (tool: WebMcpTool, options: { signal: AbortSignal }) => Promise<void> | void;
};
export class WebMcpFailure extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}
export function webMcpContext(document: Document): WebMcpContext | null {
  const context = (document as Document & { modelContext?: WebMcpContext }).modelContext;
  return context && typeof context.registerTool === 'function' ? context : null;
}
export async function registerWebMcpTools(
  context: WebMcpContext,
  tools: WebMcpTool[],
  signal: AbortSignal,
  activity: (name: string, phase: 'running' | 'complete' | 'failed') => void = () => {},
): Promise<void> {
  signal.throwIfAborted();
  let running = false;
  for (const tool of tools) {
    await context.registerTool(
      {
        ...tool,
        execute: async (input, options) => {
          if (running) return { ok: false, error: 'busy' };
          const execution = AbortSignal.any([signal, options.signal]);
          running = true;
          try {
            execution.throwIfAborted();
            activity(tool.name, 'running');
            const result = await tool.execute(input, { signal: execution });
            execution.throwIfAborted();
            activity(tool.name, 'complete');
            return { ok: true, result };
          } catch (error) {
            if (!signal.aborted) activity(tool.name, 'failed');
            return {
              ok: false,
              error: execution.aborted
                ? 'cancelled'
                : error instanceof WebMcpFailure
                  ? error.code
                  : 'unavailable',
            };
          } finally {
            running = false;
          }
        },
      },
      { signal },
    );
    signal.throwIfAborted();
  }
}
