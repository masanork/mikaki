/** Loaded only after the owner enables native browser tools. */
import { registerWebMcpTools, type WebMcpContext } from './webmcp.ts';
import { createWorkWebMcpTools, type WorkWebMcpHost } from './work-webmcp.ts';

export function registerWorkAssistant(
  context: WebMcpContext,
  host: WorkWebMcpHost,
  permission: () => string | null,
  signal: AbortSignal,
  activity: (name: string, phase: 'running' | 'complete' | 'failed') => void,
) {
  return registerWebMcpTools(context, createWorkWebMcpTools(host, permission), signal, activity);
}
