import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { BrowserContext, ConsoleMessage, Page, Request, Response } from '@playwright/test';

// Use only with disposable local fixtures: traces and screenshots include DOM,
// cookies and response bodies. Never attach this recorder to production accounts.
export function diagnosticText(value: string): string {
  return value
    .replace(/https?:\/\/[^\s"'<>]+/g, (raw) => {
      try {
        const url = new URL(raw);
        return `${url.origin}${url.pathname}`;
      } catch {
        return '[url]';
      }
    })
    .replace(/(?:mag_|Bearer\s+)?[A-Za-z0-9_-]{43,}/g, '[redacted]')
    .slice(0, 4000);
}

export async function startBrowserEvidence(context: BrowserContext, name: string) {
  const events: { kind: string; detail: string }[] = [];
  const detach: (() => void)[] = [];
  const record = (kind: string, detail: string) => {
    if (events.length === 200) events.shift();
    events.push({ kind, detail: diagnosticText(detail) });
  };
  const attach = (page: Page) => {
    const error = (error: Error) => record('pageerror', error.message);
    const console = (message: ConsoleMessage) => {
      if (['error', 'warning'].includes(message.type())) record('console', message.text());
    };
    const failed = (request: Request) =>
      record(
        'requestfailed',
        `${request.method()} ${request.url()} ${request.failure()?.errorText}`,
      );
    const response = (response: Response) => {
      if (response.status() >= 400) record('http', `${response.status()} ${response.url()}`);
    };
    page.on('pageerror', error);
    page.on('console', console);
    page.on('requestfailed', failed);
    page.on('response', response);
    detach.push(() => {
      page.off('pageerror', error);
      page.off('console', console);
      page.off('requestfailed', failed);
      page.off('response', response);
    });
  };
  context.pages().forEach(attach);
  context.on('page', attach);
  await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
  let finished = false;
  return {
    async finish(failure?: unknown): Promise<string | null> {
      if (finished) return null;
      finished = true;
      try {
        if (failure === undefined) {
          await context.tracing.stop();
          return null;
        }
        const directory = join(
          'artifacts/browser-failures',
          `${name.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 80)}-${randomUUID()}`,
        );
        await mkdir(directory, { recursive: true });
        await writeFile(
          join(directory, 'diagnostics.json'),
          JSON.stringify(
            {
              name,
              fixture: 'disposable-local-only',
              failure: diagnosticText(
                failure instanceof Error ? (failure.stack ?? failure.message) : String(failure),
              ),
              events,
            },
            null,
            2,
          ) + '\n',
        );
        await context.tracing.stop({ path: join(directory, 'trace.zip') });
        for (const [index, page] of context.pages().entries()) {
          if (!page.isClosed())
            await page
              .screenshot({ path: join(directory, `page-${index}.png`), fullPage: true })
              .catch(() => {});
        }
        console.error(`Browser failure evidence: ${directory}`);
        return directory;
      } catch (error) {
        // Keep the original assertion as the primary failure.
        console.error(`Could not finish browser evidence: ${diagnosticText(String(error))}`);
        return null;
      } finally {
        context.off('page', attach);
        detach.forEach((remove) => remove());
      }
    },
  };
}
