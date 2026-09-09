import { Readable } from 'node:stream';
import { ServerResponse } from 'node:http';
import type { IncomingMessage } from 'node:http';

import { createEvent } from 'h3';
import { describe, expect, test } from 'vitest';

import { readLegacyImportRequest } from '#server/utils/legacyImportRequest';
import { IMPORT_BYTE_LIMIT } from '#server/utils/legacyImport';

function event(chunks: string[], headers: Record<string, string> = {}) {
  const req = Readable.from(chunks) as IncomingMessage;
  req.headers = { 'content-type': 'application/json', ...headers };
  req.method = 'POST';
  req.url = '/api/admin/interfaces/import/preview';
  return createEvent(req, new ServerResponse(req));
}
describe('secret import request boundary', () => {
  test('accepts chunked JSON without Content-Length and prevents caching', async () => {
    const request = event(['{"file":"{}",', '"settings":{}}']);
    expect(await readLegacyImportRequest(request)).toEqual({
      file: '{}',
      settings: {},
    });
    expect(request.node.res.getHeader('cache-control')).toBe('no-store');
  });
  test('rejects oversized actual bytes even with a forged small Content-Length', async () => {
    for (const headers of [{}, { 'content-length': '1' }])
      await expect(
        readLegacyImportRequest(
          event([' '.repeat(IMPORT_BYTE_LIMIT), 'x'], headers)
        )
      ).rejects.toMatchObject({ statusCode: 413 });
  });
  test('rejects oversized declaration and non-JSON before body parsing', async () => {
    await expect(
      readLegacyImportRequest(
        event([], { 'content-length': String(IMPORT_BYTE_LIMIT + 1) })
      )
    ).rejects.toMatchObject({ statusCode: 413 });
    await expect(
      readLegacyImportRequest(event([], { 'content-type': 'text/plain' }))
    ).rejects.toMatchObject({ statusCode: 415 });
  });
});
