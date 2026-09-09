import { createError, getHeader, setHeader } from 'h3';
import type { H3Event } from 'h3';

import {
  IMPORT_BYTE_LIMIT,
  LegacyImportError,
  parseImportJson,
} from './legacyImport';

export async function readLegacyImportRequest(event: H3Event) {
  setHeader(event, 'Cache-Control', 'no-store');
  if (
    !getHeader(event, 'content-type')
      ?.toLowerCase()
      .startsWith('application/json')
  ) {
    throw createError({ statusCode: 415, statusMessage: 'Expected JSON' });
  }
  const declared = getHeader(event, 'content-length');
  if (
    declared &&
    (!/^\d+$/.test(declared) || Number(declared) > IMPORT_BYTE_LIMIT)
  ) {
    throw createError({
      statusCode: 413,
      statusMessage: 'Import request too large',
    });
  }
  let length = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of event.node.req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += buffer.length;
    if (length > IMPORT_BYTE_LIMIT)
      throw createError({
        statusCode: 413,
        statusMessage: 'Import request too large',
      });
    chunks.push(buffer);
  }
  const value = parseImportJson(Buffer.concat(chunks).toString('utf8'));
  if (
    !value ||
    typeof value !== 'object' ||
    !('file' in value) ||
    typeof value.file !== 'string' ||
    !('settings' in value) ||
    Object.keys(value).some((k) => k !== 'file' && k !== 'settings')
  ) {
    throw new LegacyImportError([{ code: 'invalid_file' }]);
  }
  return { file: value.file, settings: value.settings };
}

export function legacyImportHttpError(error: unknown): never {
  if (error instanceof LegacyImportError) {
    throw createError({
      statusCode: 400,
      statusMessage: 'Invalid legacy import',
      data: { issues: error.issues },
    });
  }
  // Never propagate Drizzle errors: they can include SQL parameters with keys.
  if (
    error &&
    typeof error === 'object' &&
    'statusCode' in error &&
    [413, 415].includes(Number(error.statusCode))
  )
    throw error;
  throw createError({
    statusCode: 500,
    statusMessage: 'Legacy import failed',
    data: { issues: [{ code: 'import_failed' }] },
  });
}
