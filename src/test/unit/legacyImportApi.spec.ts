import { Readable } from 'node:stream';
import { ServerResponse } from 'node:http';
import type { IncomingMessage } from 'node:http';

import { createError, createEvent } from 'h3';
import { beforeEach, describe, expect, test, vi } from 'vitest';

import previewHandler from '#server/api/admin/interfaces/import/preview.post';
import createHandler from '#server/api/admin/interfaces/import/create.post';

const mocks = vi.hoisted(() => ({
  getCurrentUser: vi.fn(),
  preview: vi.fn(),
  create: vi.fn(),
}));
vi.mock('#server/utils/session', () => ({
  getCurrentUser: mocks.getCurrentUser,
}));
vi.mock('#server/utils/Database', () => ({
  default: { legacyImport: { preview: mocks.preview, create: mocks.create } },
}));
vi.mock('#server/utils/password', () => ({ isPasswordValid: vi.fn() }));

function event() {
  const req = Readable.from(['{"file":"{}","settings":{}}']) as IncomingMessage;
  req.headers = { 'content-type': 'application/json' };
  req.method = 'POST';
  req.url = '/';
  return createEvent(req, new ServerResponse(req));
}
beforeEach(() => {
  vi.clearAllMocks();
});
describe('legacy import API permissions', () => {
  test.each([previewHandler, createHandler])(
    'rejects unauthenticated requests before reading a backup',
    async (handler) => {
      mocks.getCurrentUser.mockRejectedValue(createError({ statusCode: 401 }));
      await expect(handler(event())).rejects.toMatchObject({ statusCode: 401 });
      expect(mocks.preview).not.toHaveBeenCalled();
      expect(mocks.create).not.toHaveBeenCalled();
    }
  );
  test.each([previewHandler, createHandler])(
    'rejects client-role requests',
    async (handler) => {
      mocks.getCurrentUser.mockResolvedValue({ id: 2, role: 2 });
      await expect(handler(event())).rejects.toMatchObject({ statusCode: 403 });
      expect(mocks.preview).not.toHaveBeenCalled();
      expect(mocks.create).not.toHaveBeenCalled();
    }
  );
  test('assigns the authenticated administrator and redacts unexpected failures', async () => {
    mocks.getCurrentUser.mockResolvedValue({ id: 7, role: 1 });
    mocks.create.mockResolvedValue({ enabled: false });
    expect(await createHandler(event())).toEqual({ enabled: false });
    expect(mocks.create).toHaveBeenCalledWith('{}', {}, 7);
    mocks.create.mockRejectedValue(new Error('secret database parameters'));
    try {
      await createHandler(event());
      throw new Error('expected failure');
    } catch (error) {
      expect(JSON.stringify(error).includes('secret database parameters')).toBe(
        false
      );
      expect(error).toMatchObject({ statusCode: 500 });
    }
  });
});
