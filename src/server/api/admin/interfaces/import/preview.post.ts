import Database from '#server/utils/Database';
import { definePermissionEventHandler } from '#server/utils/handler';
import {
  readLegacyImportRequest,
  legacyImportHttpError,
} from '#server/utils/legacyImportRequest';

export default definePermissionEventHandler(
  'admin',
  'any',
  async ({ event }) => {
    try {
      const { file, settings } = await readLegacyImportRequest(event);
      return await Database.legacyImport.preview(file, settings);
    } catch (error) {
      return legacyImportHttpError(error);
    }
  }
);
