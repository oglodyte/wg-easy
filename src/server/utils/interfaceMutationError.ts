import { useTranslation } from '@intlify/h3';
import { createError, type H3Event } from 'h3';
import { HeaderProtectionConfigurationError } from '#server/utils/headerProtection';

/** Do not propagate SQL bindings or secret values into an HTTP error. */
export async function interfaceMutationError(event: H3Event, error: unknown) {
  const invalidHeader = error instanceof HeaderProtectionConfigurationError;
  const translate = await useTranslation(event);
  const key = invalidHeader
    ? error.code === 'invalid_key'
      ? 'zod.keyMalformed'
      : 'zod.interface.headerProtectionJunkSize'
    : 'admin.interfaces.saveFailed';
  return createError({
    statusCode: invalidHeader ? 400 : 500,
    message: translate ? translate(key) : key,
  });
}
