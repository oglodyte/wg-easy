import { useTranslation } from '@intlify/h3';
import { createError, type H3Event } from 'h3';

import {
  ClientConfigurationError,
  ClientConflictError,
  InterfaceUnavailableForClientCreationError,
} from '#db/repositories/client/service';
import { ClientCredentialError } from '#server/utils/clientCredentials';
import { PolicyValidationError } from '#server/utils/routingPolicy';
import { RoutingValidationError } from '#server/utils/routing';

/** The request boundary never propagates private SQL binds or backend causes. */
export async function clientMutationHttpError(
  event: H3Event,
  error: unknown
): Promise<never> {
  const t = await useTranslation(event);
  if (error instanceof ClientCredentialError)
    throw createError({
      statusCode: 400,
      message: t(`client.configurationErrors.${error.code}`),
      data: { code: error.code },
    });
  if (error instanceof ClientConflictError)
    throw createError({
      statusCode: 409,
      message: t(
        error.code === 'credential_conflict'
          ? 'client.configurationErrors.credential_conflict'
          : 'client.enabledConflict'
      ),
      data: { code: error.code },
    });
  if (error instanceof ClientConfigurationError)
    throw createError({
      statusCode:
        error.code === 'write_failed'
          ? 500
          : error.code === 'policy_version_required'
            ? 409
            : 400,
      message: t(`client.configurationErrors.${error.code}`),
      data: { code: error.code, field: error.field },
    });
  if (error instanceof InterfaceUnavailableForClientCreationError)
    throw createError({
      statusCode: 409,
      message: t('client.configurationErrors.interface_unavailable'),
      data: { code: 'interface_unavailable' },
    });
  if (error instanceof PolicyValidationError)
    throw createError({
      statusCode: 409,
      message: t('client.configurationErrors.routing_conflict'),
      data: { code: error.code, detail: error.detail },
    });
  if (error instanceof RoutingValidationError)
    throw createError({
      statusCode: 409,
      message: t('client.configurationErrors.routing_conflict'),
      data: { issues: error.issues },
    });
  throw createError({
    statusCode: 500,
    message: t('client.configurationErrors.write_failed'),
    data: { code: 'write_failed' },
  });
}
