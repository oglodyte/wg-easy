import { useTranslation } from '@intlify/h3';
import { createError, readBody, type H3Event } from 'h3';
import type { ZodType } from 'zod';

import {
  ClientConfigurationError,
  ClientConflictError,
  InterfaceUnavailableForClientCreationError,
} from '#db/repositories/client/service';
import { ClientCredentialError } from '#server/utils/clientCredentials';
import { PolicyValidationError } from '#server/utils/routingPolicy';
import { RoutingValidationError } from '#server/utils/routing';
import { validateZod } from '#server/utils/types';

export async function readClientConfigurationBody<T>(
  event: H3Event,
  schema: ZodType<T>
) {
  const input: unknown = await readBody(event);
  try {
    return await validateZod(schema, event)(input);
  } catch (error) {
    // H3 does not always serialize an error's top-level message.
    const message = error instanceof Error ? error.message : undefined;
    throw createError({
      statusCode: 400,
      message,
      data: { message },
    });
  }
}

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
  if (error instanceof RoutingValidationError) {
    const overlap = error.issues.find(
      (issue) => issue.code === 'server_allowed_ip_conflict'
    );
    const [prefix, otherPrefix] = overlap?.prefixes ?? [];
    const [client, otherClient] = overlap?.clientIds ?? [];
    const message =
      prefix && otherPrefix && client !== undefined && otherClient !== undefined
        ? t('client.configurationErrors.server_prefix_overlap', {
            prefix,
            otherPrefix,
            client,
            otherClient,
          })
        : t('client.configurationErrors.routing_conflict');
    throw createError({
      statusCode: 409,
      message,
      data: { message, issues: error.issues },
    });
  }
  throw createError({
    statusCode: 500,
    message: t('client.configurationErrors.write_failed'),
    data: { code: 'write_failed' },
  });
}
