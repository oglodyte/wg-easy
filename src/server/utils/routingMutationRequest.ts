import { useTranslation } from '@intlify/h3';
import { createError, type H3Event } from 'h3';

import {
  RoutingGroupNotFoundError,
  RoutingPolicyRevisionConflictError,
} from '#db/repositories/routingGroup/service';
import { PolicyValidationError } from '#server/utils/routingPolicy';
import { RoutingValidationError } from '#server/utils/routing';

export async function routingMutationHttpError(
  event: H3Event,
  error: unknown
): Promise<never> {
  const t = await useTranslation(event);
  if (error instanceof RoutingGroupNotFoundError)
    throw createError({
      statusCode: 404,
      message: t('admin.routing.notFound'),
    });
  if (error instanceof RoutingPolicyRevisionConflictError)
    throw createError({
      statusCode: 409,
      message: t('admin.routing.previewStale'),
      data: { code: 'desired_changed', desiredRevision: error.desiredRevision },
    });
  if (error instanceof PolicyValidationError)
    throw createError({
      statusCode: 409,
      message: t('admin.routing.policyInvalid'),
      data: { code: error.code, detail: error.detail },
    });
  if (error instanceof RoutingValidationError)
    throw createError({
      statusCode: 409,
      message: t('admin.routing.policyInvalid'),
      data: { issues: error.issues },
    });
  throw createError({
    statusCode: 500,
    message: t('admin.routing.operationFailed'),
    data: { code: 'routing_operation_failed' },
  });
}
