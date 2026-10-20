import z from 'zod';

import {
  parseManagedHookCounts,
  type ManagedHookCounts,
  ManagedServerHookError,
} from '#server/utils/managedServerHooks';
import {
  InterfaceNameSchema,
  NetworkDeviceSchema,
} from '#shared/utils/schemas';

/** Restricted recovery data; identical config bytes do not imply no restart. */
export type ManagedLifecycleIntent = {
  interfaces: {
    interfaceId: string;
    previousUp: boolean;
    targetUp: boolean;
    previousHooksApplied?: boolean;
    targetHooksApplied?: boolean;
    restart: boolean;
    previousDefaultEgress?: string;
    targetDefaultEgress?: string;
  }[];
  hooks: ManagedHookCounts;
};
const schema = z
  .object({
    interfaces: z
      .array(
        z
          .object({
            interfaceId: InterfaceNameSchema,
            previousUp: z.boolean(),
            targetUp: z.boolean(),
            previousHooksApplied: z.boolean().optional(),
            targetHooksApplied: z.boolean().optional(),
            restart: z.boolean(),
            previousDefaultEgress: NetworkDeviceSchema.optional(),
            targetDefaultEgress: NetworkDeviceSchema.optional(),
          })
          .strict()
      )
      .max(1024),
    hooks: z.unknown(),
  })
  .strict();

export function parseManagedLifecycleIntent(
  value: unknown
): ManagedLifecycleIntent {
  try {
    const parsed = schema.parse(value),
      ids = new Set<string>();
    for (const entry of parsed.interfaces) {
      if (
        ids.has(entry.interfaceId) ||
        (entry.previousUp !== entry.targetUp && !entry.restart) ||
        (entry.previousUp && entry.previousHooksApplied === false) ||
        (entry.targetUp && entry.targetHooksApplied === false) ||
        (!(entry.previousHooksApplied ?? entry.previousUp) &&
          (entry.targetHooksApplied ?? entry.targetUp) &&
          !entry.targetUp)
      )
        throw new Error();
      ids.add(entry.interfaceId);
    }
    return {
      interfaces: parsed.interfaces,
      hooks: parseManagedHookCounts(parsed.hooks),
    };
  } catch {
    throw new ManagedServerHookError('invalid_lifecycle_manifest');
  }
}
