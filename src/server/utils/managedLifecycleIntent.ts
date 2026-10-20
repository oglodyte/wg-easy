import z from 'zod';

import {
  parseManagedHookCounts,
  type ManagedHookCounts,
  ManagedServerHookError,
} from '#server/utils/managedServerHooks';
import { InterfaceNameSchema } from '#shared/utils/schemas';

/** Restricted recovery data; identical config bytes do not imply no restart. */
export type ManagedLifecycleIntent = {
  interfaces: {
    interfaceId: string;
    previousUp: boolean;
    targetUp: boolean;
    restart: boolean;
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
            restart: z.boolean(),
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
        (entry.previousUp !== entry.targetUp && !entry.restart)
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
