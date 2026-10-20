import z from 'zod';

import { execFile } from '#server/utils/cmd';

export const RoutingKernelNamespaceSchema = z
  .string()
  .regex(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[1-9][0-9]{0,19}:[1-9][0-9]{0,19}$/
  );
export class RoutingKernelContextError extends Error {
  readonly code = 'namespace_unavailable';
  constructor() {
    super('Routing kernel context: namespace unavailable');
    this.name = 'RoutingKernelContextError';
  }
}

/** Run in the same namespace as all routing/device operations, never a host guess. */
export async function readRoutingKernelNamespace(
  run: typeof execFile = execFile
) {
  try {
    const [boot, namespace] = await Promise.all([
      run('cat', ['/proc/sys/kernel/random/boot_id'], { log: false }),
      run('stat', ['-L', '-c', '%d:%i', '/proc/self/ns/net'], { log: false }),
    ]);
    return RoutingKernelNamespaceSchema.parse(
      `${boot.trim()}:${namespace.trim()}`
    );
  } catch {
    throw new RoutingKernelContextError();
  }
}
