import z from 'zod';

import { execFile } from '#server/utils/cmd';

export const RoutingKernelNamespaceSchema = z
  .string()
  .regex(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[1-9][0-9]{0,19}:[1-9][0-9]{0,19}(?::[1-9][0-9]{0,19})?$/
  )
  .refine((value) => {
    const cookie = value.split(':')[3];
    return (
      cookie === undefined ||
      (/^[1-9][0-9]{0,19}$/.test(cookie) &&
        BigInt(cookie) <= 0xffffffffffffffffn)
    );
  });
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
    const [boot, namespace, cookie] = await Promise.all([
      run('cat', ['/proc/sys/kernel/random/boot_id'], { log: false }),
      run('stat', ['-L', '-c', '%d:%i', '/proc/self/ns/net'], { log: false }),
      run('/usr/local/bin/wg-easy-netns-cookie', [], { log: false }),
    ]);
    // Inodes can be reused immediately after a container is removed. The
    // kernel cookie distinguishes lifetimes while remaining stable on restart
    // of the application process within the same namespace.
    if (!/^[1-9][0-9]{0,19}$/.test(cookie.trim())) throw new Error();
    return RoutingKernelNamespaceSchema.parse(
      `${boot.trim()}:${namespace.trim()}:${cookie.trim()}`
    );
  } catch {
    throw new RoutingKernelContextError();
  }
}
