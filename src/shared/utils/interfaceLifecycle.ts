import type { InterfaceRuntimeAction } from '../types/runtime';

export type InterfaceLifecycleChange =
  | { kind: 'create'; enabled: boolean }
  | { kind: 'enabled'; before: boolean; after: boolean }
  | { kind: 'peer' }
  | { kind: 'endpoint' }
  | { kind: 'server' }
  | { kind: 'delete' };

/**
 * Stable Phase 1 contract for the runtime action required by an interface
 * change. The later reconciler consumes this impact; API handlers do not run
 * interface commands directly.
 */
export function getInterfaceRuntimeAction(
  change: InterfaceLifecycleChange
): InterfaceRuntimeAction {
  switch (change.kind) {
    case 'create':
      return change.enabled ? 'up' : 'none';
    case 'enabled':
      if (change.before === change.after) return 'none';
      return change.after ? 'up' : 'down';
    case 'peer':
      return 'sync';
    case 'endpoint':
      return 'none';
    case 'server':
      return 'restart';
    case 'delete':
      return 'down';
  }
}

export const interfaceRestartFields = [
  'ipv4Cidr',
  'ipv6Cidr',
  'mtu',
  'device',
  'port',
  'privateKey',
  'hooks',
  'awgServerParameters',
] as const;
