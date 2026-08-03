export const CONFIG_FORMATS = ['wireguard', 'amneziawg'] as const;
export const CONFIG_FORMAT_SELECTIONS = ['auto', ...CONFIG_FORMATS] as const;

export type ConfigFormat = (typeof CONFIG_FORMAT_SELECTIONS)[number];
export type ConcreteConfigFormat = (typeof CONFIG_FORMATS)[number];

export type InterfaceRuntimeAction =
  'none' | 'sync' | 'restart' | 'up' | 'down';

export type InterfaceChangeImpact = {
  interfaceId: string;
  action: InterfaceRuntimeAction;
};

export type MutationRuntimeStatus = 'pending' | 'applied' | 'degraded';

export type MutationRuntimeState = {
  status: MutationRuntimeStatus;
  appliedRevision: number;
  error?: string;
};

export type MutationResult = {
  /** The desired database state was persisted. */
  success: boolean;
  revision: number;
  runtime: MutationRuntimeState;
};

export type InterfaceRuntimeStatus =
  'disabled' | 'pending' | 'starting' | 'up' | 'degraded' | 'stopping';

export type ReconciliationStatus = 'idle' | 'pending' | 'applying' | 'degraded';

export type RoutingGroupRuntimeStatus =
  | 'disabled'
  | 'draft_invalid'
  | 'awaiting_exit'
  | 'selected_pending'
  | 'active'
  | 'blocked'
  | 'host_fallback'
  | 'degraded';

export type AllExitsDownPolicy = 'block' | 'host';
