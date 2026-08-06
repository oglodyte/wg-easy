import type { InferSelectModel } from 'drizzle-orm';
import z from 'zod';
import type { infer as ZodInfer } from 'zod';

import type {
  routingGroup,
  routingGroupExit,
  routingGroupMember,
  routingGroupRuntimeState,
  routingSlotTombstone,
} from './schema';

import type { RoutingGroupSchema } from '#shared/utils/schemas';

export type RoutingGroupType = InferSelectModel<typeof routingGroup>;
export type RoutingGroupExitType = InferSelectModel<typeof routingGroupExit>;
export type RoutingGroupMemberType = InferSelectModel<
  typeof routingGroupMember
>;
export type RoutingGroupRuntimeStateType = InferSelectModel<
  typeof routingGroupRuntimeState
>;
export type RoutingSlotTombstoneType = InferSelectModel<
  typeof routingSlotTombstone
>;

export type RoutingGroupInput = ZodInfer<typeof RoutingGroupSchema>;

export const RoutingGroupGetSchema = z.object({
  groupId: z.coerce.number().int().positive(),
});

export type RoutingClientSummary = {
  id: number;
  name: string;
  interfaceId: string;
  enabled: boolean;
  persistentKeepalive: number;
};

export type RoutingGroupAggregate = RoutingGroupType & {
  exits: Array<
    RoutingGroupExitType & {
      client: RoutingClientSummary;
    }
  >;
  members: Array<
    RoutingGroupMemberType & {
      client: RoutingClientSummary;
    }
  >;
  runtime: RoutingGroupRuntimeStateType | null;
  validationWarnings: string[];
  execution: {
    available: boolean;
    active: boolean;
    reason: string;
  };
};
