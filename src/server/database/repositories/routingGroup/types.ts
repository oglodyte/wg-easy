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

import { RoutingGroupSchema } from '#shared/utils/schemas';

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
export const RoutingGroupSaveSchema = RoutingGroupSchema.safeExtend({
  expectedDesiredRevision: z
    .number()
    .int()
    .nonnegative()
    .max(Number.MAX_SAFE_INTEGER)
    .optional(),
  expectedDesiredFingerprint: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional(),
});
export const RoutingGroupPreviewSchema = z
  .strictObject({
    groupId: z
      .number()
      .int()
      .positive()
      .max(Number.MAX_SAFE_INTEGER)
      .optional(),
    group: RoutingGroupSchema,
    memberClientId: z
      .number()
      .int()
      .positive()
      .max(Number.MAX_SAFE_INTEGER)
      .optional(),
    destinationIpv4: z.ipv4().optional(),
  })
  .superRefine((value, ctx) => {
    if (
      (value.memberClientId === undefined) !==
      (value.destinationIpv4 === undefined)
    )
      ctx.addIssue({
        code: 'custom',
        path: ['destinationIpv4'],
        message: 'Choose both a member and destination for an explanation',
      });
  });
export type RoutingGroupPreviewInput = z.infer<
  typeof RoutingGroupPreviewSchema
>;
export type RoutingGroupSaveConditions = Pick<
  z.infer<typeof RoutingGroupSaveSchema>,
  'expectedDesiredRevision' | 'expectedDesiredFingerprint'
>;

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
  baselineEditable: boolean;
  execution: {
    available: boolean;
    active: boolean;
    reason: string;
  };
};
