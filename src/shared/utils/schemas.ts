import { normalizeCidr, parseCidr } from 'cidr-tools';
import z from 'zod';

import { CONFIG_FORMAT_SELECTIONS, CONFIG_FORMATS } from '../types/runtime';

const LINUX_INTERFACE_NAME_MAX_BYTES = 15;
const ROUTING_SLOT_MIN = 1;
const ROUTING_SLOT_MAX = 999;
const ROUTING_GROUP_EXIT_LIMIT = 16;
const ROUTING_GROUP_PREFIX_LIMIT = 64;
const ROUTING_GROUP_MEMBER_LIMIT = 1024;
const ROUTING_GROUP_RULE_LIMIT = 4096;

function hasUsableServerAndClientAddresses(value: string) {
  const parsed = parseCidr(value);
  return parsed.end - parsed.start >= 3n;
}

function isCidrVersion(value: string, version: 4 | 6) {
  try {
    const parsed = parseCidr(value);
    return parsed.version === version && parsed.prefixPresent;
  } catch {
    return false;
  }
}

const LinuxIdentifierSchema = z
  .string()
  .min(1)
  .refine(
    (value) => value.length <= LINUX_INTERFACE_NAME_MAX_BYTES,
    'Linux interface names must be at most 15 bytes'
  )
  .regex(
    /^[A-Za-z0-9_.-]+$/,
    'Linux interface names may contain only letters, digits, underscore, dot, and hyphen'
  )
  .refine((value) => value !== '.' && value !== '..', 'Invalid Linux name');

export const InterfaceNameSchema = LinuxIdentifierSchema;
export const NetworkDeviceSchema = LinuxIdentifierSchema;

function cidrSchema(version: 4 | 6) {
  return z
    .string()
    .refine(
      (value) => isCidrVersion(value, version),
      `Expected an IPv${version} CIDR`
    )
    .refine(
      hasUsableServerAndClientAddresses,
      'CIDR must contain addresses for the network, server, client, and boundary'
    )
    .transform((value) => normalizeCidr(value));
}

export const Ipv4CidrSchema = cidrSchema(4);
export const Ipv6CidrSchema = cidrSchema(6);
export const RoutingGroupPrefixSchema = z
  .string()
  .refine((value) => isCidrVersion(value, 4), 'Expected an IPv4 CIDR')
  .transform((value) => normalizeCidr(value));

export const ConfigFormatSchema = z.enum(CONFIG_FORMAT_SELECTIONS);
export const ConcreteConfigFormatSchema = z.enum(CONFIG_FORMATS);

export const RoutingSlotSchema = z
  .number()
  .int()
  .min(ROUTING_SLOT_MIN)
  .max(ROUTING_SLOT_MAX);

const RoutingGroupExitSchema = z.object({
  clientId: z.number().int().positive(),
  priority: z.number().int().nonnegative(),
  enabled: z.boolean(),
});

export const RoutingGroupSchema = z
  .object({
    name: z.string().trim().min(1),
    enabled: z.boolean(),
    exits: z.array(RoutingGroupExitSchema).max(ROUTING_GROUP_EXIT_LIMIT),
    natEnabled: z.boolean(),
    allExitsDownPolicy: z.enum(['block', 'host']),
    routedIpv4Prefixes: z
      .array(RoutingGroupPrefixSchema)
      .max(ROUTING_GROUP_PREFIX_LIMIT)
      .transform((prefixes) => [...new Set(prefixes)]),
    memberClientIds: z
      .array(z.number().int().positive())
      .max(ROUTING_GROUP_MEMBER_LIMIT)
      .transform((clientIds) => [...new Set(clientIds)]),
  })
  .superRefine((group, context) => {
    const exitClientIds = new Set<number>();
    const exitPriorities = new Set<number>();

    for (const exit of group.exits) {
      if (exitClientIds.has(exit.clientId)) {
        context.addIssue({
          code: 'custom',
          path: ['exits'],
          message: 'Exit clients must be unique within a routing group',
        });
      }
      exitClientIds.add(exit.clientId);

      if (exitPriorities.has(exit.priority)) {
        context.addIssue({
          code: 'custom',
          path: ['exits'],
          message: 'Exit priorities must be unique within a routing group',
        });
      }
      exitPriorities.add(exit.priority);
    }

    for (const clientId of group.memberClientIds) {
      if (exitClientIds.has(clientId)) {
        context.addIssue({
          code: 'custom',
          path: ['memberClientIds'],
          message: 'A routing-group member cannot also be an exit client',
        });
      }
    }

    if (group.enabled) {
      if (group.memberClientIds.length === 0) {
        context.addIssue({
          code: 'custom',
          path: ['memberClientIds'],
          message: 'Enabled routing groups require at least one member',
        });
      }
      if (!group.exits.some((exit) => exit.enabled)) {
        context.addIssue({
          code: 'custom',
          path: ['exits'],
          message: 'Enabled routing groups require an enabled exit candidate',
        });
      }
      if (group.routedIpv4Prefixes.length === 0) {
        context.addIssue({
          code: 'custom',
          path: ['routedIpv4Prefixes'],
          message: 'Enabled routing groups require at least one IPv4 prefix',
        });
      }
    }

    if (
      group.memberClientIds.length * group.routedIpv4Prefixes.length >
      ROUTING_GROUP_RULE_LIMIT
    ) {
      context.addIssue({
        code: 'custom',
        message: `A routing group may generate at most ${ROUTING_GROUP_RULE_LIMIT} member-prefix rules`,
      });
    }
  });

export const schemaLimits = {
  linuxInterfaceNameMaxBytes: LINUX_INTERFACE_NAME_MAX_BYTES,
  routingSlotMin: ROUTING_SLOT_MIN,
  routingSlotMax: ROUTING_SLOT_MAX,
  routingGroupExitLimit: ROUTING_GROUP_EXIT_LIMIT,
  routingGroupPrefixLimit: ROUTING_GROUP_PREFIX_LIMIT,
  routingGroupMemberLimit: ROUTING_GROUP_MEMBER_LIMIT,
  routingGroupRuleLimit: ROUTING_GROUP_RULE_LIMIT,
} as const;
