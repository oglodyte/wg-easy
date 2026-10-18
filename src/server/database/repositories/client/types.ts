import type { InferSelectModel } from 'drizzle-orm';
import z from 'zod';
import { isIPv4, isIPv6 } from 'is-ip';

import type { client } from './schema';

import {
  AddressSchema,
  AllowedIpsSchema,
  DnsSchema,
  EnabledSchema,
  FirewallIpsSchema,
  HookSchema,
  ISchema,
  JcSchema,
  JmaxSchema,
  JminSchema,
  MtuSchema,
  PersistentKeepaliveSchema,
  controlStringRefine,
  safeStringRefine,
  schemaForType,
  t,
} from '#server/utils/types';
import {
  InterfaceNameSchema,
  ConfigFormatSchema,
  ServerAllowedIpsSchema,
} from '#shared/utils/schemas';

export type ClientType = InferSelectModel<typeof client>;

export type ClientNextIpType = Pick<ClientType, 'ipv4Address' | 'ipv6Address'>;

export type CreateClientType = Omit<
  ClientType,
  'createdAt' | 'updatedAt' | 'id'
>;

export type UpdateClientType = Omit<
  CreateClientType,
  | 'privateKey'
  | 'publicKey'
  | 'preSharedKey'
  | 'userId'
  | 'interfaceId'
  | 'preferredConfigFormat'
>;

const name = z
  .string({ message: t('zod.client.name') })
  .min(1, t('zod.client.name'))
  .pipe(safeStringRefine)
  .pipe(controlStringRefine);

// TODO?: validate iso string
const expiresAt = z
  .string({ message: t('zod.client.expiresAt') })
  .min(1, t('zod.client.expiresAt'))
  .pipe(safeStringRefine)
  .nullable();

const address4 = z
  .string({ message: t('zod.client.address4') })
  .min(1, { message: t('zod.client.address4') })
  .pipe(safeStringRefine)
  .pipe(controlStringRefine)
  .refine((v) => isIPv4(v));

const address6 = z
  .string({ message: t('zod.client.address6') })
  .min(1, { message: t('zod.client.address6') })
  .pipe(safeStringRefine)
  .pipe(controlStringRefine)
  .refine((v) => isIPv6(v));

export const ClientCreateSchema = z.object({
  name: name,
  expiresAt: expiresAt,
  interfaceId: InterfaceNameSchema.optional(),
});

export type ClientCreateType = z.infer<typeof ClientCreateSchema>;

const filter = z.string().pipe(safeStringRefine);

const sort = z.enum(['asc', 'desc']);

export const ClientQuerySchema = z.object({
  filter: filter.optional(),
  sort: sort.optional(),
  interfaceId: InterfaceNameSchema.optional(),
});

export type ClientQueryType = z.infer<typeof ClientQuerySchema>;

export const ClientUpdateSchema = schemaForType<UpdateClientType>()(
  z.object({
    name: name,
    enabled: EnabledSchema,
    expiresAt: expiresAt,
    ipv4Address: address4,
    ipv6Address: z
      .union([address6, z.literal(''), z.null()])
      .transform((v) => v || null),
    preUp: HookSchema,
    postUp: HookSchema,
    preDown: HookSchema,
    postDown: HookSchema,
    allowedIps: AllowedIpsSchema.nullable(),
    serverAllowedIps: ServerAllowedIpsSchema,
    firewallIps: FirewallIpsSchema.nullable(),
    mtu: MtuSchema,
    jC: JcSchema,
    jMin: JminSchema,
    jMax: JmaxSchema,
    i1: ISchema,
    i2: ISchema,
    i3: ISchema,
    i4: ISchema,
    i5: ISchema,
    persistentKeepalive: PersistentKeepaliveSchema,
    serverEndpoint: AddressSchema.nullable(),
    dns: DnsSchema.nullable(),
  })
);

// Prepared contracts only. Existing routes continue using the schemas above
// until the complete peer-aware runtime transition is available in Phase 2.
export const VpnKeySchema = z
  .string()
  .regex(/^[A-Za-z0-9+/]{43}=$/)
  .refine((value) => {
    // Canonical base64's unused final bits must be zero. This is browser-safe.
    const alphabet =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    return alphabet.indexOf(value[42] ?? '') % 4 === 0;
  }, 'Invalid VPN key');

const ClientCredentialFields = {
  privateKey: VpnKeySchema.optional(),
  publicKey: VpnKeySchema.optional(),
  preSharedKey: VpnKeySchema.nullable().optional(),
  preferredConfigFormat: ConfigFormatSchema.optional(),
};

export const ClientConfigurationUpdateSchema = ClientUpdateSchema.extend(
  ClientCredentialFields
);
export const ClientConfigurationCreateSchema =
  ClientUpdateSchema.partial().extend({
    ...ClientCredentialFields,
    name,
    expiresAt: expiresAt.optional(),
    interfaceId: InterfaceNameSchema.optional(),
  });

const clientId = z.coerce.number({ message: t('zod.client.id') });

export const ClientGetSchema = z.object({
  clientId: clientId,
});

export const ClientDeleteQuerySchema = z.object({
  removeRoutingMembership: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => value === 'true'),
});

export type ClientCreateFromExistingType = Pick<
  ClientType,
  | 'name'
  | 'ipv4Address'
  | 'ipv6Address'
  | 'privateKey'
  | 'preSharedKey'
  | 'publicKey'
  | 'enabled'
> & { interfaceId: string };
