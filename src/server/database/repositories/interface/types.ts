import type { InferSelectModel } from 'drizzle-orm';
import z from 'zod';

import type { wgInterface } from './schema';

import {
  EnabledSchema,
  HSchema,
  ISchema,
  JcSchema,
  JmaxSchema,
  JminSchema,
  MtuSchema,
  PortSchema,
  SSchema,
  schemaForType,
} from '#server/utils/types';
import {
  Ipv4CidrSchema,
  Ipv6CidrSchema,
  InterfaceNameSchema,
  NetworkDeviceSchema,
} from '#shared/utils/schemas';

export type InterfaceType = InferSelectModel<typeof wgInterface>;

export type InterfaceCreateType = Omit<
  InterfaceType,
  'createdAt' | 'updatedAt'
>;

export const InterfaceCreateSchema = z.object({
  name: InterfaceNameSchema,
  device: NetworkDeviceSchema,
  port: PortSchema,
  ipv4Cidr: Ipv4CidrSchema,
  ipv6Cidr: Ipv6CidrSchema,
  cloneFromInterfaceId: InterfaceNameSchema.optional(),
});

export type InterfaceCreateInput = z.infer<typeof InterfaceCreateSchema>;

export const InterfaceGetSchema = z.object({
  interfaceId: InterfaceNameSchema,
});

export type InterfaceUpdateType = Omit<
  InterfaceCreateType,
  | 'name'
  | 'createdAt'
  | 'updatedAt'
  | 'privateKey'
  | 'publicKey'
  | 'pendingDelete'
>;

const device = NetworkDeviceSchema;

export const InterfaceUpdateSchema = schemaForType<InterfaceUpdateType>()(
  z.object({
    ipv4Cidr: Ipv4CidrSchema,
    ipv6Cidr: Ipv6CidrSchema,
    mtu: MtuSchema,
    jC: JcSchema,
    jMin: JminSchema,
    jMax: JmaxSchema,
    s1: SSchema,
    s2: SSchema,
    s3: SSchema,
    s4: SSchema,
    h1: HSchema,
    h2: HSchema,
    h3: HSchema,
    h4: HSchema,
    i1: ISchema,
    i2: ISchema,
    i3: ISchema,
    i4: ISchema,
    i5: ISchema,
    port: PortSchema,
    device: device,
    enabled: EnabledSchema,
    firewallEnabled: EnabledSchema,
    awgParametersEnabled: EnabledSchema,
    defaultConfigFormat: z.enum(['wireguard', 'amneziawg']),
  })
).superRefine((value, context) => {
  if (value.awgParametersEnabled && value.defaultConfigFormat === 'wireguard') {
    context.addIssue({
      code: 'custom',
      path: ['defaultConfigFormat'],
      message:
        'WireGuard cannot be the default export format while AWG parameters are enabled',
    });
  }
});

export type InterfaceCidrUpdateType = {
  ipv4Cidr: string;
  ipv6Cidr: string;
};

export const InterfaceCidrUpdateSchema =
  schemaForType<InterfaceCidrUpdateType>()(
    z.object({
      ipv4Cidr: Ipv4CidrSchema,
      ipv6Cidr: Ipv6CidrSchema,
    })
  );
