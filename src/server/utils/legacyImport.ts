import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { isIP } from 'node:net';

import { parseCidr, containsCidr } from 'cidr-tools';
import { stringifyIp } from 'ip-bigint';
import z from 'zod';

import {
  InterfaceNameSchema,
  NetworkDeviceSchema,
  Ipv6CidrSchema,
} from '#shared/utils/schemas';
import {
  MtuSchema,
  PortSchema,
  PersistentKeepaliveSchema,
  HookSchema,
  HSchema,
} from '#server/utils/types';

export const IMPORT_BYTE_LIMIT = 10 * 1024 * 1024;
export type ImportIssue = { code: string; field?: string; client?: number };
export class LegacyImportError extends Error {
  constructor(public readonly issues: ImportIssue[]) {
    super('Legacy import validation failed');
  }
}
function fail(code: string, field?: string, client?: number): never {
  throw new LegacyImportError([{ code, field, client }]);
}
const text = z
  .string()
  .max(1024)
  // eslint-disable-next-line no-control-regex
  .regex(/^[^\x00-\x1f\x7f]*$/);
const key = z
  .string()
  .regex(/^[A-Za-z0-9+/]{43}=$/)
  .refine((v) => Buffer.from(v, 'base64').toString('base64') === v);
const legacyNumber = z.union([
  z.number().int().nonnegative(),
  z.string().max(10).regex(/^\d+$/).transform(Number),
]);
const legacyHeader = z.union([
  z
    .string()
    .max(31)
    .regex(/^\d+(-\d+)?$/),
  z.number().int().nonnegative(),
]);
const awgFields = {
  jc: legacyNumber.optional(),
  jmin: legacyNumber.optional(),
  jmax: legacyNumber.optional(),
  s1: legacyNumber.optional(),
  s2: legacyNumber.optional(),
  h1: legacyHeader.optional(),
  h2: legacyHeader.optional(),
  h3: legacyHeader.optional(),
  h4: legacyHeader.optional(),
};
const legacyClient = z.strictObject({
  id: text.optional(),
  name: text.min(1),
  address: z.ipv4(),
  privateKey: key,
  publicKey: key,
  preSharedKey: z.union([key, z.literal(''), z.null()]).optional(),
  enabled: z.boolean(),
  createdAt: text.nullish(),
  updatedAt: text.nullish(),
  expiredAt: text.nullish(),
  oneTimeLink: text.nullish(),
  oneTimeLinkExpiresAt: text.nullish(),
});
const backupSchema = z.strictObject({
  server: z.strictObject({
    privateKey: key,
    publicKey: key,
    address: z.ipv4(),
    ...awgFields,
  }),
  clients: z.record(z.string(), legacyClient),
});
const host = text
  .min(1)
  .refine(
    (v) =>
      isIP(v) !== 0 ||
      /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(v)
  );
const prefix = text.refine((v) => {
  try {
    return parseCidr(v).prefixPresent;
  } catch {
    return false;
  }
});
export const LegacyImportSettingsSchema = z.strictObject({
  name: InterfaceNameSchema,
  device: NetworkDeviceSchema,
  listenPort: PortSchema.int(),
  ipv6Cidr: Ipv6CidrSchema,
  endpointHost: host.transform((v) => (isIP(v) === 6 ? `[${v}]` : v)),
  endpointPort: PortSchema.int(),
  dns: z.array(host).max(16),
  allowedIps: z.array(prefix).min(1).max(64),
  mtu: MtuSchema.int(),
  persistentKeepalive: PersistentKeepaliveSchema.int(),
  hooks: z.strictObject({
    preUp: z.string().max(8192).pipe(HookSchema),
    postUp: z.string().max(8192).pipe(HookSchema),
    preDown: z.string().max(8192).pipe(HookSchema),
    postDown: z.string().max(8192).pipe(HookSchema),
  }),
  hooksReviewed: z.literal(true),
  mode: z.enum(['wireguard-compatible', 'amneziawg']),
  awg: z.strictObject(awgFields).optional(),
});
export type LegacyImportSettings = z.infer<typeof LegacyImportSettingsSchema>;
export type LegacyBackup = z.infer<typeof backupSchema>;
export type ImportTargetState = {
  interfaces: {
    name: string;
    port: number;
    ipv4Cidr: string;
    ipv6Cidr: string;
    publicKey: string;
  }[];
  clients: { publicKey: string; ipv4Address: string; ipv6Address: string }[];
};

// No reviver, recursive traversal, or value-bearing parser errors.
export function parseImportJson(raw: string): unknown {
  if (Buffer.byteLength(raw) > IMPORT_BYTE_LIMIT) fail('too_large');
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return fail('invalid_file');
  }
  const pending: { value: unknown; depth: number }[] = [{ value, depth: 0 }];
  while (pending.length) {
    const entry = pending.pop()!;
    if (entry.depth > 8) fail('invalid_file');
    if (entry.value && typeof entry.value === 'object') {
      for (const [name, child] of Object.entries(entry.value)) {
        if (['__proto__', 'constructor', 'prototype'].includes(name))
          fail('invalid_file');
        pending.push({ value: child, depth: entry.depth + 1 });
      }
    }
  }
  return value;
}

export function deriveImportPublicKey(privateKey: string) {
  const privateObject = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      Buffer.from(privateKey, 'base64'),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  return createPublicKey(privateObject)
    .export({ format: 'der', type: 'spki' })
    .subarray(-32)
    .toString('base64');
}
function timestamp(value: string | null | undefined) {
  if (!value || !z.iso.datetime({ offset: true }).safeParse(value).success)
    return null;
  return new Date(value).toISOString();
}
export function inspectLegacyBackup(file: string) {
  const raw = parseImportJson(file);
  if (
    raw &&
    typeof raw === 'object' &&
    'clients' in raw &&
    raw.clients &&
    typeof raw.clients === 'object' &&
    Object.keys(raw.clients).length > 4096
  )
    fail('too_many_clients');
  const result = backupSchema.safeParse(raw);
  if (!result.success) fail('invalid_file');
  const backup = result.data;
  const clients = Object.values(backup.clients);
  const cidr = parseCidr(`${backup.server.address}/24`);
  const ipv4Cidr = `${stringifyIp({ number: cidr.start, version: 4 })}/24`;
  if (
    backup.server.address !==
    stringifyIp({ number: cidr.start + 1n, version: 4 })
  )
    fail('server_address');
  const identities = new Set<string>();
  for (const [index, identity] of [backup.server, ...clients].entries()) {
    if (deriveImportPublicKey(identity.privateKey) !== identity.publicKey)
      fail('key_mismatch', undefined, index || undefined);
    if (identities.has(identity.publicKey))
      fail('credential_conflict', undefined, index || undefined);
    identities.add(identity.publicKey);
  }
  const addresses = new Set<string>();
  const warnings: ImportIssue[] = [];
  clients.forEach((client, index) => {
    const number = parseCidr(`${client.address}/32`).start;
    if (number <= cidr.start + 1n || number >= cidr.end)
      fail('client_address', undefined, index + 1);
    if (addresses.has(client.address))
      fail('address_conflict', undefined, index + 1);
    addresses.add(client.address);
    if (client.expiredAt && !timestamp(client.expiredAt))
      fail('invalid_expiry', undefined, index + 1);
    if (!timestamp(client.createdAt) || !timestamp(client.updatedAt))
      warnings.push({ code: 'timestamp_default', client: index + 1 });
  });
  const awg = Object.fromEntries(
    Object.keys(awgFields)
      .filter((k) => backup.server[k as keyof typeof awgFields] !== undefined)
      .map((k) => [k, backup.server[k as keyof typeof awgFields]])
  );
  return {
    backup,
    clients,
    ipv4Cidr,
    warnings,
    detectedMode: Object.keys(awg).length
      ? ('amneziawg' as const)
      : ('wireguard-compatible' as const),
    awg,
  };
}
export type InspectedImport = ReturnType<typeof inspectLegacyBackup>;
export function importSummary(source: InspectedImport) {
  return {
    ipv4Cidr: source.ipv4Cidr,
    detectedMode: source.detectedMode,
    awg: source.awg,
    count: source.clients.length,
    enabledCount: source.clients.filter((client) => client.enabled).length,
    expiringCount: source.clients.filter((client) => client.expiredAt).length,
    clients: source.clients.map((client, index) => ({
      index: index + 1,
      name: client.name,
      address: client.address,
      enabled: client.enabled,
      expiresAt: timestamp(client.expiredAt),
      fingerprint: createHash('sha256')
        .update(Buffer.from(client.publicKey, 'base64'))
        .digest('hex')
        .slice(0, 16),
    })),
  };
}
export function prepareLegacyImport(source: InspectedImport, input: unknown) {
  const parsed = LegacyImportSettingsSchema.safeParse(input);
  if (!parsed.success) {
    throw new LegacyImportError(
      parsed.error.issues.map((issue) => ({
        code: 'invalid_setting',
        field:
          typeof issue.path[0] === 'string' &&
          issue.path[0] in LegacyImportSettingsSchema.shape
            ? issue.path[0]
            : 'settings',
      }))
    );
  }
  const settings = parsed.data;
  const awg = { ...source.awg, ...settings.awg };
  const parameters = {
    jC: null,
    jMin: null,
    jMax: null,
    s1: null,
    s2: null,
    h1: null,
    h2: null,
    h3: null,
    h4: null,
  } as {
    jC: number | null;
    jMin: number | null;
    jMax: number | null;
    s1: number | null;
    s2: number | null;
    h1: string | null;
    h2: string | null;
    h3: string | null;
    h4: string | null;
  };
  if (settings.mode === 'amneziawg') {
    const numeric = z
      .strictObject({
        jc: z.number().int().min(1).max(128),
        jmin: z.number().int().min(0).max(1279),
        jmax: z.number().int().min(0).max(1280),
        s1: z.number().int().min(0).max(1132),
        s2: z.number().int().min(0).max(1132),
        h1: z
          .union([z.number(), z.string()])
          .transform(String)
          .pipe(HSchema.unwrap()),
        h2: z
          .union([z.number(), z.string()])
          .transform(String)
          .pipe(HSchema.unwrap()),
        h3: z
          .union([z.number(), z.string()])
          .transform(String)
          .pipe(HSchema.unwrap()),
        h4: z
          .union([z.number(), z.string()])
          .transform(String)
          .pipe(HSchema.unwrap()),
      })
      .safeParse(awg);
    if (!numeric.success) fail('invalid_awg', 'awg');
    const a = numeric.data;
    const ranges = [a.h1, a.h2, a.h3, a.h4].map((h) => {
      const [lo, hi] = h.split('-').map(Number);
      return [lo!, hi ?? lo!] as const;
    });
    if (
      a.jmin > a.jmax ||
      ranges.some((r, i) =>
        ranges.slice(i + 1).some((s) => r[0] <= s[1] && s[0] <= r[1])
      )
    )
      fail('invalid_awg', 'awg');
    Object.assign(parameters, {
      jC: a.jc,
      jMin: a.jmin,
      jMax: a.jmax,
      s1: a.s1,
      s2: a.s2,
      h1: a.h1,
      h2: a.h2,
      h3: a.h3,
      h4: a.h4,
    });
  }
  const cidr6 = parseCidr(settings.ipv6Cidr);
  if (BigInt(source.clients.length) > cidr6.end - cidr6.start - 2n)
    fail('ipv6_capacity', 'ipv6Cidr');
  const now = new Date().toISOString();
  return {
    source,
    settings,
    parameters,
    clients: source.clients.map((c, i) => ({
      name: c.name,
      enabled: c.enabled,
      privateKey: c.privateKey,
      publicKey: c.publicKey,
      preSharedKey: c.preSharedKey || null,
      ipv4Address: c.address,
      ipv6Address: stringifyIp({
        number: cidr6.start + 2n + BigInt(i),
        version: 6,
      }),
      expiresAt: timestamp(c.expiredAt),
      createdAt: timestamp(c.createdAt) ?? now,
      updatedAt: timestamp(c.updatedAt) ?? now,
    })),
  };
}
export type PreparedImport = ReturnType<typeof prepareLegacyImport>;
export function validateImportReservations(
  plan: PreparedImport,
  state: ImportTargetState
) {
  const { settings, source } = plan;
  for (const existing of state.interfaces) {
    if (existing.name === settings.name) fail('name_conflict', 'name');
    if (existing.port === settings.listenPort)
      fail('port_conflict', 'listenPort');
    for (const [a, b, field] of [
      [existing.ipv4Cidr, source.ipv4Cidr, 'ipv4Cidr'],
      [existing.ipv6Cidr, settings.ipv6Cidr, 'ipv6Cidr'],
    ] as const) {
      if (containsCidr(a, b) || containsCidr(b, a))
        fail('cidr_conflict', field);
    }
  }
  const keys = new Set(
    [...state.interfaces, ...state.clients].map((c) => c.publicKey)
  );
  if (
    [source.backup.server, ...plan.clients].some((c) => keys.has(c.publicKey))
  )
    fail('credential_conflict');
  const addresses = new Set(
    state.clients.flatMap((c) => [c.ipv4Address, c.ipv6Address])
  );
  if (
    plan.clients.some(
      (c) => addresses.has(c.ipv4Address) || addresses.has(c.ipv6Address)
    )
  )
    fail('address_conflict');
}
