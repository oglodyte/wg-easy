import { eq, sql, or, like, and, inArray } from 'drizzle-orm';
import { parseCidr } from 'cidr-tools';

import { client } from './schema';
import type {
  ClientCreateFromExistingType,
  ClientConfigurationCreateType,
  ClientConfigurationUpdateType,
  ClientQueryType,
} from './types';
import {
  ClientConfigurationCreateSchema,
  ClientConfigurationUpdateSchema,
} from './types';

import { nextIP } from '#server/utils/ip';
import {
  RoutingValidationError,
  canonicalizeServerAllowedIps,
  findRoutingPrefixConflicts,
  findServerAllowedIpConflicts,
} from '#server/utils/routing';
import type { ID } from '#server/utils/types';
import {
  prepareClientCredentials,
  ClientCredentialError,
} from '#server/utils/clientCredentials';
import { PolicyValidationError } from '#server/utils/routingPolicy';
import { bumpDesiredRevision } from '#db/repositories/runtime/service';
import type { DBType } from '#db/sqlite';
import {
  routingGroupExit,
  routingGroupMember,
  routingGroupRuntimeState,
  userConfig,
  wgInterface,
} from '#db/schema';

export class InterfaceUnavailableForClientCreationError extends Error {}
export class ClientConflictError extends Error {
  constructor(
    message: string,
    readonly code:
      | 'credential_conflict'
      | 'enabled_identity_conflict' = 'enabled_identity_conflict'
  ) {
    super(message);
  }
}
export class ClientConfigurationError extends Error {
  constructor(
    readonly code:
      | 'invalid_configuration'
      | 'invalid_server_prefixes'
      | 'invalid_address'
      | 'format_unavailable'
      | 'policy_version_required'
      | 'write_failed',
    readonly field?: 'ipv4Address' | 'ipv6Address'
  ) {
    super(
      code === 'invalid_server_prefixes'
        ? 'Server allowed IPs must be non-default CIDRs; use a routing group for default routing'
        : code === 'invalid_address'
          ? `${field === 'ipv6Address' ? 'IPv6' : 'IPv4'} address is not within the CIDR range or is reserved`
          : `Client configuration: ${code}`
    );
    this.name = 'ClientConfigurationError';
  }
}

export class ClientRoutingReferenceError extends Error {
  readonly kind: 'exit' | 'member';
  readonly groupIds: number[];

  constructor(kind: 'exit' | 'member', groupIds: number[], message: string) {
    super(message);
    this.name = 'ClientRoutingReferenceError';
    this.kind = kind;
    this.groupIds = groupIds;
  }
}

type ClientTransaction = Parameters<Parameters<DBType['transaction']>[0]>[0];

async function assertCredentialIdentityAvailable(
  tx: ClientTransaction,
  id: ID,
  candidate: { interfaceId: string; publicKey: string }
) {
  const [servers, reused] = await Promise.all([
    tx.query.wgInterface.findMany({ columns: { publicKey: true } }).execute(),
    tx.query.client
      .findMany({
        columns: { id: true, interfaceId: true },
        where: and(
          eq(client.publicKey, candidate.publicKey),
          sql`${client.id} <> ${id}`
        ),
      })
      .execute(),
  ]);
  if (
    servers.some((s) => s.publicKey === candidate.publicKey) ||
    reused.some((c) => c.interfaceId !== candidate.interfaceId)
  )
    throw new ClientConflictError(
      'VPN credentials cannot be reused across managed interfaces or server identities',
      'credential_conflict'
    );
}

function assertClientAddresses(
  iface: { ipv4Cidr: string; ipv6Cidr: string | null },
  candidate: { ipv4Address: string; ipv6Address: string | null }
) {
  try {
    const network = parseCidr(iface.ipv4Cidr),
      address = parseCidr(`${candidate.ipv4Address}/32`);
    if (address.start <= network.start + 1n || address.start >= network.end)
      throw new Error();
  } catch {
    throw new ClientConfigurationError('invalid_address', 'ipv4Address');
  }
  try {
    if (iface.ipv6Cidr) {
      if (!candidate.ipv6Address) throw new Error();
      const network6 = parseCidr(iface.ipv6Cidr),
        address6 = parseCidr(`${candidate.ipv6Address}/128`);
      if (
        address6.start <= network6.start + 1n ||
        address6.start >= network6.end
      )
        throw new Error();
    } else if (candidate.ipv6Address !== null) throw new Error();
  } catch {
    throw new ClientConfigurationError('invalid_address', 'ipv6Address');
  }
}

async function assertFullConfigurationAvailable(
  tx: ClientTransaction,
  advanced: boolean
) {
  const settings = await tx.query.general
    .findFirst({ columns: { routingPolicyVersion: true } })
    .execute();
  if (
    !settings ||
    ![1, 2].includes(settings.routingPolicyVersion) ||
    (advanced && settings.routingPolicyVersion !== 2)
  )
    throw new ClientConfigurationError('policy_version_required');
}

function assertClientFormat(
  iface: { awgParametersEnabled: boolean },
  preferred: string
) {
  if (preferred === 'wireguard' && iface.awgParametersEnabled)
    throw new ClientConfigurationError('format_unavailable');
}

function assertClientAwgOverrides(
  iface: { jMin: number | null; jMax: number | null },
  candidate: { jMin: number | null; jMax: number | null }
) {
  const minimum = candidate.jMin ?? iface.jMin,
    maximum = candidate.jMax ?? iface.jMax;
  if (minimum !== null && maximum !== null && minimum > maximum)
    throw new ClientConfigurationError('invalid_configuration');
}

async function assertEnabledIdentityAvailable(
  tx: ClientTransaction,
  id: ID,
  candidate: {
    enabled: boolean;
    publicKey: string;
    interfaceId: string;
    ipv4Address: string;
    ipv6Address: string | null;
  }
) {
  if (!candidate.enabled) return;
  const conflicts = await tx.query.client
    .findMany({
      columns: { id: true },
      where: and(
        eq(client.enabled, true),
        sql`${client.id} <> ${id}`,
        or(
          and(
            eq(client.interfaceId, candidate.interfaceId),
            eq(client.publicKey, candidate.publicKey)
          ),
          eq(client.ipv4Address, candidate.ipv4Address),
          candidate.ipv6Address
            ? eq(client.ipv6Address, candidate.ipv6Address)
            : undefined
        )
      ),
    })
    .execute();
  if (conflicts.length)
    throw new ClientConflictError(
      'An enabled client already uses this tunnel address or VPN identity'
    );
}

async function validateServerAllowedIpsUpdate(
  tx: ClientTransaction,
  clientId: number,
  prefixes: readonly string[],
  persistentKeepalive: number
) {
  const normalized = canonicalizeServerAllowedIps(prefixes);
  const [clients, groups, exits, general] = await Promise.all([
    tx.query.client.findMany().execute(),
    tx.query.routingGroup.findMany().execute(),
    tx.query.routingGroupExit.findMany().execute(),
    tx.query.general.findFirst().execute(),
  ]);
  if (!general) throw new Error('General Config not found');
  const assignments = clients.map((existing) => ({
    ...existing,
    serverAllowedIps:
      existing.id === clientId ? normalized : existing.serverAllowedIps,
  }));
  const conflictGroups = groups.map((group) => ({
    id: group.id,
    enabled: group.enabled,
    routedIpv4Prefixes: group.routedIpv4Prefixes,
    exits: exits
      .filter(({ groupId }) => groupId === group.id)
      .map(({ clientId: exitClientId, enabled }) => ({
        clientId: exitClientId,
        enabled,
      })),
  }));
  const issues = [
    ...findServerAllowedIpConflicts(assignments),
    ...(general.routingPolicyVersion === 1
      ? findRoutingPrefixConflicts({
          clients: assignments,
          groups: conflictGroups,
        })
      : []),
  ];
  const enabledGroupIds = new Set(
    groups.filter(({ enabled }) => enabled).map(({ id }) => id)
  );
  const isEnabledExit = exits.some(
    (exit) =>
      exit.clientId === clientId &&
      exit.enabled &&
      enabledGroupIds.has(exit.groupId)
  );
  const maximumKeepalive = Math.floor(
    general.routingExitHealthTimeoutSeconds / 3
  );
  if (
    isEnabledExit &&
    (persistentKeepalive <= 0 || persistentKeepalive > maximumKeepalive)
  ) {
    issues.push({
      code: 'exit_keepalive_invalid',
      message: `Exit client ${clientId} persistent keepalive must be between 1 and ${maximumKeepalive} seconds`,
      clientIds: [clientId],
    });
  }
  if (issues.length > 0) throw new RoutingValidationError(issues);
  return normalized;
}

function createPreparedStatement(db: DBType) {
  return {
    findAll: db.query.client
      .findMany({
        with: {
          oneTimeLink: true,
        },
      })
      .prepare(),
    findById: db.query.client
      .findFirst({ where: eq(client.id, sql.placeholder('id')) })
      .prepare(),
  };
}

export class ClientService {
  #db: DBType;
  #statements: ReturnType<typeof createPreparedStatement>;

  constructor(db: DBType) {
    this.#db = db;
    this.#statements = createPreparedStatement(db);
  }

  /**
   * Never return values directly from this function. Use {@link getAllPublic} instead.
   */
  async getAll() {
    const result = await this.#statements.findAll.execute();
    return result.map((row) => ({
      ...row,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    }));
  }

  async getAllForInterface(interfaceId: string) {
    const result = await this.#db.query.client
      .findMany({
        where: eq(client.interfaceId, interfaceId),
        with: { oneTimeLink: true },
      })
      .execute();
    return result.map((row) => ({
      ...row,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    }));
  }

  async getAllForInterfaces(interfaceIds: readonly string[]) {
    const clients = await Promise.all(
      [...new Set(interfaceIds)].map((interfaceId) =>
        this.getAllForInterface(interfaceId)
      )
    );
    return clients.flat();
  }

  /**
   * Returns all clients without sensitive data
   */
  async getAllPublic({ filter, sort, interfaceId }: ClientQueryType = {}) {
    const filters = [];

    if (filter?.trim()) {
      const filterPattern = `%${filter?.toLowerCase()}%`;
      filters.push(
        or(
          like(client.name, filterPattern),
          like(client.ipv4Address, filterPattern),
          like(client.ipv6Address, filterPattern)
        )
      );
    }
    if (interfaceId) filters.push(eq(client.interfaceId, interfaceId));

    const result = await this.#db.query.client
      .findMany({
        with: {
          oneTimeLink: true,
        },
        where: and(...filters),
        columns: {
          privateKey: false,
          preSharedKey: false,
        },
        orderBy: (t, { asc, desc }) => {
          if (sort === 'desc') {
            return desc(t.name);
          } else {
            // default to asc
            return asc(t.name);
          }
        },
      })
      .execute();

    return result.map((row) => ({
      ...row,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    }));
  }

  /**
   * Returns all clients without sensitive data belonging to user
   */
  async getAllForUser(
    userId: ID,
    { filter, sort, interfaceId }: ClientQueryType = {}
  ) {
    const filters = [];

    if (filter?.trim()) {
      const filterPattern = `%${filter?.toLowerCase()}%`;
      filters.push(
        or(
          like(client.name, filterPattern),
          like(client.ipv4Address, filterPattern),
          like(client.ipv6Address, filterPattern)
        )
      );
    }
    if (interfaceId) filters.push(eq(client.interfaceId, interfaceId));

    const result = await this.#db.query.client
      .findMany({
        where: and(eq(client.userId, userId), ...filters),
        with: { oneTimeLink: true },
        columns: {
          privateKey: false,
          preSharedKey: false,
        },
        orderBy: (t, { asc, desc }) => {
          if (sort === 'desc') {
            return desc(t.name);
          } else {
            // default to asc
            return asc(t.name);
          }
        },
      })
      .execute();

    return result.map((row) => ({
      ...row,
      createdAt: new Date(row.createdAt),
      updatedAt: new Date(row.updatedAt),
    }));
  }

  get(id: ID) {
    return this.#statements.findById.execute({ id });
  }

  async #write<T>(operation: (tx: ClientTransaction) => Promise<T>) {
    try {
      return await this.#db.transaction(operation);
    } catch (error) {
      if (
        error instanceof ClientConfigurationError ||
        error instanceof ClientConflictError ||
        error instanceof ClientCredentialError ||
        error instanceof ClientRoutingReferenceError ||
        error instanceof InterfaceUnavailableForClientCreationError ||
        error instanceof RoutingValidationError ||
        error instanceof PolicyValidationError
      )
        throw error;
      // Drizzle driver messages can contain every private SQL bind. Never retain
      // the cause on an error returned to API/CLI callers or ordinary logs.
      throw new ClientConfigurationError('write_failed');
    }
  }

  async create(input: ClientConfigurationCreateType) {
    const parsed = ClientConfigurationCreateSchema.safeParse(input);
    if (!parsed.success)
      throw new ClientConfigurationError('invalid_configuration');
    const data = parsed.data,
      credentials = prepareClientCredentials(data);
    return this.#write(async (tx) => {
      await assertFullConfigurationAvailable(
        tx,
        Object.entries(data).some(
          ([key, value]) =>
            value !== undefined &&
            !['name', 'expiresAt', 'interfaceId'].includes(key)
        )
      );
      const generalConfig = await tx.query.general
        .findFirst({ columns: { defaultInterfaceId: true } })
        .execute();
      if (!generalConfig) throw new Error();
      const selectedInterfaceId =
        data.interfaceId ?? generalConfig.defaultInterfaceId;
      const [clients, clientInterface, defaults] = await Promise.all([
        tx.query.client
          .findMany({ where: eq(client.interfaceId, selectedInterfaceId) })
          .execute(),
        tx.query.wgInterface
          .findFirst({ where: eq(wgInterface.name, selectedInterfaceId) })
          .execute(),
        tx.query.userConfig
          .findFirst({ where: eq(userConfig.id, selectedInterfaceId) })
          .execute(),
      ]);
      if (!clientInterface || !defaults) throw new Error();
      if (clientInterface.pendingDelete)
        throw new InterfaceUnavailableForClientCreationError(
          'WireGuard interface is pending deletion'
        );
      const ipv4Address =
          data.ipv4Address ??
          nextIP(4, parseCidr(clientInterface.ipv4Cidr), clients),
        ipv6Address =
          data.ipv6Address === undefined
            ? clientInterface.ipv6Cidr
              ? nextIP(6, parseCidr(clientInterface.ipv6Cidr), clients)
              : null
            : data.ipv6Address;
      assertClientAddresses(clientInterface, { ipv4Address, ipv6Address });
      assertClientFormat(clientInterface, data.preferredConfigFormat ?? 'auto');
      assertClientAwgOverrides(clientInterface, {
        jMin: data.jMin === undefined ? defaults.defaultJMin : data.jMin,
        jMax: data.jMax === undefined ? defaults.defaultJMax : data.jMax,
      });
      await assertCredentialIdentityAvailable(tx, 0, {
        interfaceId: selectedInterfaceId,
        publicKey: credentials.publicKey,
      });
      await assertEnabledIdentityAvailable(tx, 0, {
        interfaceId: selectedInterfaceId,
        publicKey: credentials.publicKey,
        ipv4Address,
        ipv6Address,
        enabled: data.enabled ?? true,
      });
      const {
        interfaceId: _interface,
        privateKey: _private,
        publicKey: _public,
        preSharedKey: _psk,
        ...fields
      } = data;
      const overrides = Object.fromEntries(
        Object.entries(fields).filter(([, value]) => value !== undefined)
      );
      const result = await tx
        .insert(client)
        .values({
          name: data.name,
          userId: 1,
          interfaceId: selectedInterfaceId,
          expiresAt: null,
          mtu: defaults.defaultMtu,
          jC: defaults.defaultJC,
          jMin: defaults.defaultJMin,
          jMax: defaults.defaultJMax,
          i1: defaults.defaultI1,
          i2: defaults.defaultI2,
          i3: defaults.defaultI3,
          i4: defaults.defaultI4,
          i5: defaults.defaultI5,
          persistentKeepalive: defaults.defaultPersistentKeepalive,
          enabled: true,
          ...overrides,
          ipv4Address,
          ipv6Address,
          ...credentials,
          serverAllowedIps: canonicalizeServerAllowedIps(
            data.serverAllowedIps ?? []
          ),
        })
        .returning({ clientId: client.id })
        .execute();
      const id = result[0]!.clientId;
      await validateServerAllowedIpsUpdate(
        tx,
        id,
        data.serverAllowedIps ?? [],
        data.persistentKeepalive ?? defaults.defaultPersistentKeepalive
      );
      await bumpDesiredRevision(tx, [selectedInterfaceId]);
      return result;
    });
  }

  toggle(id: ID, enabled: boolean) {
    return this.#write(async (tx) => {
      const existing = await tx.query.client
        .findFirst({ where: eq(client.id, id) })
        .execute();
      if (!existing) throw new Error('Client not found');
      await assertEnabledIdentityAvailable(tx, id, { ...existing, enabled });
      await tx
        .update(client)
        .set({ enabled })
        .where(eq(client.id, id))
        .execute();
      await bumpDesiredRevision(tx, [existing.interfaceId]);
    });
  }

  delete(id: ID, { removeRoutingMembership = false } = {}) {
    return this.#write(async (tx) => {
      const existing = await tx.query.client
        .findFirst({ where: eq(client.id, id) })
        .execute();
      if (!existing) throw new Error('Client not found');
      const [exitReferences, memberReferences] = await Promise.all([
        tx.query.routingGroupExit
          .findMany({ where: eq(routingGroupExit.clientId, id) })
          .execute(),
        tx.query.routingGroupMember
          .findMany({ where: eq(routingGroupMember.clientId, id) })
          .execute(),
      ]);
      if (exitReferences.length > 0) {
        const groupIds = exitReferences.map(({ groupId }) => groupId);
        throw new ClientRoutingReferenceError(
          'exit',
          groupIds,
          `Client deletion is blocked while it is an exit for routing group(s) ${groupIds.join(', ')}`
        );
      }
      if (memberReferences.length > 0 && !removeRoutingMembership) {
        const groupIds = memberReferences.map(({ groupId }) => groupId);
        throw new ClientRoutingReferenceError(
          'member',
          groupIds,
          `Client belongs to routing group(s) ${groupIds.join(', ')}; confirm membership removal before deletion`
        );
      }
      if (memberReferences.length > 0) {
        await tx
          .delete(routingGroupMember)
          .where(eq(routingGroupMember.clientId, id))
          .execute();
      }
      await tx.delete(client).where(eq(client.id, id)).execute();
      const revision = await bumpDesiredRevision(tx, [existing.interfaceId]);
      if (memberReferences.length > 0) {
        const groupIds = [
          ...new Set(memberReferences.map(({ groupId }) => groupId)),
        ];
        await tx
          .update(routingGroupRuntimeState)
          .set({
            selectedExitClientId: null,
            appliedExitClientId: null,
            evaluatedRevision: revision,
            appliedRevision: null,
            selectedSince: null,
            appliedSince: null,
            status: 'draft_invalid',
            reason:
              'A member was explicitly removed during client deletion; review the routing group before enabling execution.',
          })
          .where(inArray(routingGroupRuntimeState.groupId, groupIds))
          .execute();
      }
    });
  }

  async update(id: ID, input: ClientConfigurationUpdateType) {
    const parsed = ClientConfigurationUpdateSchema.safeParse(input);
    if (!parsed.success)
      throw new ClientConfigurationError(
        parsed.error.issues.some(
          (issue) => issue.path[0] === 'serverAllowedIps'
        )
          ? 'invalid_server_prefixes'
          : 'invalid_configuration'
      );
    const data = parsed.data;
    return this.#write(async (tx) => {
      const existingClient = await tx.query.client
        .findFirst({ where: eq(client.id, id) })
        .execute();
      if (!existingClient) throw new Error();
      await assertFullConfigurationAvailable(
        tx,
        (
          [
            'privateKey',
            'publicKey',
            'preSharedKey',
            'preferredConfigFormat',
          ] as const
        ).some(
          (key) => data[key] !== undefined && data[key] !== existingClient[key]
        )
      );
      const clientInterface = await tx.query.wgInterface
        .findFirst({ where: eq(wgInterface.name, existingClient.interfaceId) })
        .execute();
      if (!clientInterface) throw new Error();
      const credentials = prepareClientCredentials(data, existingClient),
        candidate = { ...existingClient, ...data, ...credentials };
      assertClientAddresses(clientInterface, candidate);
      assertClientFormat(
        clientInterface,
        data.preferredConfigFormat ?? existingClient.preferredConfigFormat
      );
      assertClientAwgOverrides(clientInterface, candidate);
      const serverAllowedIps = await validateServerAllowedIpsUpdate(
        tx,
        id,
        data.serverAllowedIps,
        data.persistentKeepalive
      );
      await assertCredentialIdentityAvailable(tx, id, candidate);
      await assertEnabledIdentityAvailable(tx, id, candidate);
      await tx
        .update(client)
        .set({ ...data, ...credentials, serverAllowedIps })
        .where(eq(client.id, id))
        .execute();
      await bumpDesiredRevision(tx, [existingClient.interfaceId]);
    });
  }

  async createFromExisting({
    name,
    enabled,
    ipv4Address,
    ipv6Address,
    preSharedKey,
    privateKey,
    publicKey,
    interfaceId,
  }: ClientCreateFromExistingType) {
    const credentials = prepareClientCredentials({
      privateKey,
      publicKey,
      preSharedKey: preSharedKey || null,
    });
    return this.#write(async (tx) => {
      const [clientConfig, iface] = await Promise.all([
        tx.query.userConfig
          .findFirst({ where: eq(userConfig.id, interfaceId) })
          .execute(),
        tx.query.wgInterface
          .findFirst({ where: eq(wgInterface.name, interfaceId) })
          .execute(),
      ]);
      if (!clientConfig || !iface || iface.pendingDelete)
        throw new InterfaceUnavailableForClientCreationError(
          'Interface is unavailable for legacy client creation'
        );
      assertClientAddresses(iface, { ipv4Address, ipv6Address });
      await assertCredentialIdentityAvailable(tx, 0, {
        interfaceId,
        publicKey: credentials.publicKey,
      });
      await assertEnabledIdentityAvailable(tx, 0, {
        interfaceId,
        enabled,
        ipv4Address,
        ipv6Address,
        publicKey: credentials.publicKey,
      });
      const result = await tx
        .insert(client)
        .values({
          name,
          userId: 1,
          interfaceId,
          ...credentials,
          ipv4Address,
          ipv6Address,
          mtu: clientConfig.defaultMtu,
          jC: clientConfig.defaultJC,
          jMin: clientConfig.defaultJMin,
          jMax: clientConfig.defaultJMax,
          i1: clientConfig.defaultI1,
          i2: clientConfig.defaultI2,
          i3: clientConfig.defaultI3,
          i4: clientConfig.defaultI4,
          i5: clientConfig.defaultI5,
          allowedIps: clientConfig.defaultAllowedIps,
          dns: clientConfig.defaultDns,
          persistentKeepalive: clientConfig.defaultPersistentKeepalive,
          serverAllowedIps: [],
          enabled,
        })
        .execute();
      await bumpDesiredRevision(tx, [interfaceId]);
      return result;
    });
  }
}
