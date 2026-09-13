import { eq } from 'drizzle-orm';

import type { DBType } from '#db/sqlite';
import {
  client,
  wgInterface,
  hooks,
  userConfig,
  interfaceRuntimeState,
} from '#db/schema';
import { bumpDesiredRevision } from '#db/repositories/runtime/service';
import {
  inspectLegacyBackup,
  prepareLegacyImport,
  validateImportReservations,
  importSummary,
  LegacyImportError,
} from '#server/utils/legacyImport';

export class LegacyInterfaceImportService {
  constructor(private readonly db: DBType) {}

  async preview(file: string, settings: unknown) {
    const source = inspectLegacyBackup(file);
    try {
      const plan = prepareLegacyImport(source, settings);
      validateImportReservations(plan, await this.readState(this.db));
      return {
        ...importSummary(source),
        blockers: [],
        warnings: source.warnings,
      };
    } catch (error) {
      if (!(error instanceof LegacyImportError)) throw error;
      return {
        ...importSummary(source),
        blockers: error.issues,
        warnings: source.warnings,
      };
    }
  }

  async create(file: string, settings: unknown, actorUserId: number) {
    const plan = prepareLegacyImport(inspectLegacyBackup(file), settings);
    const { source, parameters: p, settings: s } = plan;
    // The database coordinator excludes other writes for this whole callback.
    return this.db.transaction(async (tx) => {
      validateImportReservations(plan, await this.readState(tx));
      await tx
        .insert(wgInterface)
        .values({
          name: s.name,
          device: s.device,
          port: s.listenPort,
          privateKey: source.backup.server.privateKey,
          publicKey: source.backup.server.publicKey,
          ipv4Cidr: source.ipv4Cidr,
          ipv6Cidr: s.ipv6Cidr,
          mtu: s.mtu,
          ...p,
          s3: null,
          s4: null,
          i1: null,
          i2: null,
          i3: null,
          i4: null,
          i5: null,
          enabled: false,
          pendingDelete: false,
          firewallEnabled: false,
          awgParametersEnabled: s.mode === 'amneziawg',
          defaultConfigFormat:
            s.mode === 'amneziawg' ? 'amneziawg' : 'wireguard',
        })
        .execute();
      await tx
        .insert(hooks)
        .values({ id: s.name, ...s.hooks })
        .execute();
      await tx
        .insert(userConfig)
        .values({
          id: s.name,
          host: s.endpointHost,
          port: s.endpointPort,
          defaultMtu: s.mtu,
          defaultPersistentKeepalive: s.persistentKeepalive,
          defaultDns: s.dns,
          defaultAllowedIps: s.allowedIps,
          defaultJC: p.jC,
          defaultJMin: p.jMin,
          defaultJMax: p.jMax,
          defaultI1: null,
          defaultI2: null,
          defaultI3: null,
          defaultI4: null,
          defaultI5: null,
        })
        .execute();
      await tx
        .insert(interfaceRuntimeState)
        .values({
          interfaceId: s.name,
          status: 'disabled',
          observedUp: false,
          restartRequired: false,
        })
        .execute();
      for (const imported of plan.clients) {
        await tx
          .insert(client)
          .values({
            ...imported,
            userId: actorUserId,
            interfaceId: s.name,
            dns: s.dns,
            allowedIps: s.allowedIps,
            serverAllowedIps: [],
            firewallIps: null,
            mtu: s.mtu,
            persistentKeepalive: s.persistentKeepalive,
            jC: p.jC,
            jMin: p.jMin,
            jMax: p.jMax,
            i1: null,
            i2: null,
            i3: null,
            i4: null,
            i5: null,
            preferredConfigFormat: 'auto',
          })
          .execute();
      }
      const revision = await bumpDesiredRevision(tx, [s.name]);
      await tx
        .update(interfaceRuntimeState)
        .set({ status: 'disabled' })
        .where(eq(interfaceRuntimeState.interfaceId, s.name))
        .execute();
      return {
        success: true,
        interfaceId: s.name,
        importedClients: plan.clients.length,
        enabled: false as const,
        revision,
        warnings: source.warnings,
      };
    });
  }

  private async readState(db: Pick<DBType, 'query'>) {
    const interfaces = await db.query.wgInterface
      .findMany({
        columns: {
          name: true,
          port: true,
          ipv4Cidr: true,
          ipv6Cidr: true,
          publicKey: true,
        },
      })
      .execute();
    const clients = await db.query.client
      .findMany({
        columns: {
          publicKey: true,
          ipv4Address: true,
          ipv6Address: true,
          enabled: true,
        },
      })
      .execute();
    return { interfaces, clients };
  }
}
