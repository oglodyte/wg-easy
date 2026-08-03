import { drizzle } from 'drizzle-orm/libsql';
import { migrate as drizzleMigrate } from 'drizzle-orm/libsql/migrator';
import { createClient } from '@libsql/client';
import { createDebug } from 'obug';
import { eq } from 'drizzle-orm';

import { GeneralService } from '#db/repositories/general/service';
import { UserService } from '#db/repositories/user/service';
import { UserConfigService } from '#db/repositories/userConfig/service';
import { InterfaceService } from '#db/repositories/interface/service';
import { HooksService } from '#db/repositories/hooks/service';
import { OneTimeLinkService } from '#db/repositories/oneTimeLink/service';
import { ClientService } from '#db/repositories/client/service';
import { finalizePhase1DataMigration } from '#db/phase1Migration';
import * as schema from '#db/schema';
import { WG_ENV, WG_INITIAL_ENV } from '#server/utils/config';

const DB_DEBUG = createDebug('Database');

const client = createClient({ url: 'file:/etc/wireguard/wg-easy.db' });
const db = drizzle({ client, schema });

export async function connect() {
  await migrate();
  const dbService = new DBService(db);

  if (WG_INITIAL_ENV.ENABLED) {
    await initialSetup(dbService);
  }

  if (WG_ENV.DISABLE_IPV6) {
    DB_DEBUG('Warning: Disabling IPv6...');
    await disableIpv6(db);
  }

  return dbService;
}

class DBService {
  clients: ClientService;
  general: GeneralService;
  users: UserService;
  userConfigs: UserConfigService;
  interfaces: InterfaceService;
  hooks: HooksService;
  oneTimeLinks: OneTimeLinkService;

  constructor(db: DBType) {
    this.clients = new ClientService(db);
    this.general = new GeneralService(db);
    this.users = new UserService(db);
    this.userConfigs = new UserConfigService(db);
    this.interfaces = new InterfaceService(db);
    this.hooks = new HooksService(db);
    this.oneTimeLinks = new OneTimeLinkService(db);
  }
}

export type DBType = typeof db;
export type DBServiceType = DBService;

async function migrate() {
  try {
    DB_DEBUG('Migrating database...');
    await drizzleMigrate(db, {
      migrationsFolder: './server/database/migrations',
    });
    const phase1Migration = await finalizePhase1DataMigration(client, {
      configDirectory: '/etc/wireguard',
      legacyEnvironment: {
        EXPERIMENTAL_AWG: process.env.EXPERIMENTAL_AWG,
        OVERRIDE_AUTO_AWG: process.env.OVERRIDE_AUTO_AWG,
      },
    });
    if (phase1Migration.unresolved.length > 0) {
      DB_DEBUG(
        `Phase 1 compatibility migration is unresolved for: ${phase1Migration.unresolved.join(', ')}`
      );
    }
    DB_DEBUG('Migration complete');
  } catch (e) {
    if (e instanceof Error) {
      DB_DEBUG('Failed to migrate database:', e.message);
    }
    throw e;
  }
}

async function initialSetup(db: DBServiceType) {
  const setup = await db.general.getSetupStep();

  if (setup.done) {
    DB_DEBUG('Setup already done. Skiping initial setup.');
    return;
  }

  if (WG_INITIAL_ENV.IPV4_CIDR && WG_INITIAL_ENV.IPV6_CIDR) {
    DB_DEBUG('Setting initial CIDR...');
    const defaultInterface = await db.interfaces.getDefault();
    await db.interfaces.updateCidr(defaultInterface.name, {
      ipv4Cidr: WG_INITIAL_ENV.IPV4_CIDR,
      ipv6Cidr: WG_INITIAL_ENV.IPV6_CIDR,
    });
  }

  if (WG_INITIAL_ENV.DNS) {
    DB_DEBUG('Setting initial DNS...');
    const defaultInterface = await db.interfaces.getDefault();
    await db.userConfigs.update(defaultInterface.name, {
      defaultDns: WG_INITIAL_ENV.DNS,
    });
  }

  if (WG_INITIAL_ENV.ALLOWED_IPS) {
    DB_DEBUG('Setting initial Allowed IPs...');
    const defaultInterface = await db.interfaces.getDefault();
    await db.userConfigs.update(defaultInterface.name, {
      defaultAllowedIps: WG_INITIAL_ENV.ALLOWED_IPS,
    });
  }

  if (
    WG_INITIAL_ENV.USERNAME &&
    WG_INITIAL_ENV.PASSWORD &&
    WG_INITIAL_ENV.HOST &&
    WG_INITIAL_ENV.PORT
  ) {
    DB_DEBUG('Creating initial user...');
    await db.users.create(WG_INITIAL_ENV.USERNAME, WG_INITIAL_ENV.PASSWORD);

    DB_DEBUG('Setting initial host and port...');
    const defaultInterface = await db.interfaces.getDefault();
    await db.userConfigs.updateHostPort(
      defaultInterface.name,
      WG_INITIAL_ENV.HOST,
      WG_INITIAL_ENV.PORT
    );

    await db.general.setSetupStep(0);
  }
}

async function disableIpv6(db: DBType) {
  const config = await db.query.general
    .findFirst({ columns: { defaultInterfaceId: true } })
    .execute();
  if (!config) throw new Error('General Config not found');
  const interfaceId = config.defaultInterfaceId;
  // This should match the initial value migration
  const postUpMatch =
    ' ip6tables -t nat -A POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport {{port}} -j ACCEPT; ip6tables -A FORWARD -i {{name}} -j ACCEPT; ip6tables -A FORWARD -o {{name}} -j ACCEPT;';
  const postDownMatch =
    ' ip6tables -t nat -D POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE; ip6tables -D INPUT -p udp -m udp --dport {{port}} -j ACCEPT; ip6tables -D FORWARD -i {{name}} -j ACCEPT; ip6tables -D FORWARD -o {{name}} -j ACCEPT;';

  await db.transaction(async (tx) => {
    const hooks = await tx.query.hooks.findFirst({
      where: eq(schema.hooks.id, interfaceId),
    });

    if (!hooks) {
      throw new Error('Hooks not found');
    }

    if (hooks.postUp.includes(postUpMatch)) {
      DB_DEBUG('Disabling IPv6 in Post Up hooks...');
      await tx
        .update(schema.hooks)
        .set({
          postUp: hooks.postUp.replace(postUpMatch, ''),
          postDown: hooks.postDown.replace(postDownMatch, ''),
        })
        .where(eq(schema.hooks.id, interfaceId))
        .execute();
    } else {
      DB_DEBUG('IPv6 Post Up hooks already disabled, skipping...');
    }
    if (hooks.postDown.includes(postDownMatch)) {
      DB_DEBUG('Disabling IPv6 in Post Down hooks...');
      await tx
        .update(schema.hooks)
        .set({
          postUp: hooks.postUp.replace(postUpMatch, ''),
          postDown: hooks.postDown.replace(postDownMatch, ''),
        })
        .where(eq(schema.hooks.id, interfaceId))
        .execute();
    } else {
      DB_DEBUG('IPv6 Post Down hooks already disabled, skipping...');
    }
  });
}
