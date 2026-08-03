import fs from 'node:fs/promises';
import path from 'node:path';

import type { Client } from '@libsql/client';

import { InterfaceNameSchema } from '#shared/utils/schemas';
import type { ConcreteConfigFormat } from '#shared/types/runtime';

const AWG_DIRECTIVE_PATTERN =
  /^(Jc|Jmin|Jmax|S1|S2|S3|S4|H1|H2|H3|H4|I1|I2|I3|I4|I5)\s*=\s*(.*?)\s*$/gim;

const PENDING_CONFIG_FORMAT = 'migration_pending';
const AMBIGUOUS_COMPATIBILITY_ERROR =
  'Compatibility mode could not be inferred from the pre-migration config or an explicit legacy backend setting. Set EXPERIMENTAL_AWG and OVERRIDE_AUTO_AWG explicitly, then restart.';

type LegacyEnvironment = {
  EXPERIMENTAL_AWG?: string;
  OVERRIDE_AUTO_AWG?: string;
};

export type CompatibilityModeResolution = {
  awgParametersEnabled: boolean;
  configFormat: ConcreteConfigFormat;
  source: 'generated_config' | 'legacy_environment' | 'fresh_install';
};

function configHasActiveAwgParameters(config: string) {
  if (!/^\s*\[Interface\]\s*$/im.test(config)) {
    return null;
  }

  for (const match of config.matchAll(AWG_DIRECTIVE_PATTERN)) {
    const value = match[2]?.trim();
    if (value && !/^0+(?:-0+)?$/.test(value)) {
      return true;
    }
  }

  return false;
}

export function resolveCompatibilityMode({
  generatedConfig,
  legacyEnvironment,
  freshInstall,
}: {
  generatedConfig?: string;
  legacyEnvironment: LegacyEnvironment;
  freshInstall: boolean;
}): CompatibilityModeResolution | null {
  if (generatedConfig !== undefined) {
    const awgParametersEnabled = configHasActiveAwgParameters(generatedConfig);
    if (awgParametersEnabled !== null) {
      return {
        awgParametersEnabled,
        configFormat: awgParametersEnabled ? 'amneziawg' : 'wireguard',
        source: 'generated_config',
      };
    }
  }

  const experimentalAwg = legacyEnvironment.EXPERIMENTAL_AWG?.toLowerCase();
  const override = legacyEnvironment.OVERRIDE_AUTO_AWG?.toLowerCase();

  if (experimentalAwg === 'false') {
    return {
      awgParametersEnabled: false,
      configFormat: 'wireguard',
      source: 'legacy_environment',
    };
  }

  if (experimentalAwg === 'true' && (override === 'awg' || override === 'wg')) {
    const awgParametersEnabled = override === 'awg';
    return {
      awgParametersEnabled,
      configFormat: awgParametersEnabled ? 'amneziawg' : 'wireguard',
      source: 'legacy_environment',
    };
  }

  if (freshInstall) {
    return {
      awgParametersEnabled: false,
      configFormat: 'wireguard',
      source: 'fresh_install',
    };
  }

  return null;
}

async function readGeneratedConfig(
  configDirectory: string,
  interfaceId: string
) {
  const validatedInterfaceId = InterfaceNameSchema.parse(interfaceId);
  try {
    return await fs.readFile(
      path.join(configDirectory, `${validatedInterfaceId}.conf`),
      'utf8'
    );
  } catch (error) {
    if (
      error instanceof Error &&
      'code' in error &&
      (error as NodeJS.ErrnoException).code === 'ENOENT'
    ) {
      return undefined;
    }
    throw error;
  }
}

async function isFreshInstall(client: Client) {
  const result = await client.execute({
    sql: `
      SELECT
        (SELECT setup_step FROM general_table WHERE id = 1) AS setup_step,
        (SELECT COUNT(*) FROM users_table) AS user_count,
        (SELECT COUNT(*) FROM clients_table) AS client_count
    `,
    args: [],
  });
  const row = result.rows[0];
  return (
    row !== undefined &&
    Number(row.setup_step) !== 0 &&
    Number(row.user_count) === 0 &&
    Number(row.client_count) === 0
  );
}

export async function finalizePhase1DataMigration(
  client: Client,
  {
    configDirectory,
    legacyEnvironment,
  }: {
    configDirectory: string;
    legacyEnvironment: LegacyEnvironment;
  }
) {
  const pendingInterfaces = await client.execute({
    sql: `
      SELECT name
      FROM interfaces_table
      WHERE default_config_format = ?
      ORDER BY name
    `,
    args: [PENDING_CONFIG_FORMAT],
  });

  if (pendingInterfaces.rows.length === 0) {
    return { migrated: [], unresolved: [] };
  }

  const freshInstall = await isFreshInstall(client);
  const resolutions = await Promise.all(
    pendingInterfaces.rows.map(async (row) => {
      const interfaceId = String(row.name);
      const generatedConfig = await readGeneratedConfig(
        configDirectory,
        interfaceId
      );
      return {
        interfaceId,
        resolution: resolveCompatibilityMode({
          generatedConfig,
          legacyEnvironment,
          freshInstall,
        }),
      };
    })
  );

  const transaction = await client.transaction('write');
  try {
    for (const { interfaceId, resolution } of resolutions) {
      if (!resolution) {
        await transaction.execute({
          sql: `
            UPDATE interface_runtime_state_table
            SET status = 'degraded', last_error = ?, updated_at = CURRENT_TIMESTAMP
            WHERE interface_id = ?
          `,
          args: [AMBIGUOUS_COMPATIBILITY_ERROR, interfaceId],
        });
        continue;
      }

      await transaction.execute({
        sql: `
          UPDATE interfaces_table
          SET awg_parameters_enabled = ?, default_config_format = ?, updated_at = CURRENT_TIMESTAMP
          WHERE name = ? AND default_config_format = ?
        `,
        args: [
          resolution.awgParametersEnabled ? 1 : 0,
          resolution.configFormat,
          interfaceId,
          PENDING_CONFIG_FORMAT,
        ],
      });
      await transaction.execute({
        sql: `
          UPDATE one_time_links_table
          SET config_format = ?, updated_at = CURRENT_TIMESTAMP
          WHERE config_format = ?
            AND id IN (
              SELECT id FROM clients_table WHERE interface_id = ?
            )
        `,
        args: [resolution.configFormat, PENDING_CONFIG_FORMAT, interfaceId],
      });
      await transaction.execute({
        sql: `
          UPDATE interface_runtime_state_table
          SET status = 'pending', last_error = NULL, updated_at = CURRENT_TIMESTAMP
          WHERE interface_id = ?
        `,
        args: [interfaceId],
      });
    }

    const unresolved = resolutions
      .filter(({ resolution }) => resolution === null)
      .map(({ interfaceId }) => interfaceId);
    await transaction.execute({
      sql: `
        UPDATE runtime_reconciliation_state_table
        SET status = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
      `,
      args:
        unresolved.length > 0
          ? [
              'degraded',
              `Compatibility migration is unresolved for: ${unresolved.join(', ')}`,
            ]
          : ['pending', null],
    });

    await transaction.commit();
  } catch (error) {
    await transaction.rollback();
    throw error;
  }

  return {
    migrated: resolutions
      .filter(({ resolution }) => resolution !== null)
      .map(({ interfaceId, resolution }) => ({ interfaceId, ...resolution! })),
    unresolved: resolutions
      .filter(({ resolution }) => resolution === null)
      .map(({ interfaceId }) => interfaceId),
  };
}

export const phase1MigrationConstants = {
  pendingConfigFormat: PENDING_CONFIG_FORMAT,
  ambiguousCompatibilityError: AMBIGUOUS_COMPATIBILITY_ERROR,
} as const;
