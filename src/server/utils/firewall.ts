import { createDebug } from 'obug';
import { isIPv6 } from 'is-ip';

import { execFile } from '#server/utils/cmd';
import type { ClientType } from '#db/repositories/client/types';
import type { InterfaceType } from '#db/repositories/interface/types';
import type { UserConfigType } from '#db/repositories/userConfig/types';
import { InterfaceNameSchema } from '#shared/utils/schemas';

const FW_DEBUG = createDebug('Firewall');
const CHAIN_NAME = 'WG_CLIENTS';
const OWNER_COMMENT = 'wg-easy client firewall';

// Mutex to prevent concurrent rule rebuilds
let rebuildInProgress = false;
let rebuildQueued = false;

// Cache iptables availability check result
let iptablesAvailable: boolean | null = null;

type ParsedEntry = {
  ip: string;
  port?: number;
  proto?: 'tcp' | 'udp' | 'both';
};

type FirewallClient = Pick<
  ClientType,
  | 'id'
  | 'name'
  | 'ipv4Address'
  | 'ipv6Address'
  | 'allowedIps'
  | 'firewallIps'
  | 'enabled'
>;

type FirewallInterfaceState = {
  wgInterface: InterfaceType;
  observedUp: boolean;
  clients: FirewallClient[];
  userConfig: UserConfigType;
};

/**
 * Sanitize a client identifier for use in an iptables comment.
 * Strips all characters except ASCII alphanumeric, space, underscore, hyphen, and dot.
 * Combines with client ID for a safe, identifiable comment.
 * Truncates to 256 bytes (iptables comment module limit).
 */
function sanitizeComment(clientId: number, clientName: string): string {
  const safe = clientName.replace(/[^a-zA-Z0-9 _.-]/g, '');
  const comment = `client ${clientId}: ${safe}`;
  return comment.slice(0, 256);
}

/**
 * Parse a firewall entry string into its components.
 * Supports formats:
 * - IP: "10.0.0.1" or "2001:db8::1"
 * - CIDR: "10.0.0.0/24" or "2001:db8::/32"
 * - IP:port: "10.0.0.1:443" or "[2001:db8::1]:443"
 * - IP:port/proto: "10.0.0.1:443/tcp" or "10.0.0.1:53/udp"
 * - CIDR:port: "10.0.0.0/24:443"
 * - CIDR:port/proto: "10.0.0.0/24:443/tcp" or "10.0.0.0/24:53/udp"
 *
 * Note: Protocol (/tcp or /udp) requires a port. "IP/tcp" or "CIDR/tcp" without
 * a port is invalid and will throw an error.
 *
 * @throws {Error} If protocol is specified without a port
 */
function parseFirewallEntry(entry: string): ParsedEntry {
  // Extract protocol suffix first: /tcp or /udp
  let proto: 'tcp' | 'udp' | 'both' | undefined;
  let remaining = entry;

  if (entry.endsWith('/tcp')) {
    proto = 'tcp';
    remaining = entry.slice(0, -4);
  } else if (entry.endsWith('/udp')) {
    proto = 'udp';
    remaining = entry.slice(0, -4);
  }

  // Handle IPv6 with port: [2001:db8::1]:443
  if (remaining.startsWith('[')) {
    const match = remaining.match(/^\[(.+)\]:(\d+)$/);
    if (match && match[1] && match[2]) {
      return {
        ip: match[1],
        port: parseInt(match[2], 10),
        proto: proto ?? 'both',
      };
    }
    // Just bracketed IPv6 without port
    const ipMatch = remaining.match(/^\[(.+)\]$/);
    if (ipMatch && ipMatch[1]) {
      if (proto) {
        throw new Error(
          `Invalid firewall entry "${entry}": Protocol (/${proto}) requires a port. Use format like "[${ipMatch[1]}]:443/${proto}"`
        );
      }
      return { ip: ipMatch[1] };
    }
    if (proto) {
      throw new Error(
        `Invalid firewall entry "${entry}": Protocol (/${proto}) requires a port`
      );
    }
    return { ip: remaining };
  }

  // Handle IPv4 with port or CIDR with port
  // Count colons to distinguish IPv6 from IPv4:port
  const colonCount = (remaining.match(/:/g) || []).length;

  if (colonCount === 1) {
    // Could be IPv4:port or CIDR:port
    const lastColon = remaining.lastIndexOf(':');
    const possiblePort = remaining.slice(lastColon + 1);
    if (/^\d+$/.test(possiblePort)) {
      return {
        ip: remaining.slice(0, lastColon),
        port: parseInt(possiblePort, 10),
        proto: proto ?? 'both',
      };
    }
  }

  // Plain IP or CIDR (IPv4 or IPv6)
  if (proto) {
    throw new Error(
      `Invalid firewall entry "${entry}": Protocol (/${proto}) requires a port. Use format like "${remaining}:443/${proto}"`
    );
  }
  return { ip: remaining };
}

/**
 * Generate iptables rule arguments for a single firewall entry
 */
function generateRuleArgs(
  clientIp: string,
  entry: ParsedEntry,
  comment?: string,
  action: 'A' | 'D' = 'A'
): string[][] {
  const rules: string[][] = [];
  const commentArgs = comment ? ['-m', 'comment', '--comment', comment] : [];
  const baseArgs = [`-${action}`, CHAIN_NAME, '-s', clientIp, '-d', entry.ip];

  if (entry.port) {
    // Port-specific rules
    if (entry.proto === 'tcp' || entry.proto === 'both') {
      rules.push([
        ...baseArgs,
        '-p',
        'tcp',
        '--dport',
        String(entry.port),
        ...commentArgs,
        '-j',
        'ACCEPT',
      ]);
    }
    if (entry.proto === 'udp' || entry.proto === 'both') {
      rules.push([
        ...baseArgs,
        '-p',
        'udp',
        '--dport',
        String(entry.port),
        ...commentArgs,
        '-j',
        'ACCEPT',
      ]);
    }
  } else {
    // No port - allow all traffic to destination
    rules.push([...baseArgs, ...commentArgs, '-j', 'ACCEPT']);
  }

  return rules;
}

function restoreArgument(value: string) {
  return /^[A-Za-z0-9_./:=+-]+$/.test(value)
    ? value
    : `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`;
}

function restoreRule(args: readonly string[]) {
  return args.map(restoreArgument).join(' ');
}

function buildRestoreDocument({
  family,
  states,
  existingSave,
}: {
  family: 4 | 6;
  states: readonly FirewallInterfaceState[];
  existingSave: string;
}) {
  const active = states.filter(
    ({ wgInterface, observedUp }) =>
      observedUp && wgInterface.enabled && wgInterface.firewallEnabled
  );
  const managedInterfaces = new Set(
    states.map(({ wgInterface }) => InterfaceNameSchema.parse(wgInterface.name))
  );
  const rules: string[][] = [];
  for (const { clients, userConfig } of active) {
    for (const client of clients) {
      if (!client.enabled) continue;
      const effectiveIps =
        client.firewallIps && client.firewallIps.length > 0
          ? client.firewallIps
          : (client.allowedIps ?? userConfig.defaultAllowedIps);
      const comment = sanitizeComment(client.id, client.name);
      for (const entry of effectiveIps.map(parseFirewallEntry)) {
        const baseIp = entry.ip.split('/')[0] ?? entry.ip;
        if ((family === 6) !== isIPv6(baseIp)) continue;
        rules.push(
          ...generateRuleArgs(
            family === 6 ? client.ipv6Address : client.ipv4Address,
            entry,
            comment
          )
        );
      }
    }
  }

  const savedLines = existingSave
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  const jumpLines = savedLines.filter(
    (line) =>
      line.startsWith('-A FORWARD ') && line.endsWith(`-j ${CHAIN_NAME}`)
  );
  const ownedJumpLines = jumpLines.filter((line) => {
    if (line.includes(`--comment "${OWNER_COMMENT}"`)) return true;
    const interfaceMatch = line.match(/^-A FORWARD -i (\S+) /);
    return interfaceMatch?.[1]
      ? managedInterfaces.has(interfaceMatch[1])
      : false;
  });
  if (ownedJumpLines.length !== jumpLines.length) {
    throw new Error(
      `A non-owned FORWARD rule jumps to reserved chain ${CHAIN_NAME}`
    );
  }
  const chainExists = savedLines.some((line) =>
    line.startsWith(`:${CHAIN_NAME} `)
  );
  const ownerMarkerExists = savedLines.some(
    (line) =>
      line.startsWith(`-A ${CHAIN_NAME} `) &&
      line.includes(`--comment "${OWNER_COMMENT} owner"`)
  );
  if (chainExists && !ownerMarkerExists && ownedJumpLines.length === 0) {
    throw new Error(`Reserved chain ${CHAIN_NAME} is not owned by wg-easy`);
  }
  const existingJumps = ownedJumpLines.map((line) =>
    line.replace(/^-A /, '-D ')
  );
  const desiredJumps = active
    .map(({ wgInterface }) => InterfaceNameSchema.parse(wgInterface.name))
    .sort((left, right) => left.localeCompare(right))
    .map(
      (interfaceName) =>
        `-I FORWARD 1 -i ${interfaceName} -m comment --comment "${OWNER_COMMENT}" -j ${CHAIN_NAME}`
    );

  return [
    '*filter',
    `:${CHAIN_NAME} - [0:0]`,
    `-F ${CHAIN_NAME}`,
    ...existingJumps,
    `-A ${CHAIN_NAME} -m comment --comment "${OWNER_COMMENT} owner"`,
    ...rules.map(restoreRule),
    ...(active.length > 0
      ? [
          `-A ${CHAIN_NAME} -m comment --comment "${OWNER_COMMENT} default deny" -j DROP`,
        ]
      : []),
    ...desiredJumps,
    'COMMIT',
    '',
  ].join('\n');
}

async function applyRestoreDocument(
  executable: 'iptables-restore' | 'ip6tables-restore',
  document: string
) {
  await execFile(executable, ['--test', '--noflush'], {
    input: document,
    log: `${executable} --test --noflush <generated-firewall>`,
  });
  await execFile(executable, ['--noflush'], {
    input: document,
    log: `${executable} --noflush <generated-firewall>`,
  });
}

export const firewall = {
  /**
   * Initialize the custom chain if it doesn't exist
   */
  async initChain(interfaceName: string, enableIpv6: boolean): Promise<void> {
    const validatedInterfaceName = InterfaceNameSchema.parse(interfaceName);
    FW_DEBUG(
      `Initializing firewall chain ${CHAIN_NAME} for interface ${interfaceName}`
    );

    // Create chain if not exists (iptables returns error if exists, so we ignore)
    await execFile('iptables', ['-N', CHAIN_NAME]).catch(() => {});
    if (enableIpv6) {
      await execFile('ip6tables', ['-N', CHAIN_NAME]).catch(() => {});
    }

    // Ensure chain is referenced from FORWARD (if not already)
    // Insert at position 1 to process before generic ACCEPT rules
    await execFile('iptables', [
      '-C',
      'FORWARD',
      '-i',
      validatedInterfaceName,
      '-j',
      CHAIN_NAME,
    ]).catch(() =>
      execFile('iptables', [
        '-I',
        'FORWARD',
        '1',
        '-i',
        validatedInterfaceName,
        '-j',
        CHAIN_NAME,
      ])
    );
    if (enableIpv6) {
      await execFile('ip6tables', [
        '-C',
        'FORWARD',
        '-i',
        validatedInterfaceName,
        '-j',
        CHAIN_NAME,
      ]).catch(() =>
        execFile('ip6tables', [
          '-I',
          'FORWARD',
          '1',
          '-i',
          validatedInterfaceName,
          '-j',
          CHAIN_NAME,
        ])
      );
    }
  },

  /**
   * Flush all rules in the custom chain
   */
  async flushChain(enableIpv6: boolean): Promise<void> {
    FW_DEBUG(`Flushing firewall chain ${CHAIN_NAME}`);
    await execFile('iptables', ['-F', CHAIN_NAME]).catch(() => {});
    if (enableIpv6) {
      await execFile('ip6tables', ['-F', CHAIN_NAME]).catch(() => {});
    }
  },

  /**
   * Apply firewall rules for a single client
   */
  async applyClientRules(
    client: FirewallClient,
    defaultAllowedIps: string[],
    enableIpv6: boolean
  ): Promise<void> {
    // Determine which IPs to use for firewall rules
    // Priority: firewallIps > allowedIps > defaultAllowedIps
    const effectiveIps =
      client.firewallIps && client.firewallIps.length > 0
        ? client.firewallIps
        : (client.allowedIps ?? defaultAllowedIps);

    FW_DEBUG(
      `Applying firewall rules for client ${client.name} (${client.id}): ${effectiveIps.join(', ')}`
    );

    const comment = sanitizeComment(client.id, client.name);

    for (const ipEntry of effectiveIps) {
      const parsed = parseFirewallEntry(ipEntry);
      const baseIp = parsed.ip.split('/')[0] ?? parsed.ip; // Handle CIDR by checking base IP
      const destIsIpv6 = isIPv6(baseIp);

      if (destIsIpv6) {
        if (enableIpv6) {
          const rules = generateRuleArgs(client.ipv6Address, parsed, comment);
          for (const rule of rules) {
            await execFile('ip6tables', rule);
          }
        }
      } else {
        const rules = generateRuleArgs(client.ipv4Address, parsed, comment);
        for (const rule of rules) {
          await execFile('iptables', rule);
        }
      }
    }
  },

  /**
   * Full rebuild of firewall rules from database state
   */
  async rebuildRules(
    wgInterface: InterfaceType,
    clients: FirewallClient[],
    userConfig: UserConfigType,
    enableIpv6: boolean
  ): Promise<void> {
    if (!wgInterface.firewallEnabled) {
      FW_DEBUG('Firewall filtering disabled, removing any existing rules');
      await this.removeFiltering(wgInterface.name, enableIpv6);
      return;
    }

    // Handle concurrent rebuilds with queue
    if (rebuildInProgress) {
      FW_DEBUG('Rebuild already in progress, queuing');
      rebuildQueued = true;
      return;
    }

    rebuildInProgress = true;

    try {
      FW_DEBUG('Rebuilding firewall rules...');

      // Initialize chain structure
      await this.initChain(wgInterface.name, enableIpv6);

      // Flush existing rules
      await this.flushChain(enableIpv6);

      // Apply rules for each enabled client
      for (const client of clients) {
        if (!client.enabled) continue;
        await this.applyClientRules(
          client,
          userConfig.defaultAllowedIps,
          enableIpv6
        );
      }

      // Add final DROP for any traffic not explicitly allowed
      await execFile('iptables', ['-A', CHAIN_NAME, '-j', 'DROP']);
      if (enableIpv6) {
        await execFile('ip6tables', ['-A', CHAIN_NAME, '-j', 'DROP']);
      }

      FW_DEBUG('Firewall rules rebuilt successfully');
    } finally {
      rebuildInProgress = false;

      // If another rebuild was queued, run it now
      if (rebuildQueued) {
        rebuildQueued = false;
        FW_DEBUG('Processing queued rebuild');
        await this.rebuildRules(wgInterface, clients, userConfig, enableIpv6);
      }
    }
  },

  /**
   * Rebuild the current shared client-filter chain from fresh state for every
   * managed interface through one complete restore transaction.
   */
  async rebuildAllRules(
    states: readonly FirewallInterfaceState[],
    enableIpv6: boolean
  ): Promise<void> {
    const hasActiveFiltering = states.some(
      ({ wgInterface, observedUp }) =>
        observedUp && wgInterface.enabled && wgInterface.firewallEnabled
    );
    if (!(await this.isAvailable(enableIpv6))) {
      if (!hasActiveFiltering) return;
      throw new Error('Per-client firewall tools are unavailable');
    }

    const ipv4Save = await execFile('iptables-save', ['-t', 'filter']);
    await applyRestoreDocument(
      'iptables-restore',
      buildRestoreDocument({ family: 4, states, existingSave: ipv4Save })
    );
    if (enableIpv6) {
      const ipv6Save = await execFile('ip6tables-save', ['-t', 'filter']);
      await applyRestoreDocument(
        'ip6tables-restore',
        buildRestoreDocument({ family: 6, states, existingSave: ipv6Save })
      );
    }
  },

  async removeInterfaceJump(
    interfaceName: string,
    enableIpv6: boolean
  ): Promise<void> {
    const validatedInterfaceName = InterfaceNameSchema.parse(interfaceName);
    await execFile('iptables', [
      '-D',
      'FORWARD',
      '-i',
      validatedInterfaceName,
      '-j',
      CHAIN_NAME,
    ]).catch(() => {});
    if (enableIpv6) {
      await execFile('ip6tables', [
        '-D',
        'FORWARD',
        '-i',
        validatedInterfaceName,
        '-j',
        CHAIN_NAME,
      ]).catch(() => {});
    }
  },

  /**
   * Remove all firewall filtering (when feature is disabled)
   */
  async removeFiltering(
    interfaceName: string,
    enableIpv6: boolean
  ): Promise<void> {
    const validatedInterfaceName = InterfaceNameSchema.parse(interfaceName);
    FW_DEBUG(`Removing firewall filtering for interface ${interfaceName}`);

    // Remove jump rules from FORWARD chain
    await this.removeInterfaceJump(validatedInterfaceName, enableIpv6);

    // Flush and delete the chain
    await execFile('iptables', ['-F', CHAIN_NAME]).catch(() => {});
    await execFile('iptables', ['-X', CHAIN_NAME]).catch(() => {});
    if (enableIpv6) {
      await execFile('ip6tables', ['-F', CHAIN_NAME]).catch(() => {});
      await execFile('ip6tables', ['-X', CHAIN_NAME]).catch(() => {});
    }
  },

  /**
   * Check if iptables (and optionally ip6tables) are available on the system.
   * @param enableIpv6 - If true, also check for ip6tables. Defaults to true.
   */
  async isAvailable(enableIpv6: boolean = true): Promise<boolean> {
    // Return cached result if we've already checked
    if (iptablesAvailable !== null) {
      return iptablesAvailable;
    }

    try {
      // Check for iptables (always required)
      await execFile('iptables', ['--version']);
      await execFile('iptables-restore', ['--version']);
      FW_DEBUG('iptables is available');

      // Check for ip6tables (only if IPv6 is enabled)
      if (enableIpv6) {
        await execFile('ip6tables', ['--version']);
        await execFile('ip6tables-restore', ['--version']);
        FW_DEBUG('ip6tables is available');
      } else {
        FW_DEBUG('IPv6 disabled, skipping ip6tables check');
      }

      iptablesAvailable = true;
      return true;
    } catch (error) {
      iptablesAvailable = false;
      FW_DEBUG('iptables/ip6tables is not available:', error);
      return false;
    }
  },

  /**
   * Clear the availability cache to force a re-check
   */
  clearAvailabilityCache(): void {
    iptablesAvailable = null;
  },
};

export const firewallTestExports = {
  parseFirewallEntry,
  generateRuleArgs,
  sanitizeComment,
  buildRestoreDocument,
};
