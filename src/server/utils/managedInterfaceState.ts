import { timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';

import { normalizeCidr } from 'cidr-tools';

import { deriveClientPublicKey } from '#server/utils/clientCredentials';
import { verifyPeerSyncPresharedKeys } from '#server/utils/peerSyncConfig';
import { InterfaceNameSchema } from '#shared/utils/schemas';

const awgDefaults: Readonly<Record<string, string>> = {
  jc: '0',
  jmin: '0',
  jmax: '0',
  s1: '0',
  s2: '0',
  s3: '0',
  s4: '0',
  h1: '1',
  h2: '2',
  h3: '3',
  h4: '4',
  i1: '',
  i2: '',
  i3: '',
  i4: '',
  i5: '',
};
const quickFields = new Set([
  'address',
  'mtu',
  'table',
  'preup',
  'postup',
  'predown',
  'postdown',
]);
const hooks = new Set(['preup', 'postup', 'predown', 'postdown']);
const interfaceFields = new Set([
  'privatekey',
  'listenport',
  'fwmark',
  ...Object.keys(awgDefaults),
]);
const peerFields = new Set([
  'publickey',
  'presharedkey',
  'allowedips',
  'endpoint',
  'persistentkeepalive',
  'advancedsecurity',
]);
export class ManagedInterfaceStateError extends Error {
  constructor(
    readonly code: string,
    readonly interfaceId?: string,
    readonly verificationScope?: string
  ) {
    super(`Managed interface verification: ${code}`);
    this.name = 'ManagedInterfaceStateError';
  }
}

/** Private in-memory data only. Never serialize, log or put it in the journal. */
export type ManagedInterfaceConfig = {
  fields: Map<string, string>;
  peers: Map<string, string>[];
};

function fail(code: string): never {
  throw new ManagedInterfaceStateError(code);
}
function parse(
  config: string,
  quick: boolean,
  allowUninitialized = false
): ManagedInterfaceConfig {
  const fields = new Map<string, string>(),
    peers: Map<string, string>[] = [];
  let section: Map<string, string> | undefined;
  for (const raw of config.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (/^\[Interface\]$/i.test(line)) {
      if (section || fields.size || peers.length) fail('invalid_configuration');
      section = fields;
      continue;
    }
    if (/^\[Peer\]$/i.test(line)) {
      if (!section) fail('invalid_configuration');
      section = new Map();
      peers.push(section);
      continue;
    }
    const match = line.match(/^([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)$/);
    if (!section || !match) fail('invalid_configuration');
    const name = match[1]!.toLowerCase();
    if (
      section.has(name) ||
      !(section === fields
        ? interfaceFields.has(name) || (quick && quickFields.has(name))
        : peerFields.has(name))
    )
      fail('invalid_configuration');
    const value = hooks.has(name)
      ? match[2]!.trim()
      : match[2]!.split('#')[0]!.trim();
    section.set(name, value);
  }
  if (!fields.get('privatekey')) {
    if (!allowUninitialized) fail('invalid_configuration');
  } else deriveClientPublicKey(fields.get('privatekey')!);
  const identities = new Set<string>();
  for (const peer of peers) {
    const identity = peer.get('publickey');
    if (!identity || identities.has(identity)) fail('invalid_configuration');
    identities.add(identity);
    canonicalPrefixes(peer.get('allowedips') ?? '');
  }
  return { fields, peers };
}

function canonicalPrefixes(value: string) {
  return [
    ...new Set(
      value
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean)
        .map((p) => normalizeCidr(p))
    ),
  ].sort();
}
function integer(
  value: string | undefined,
  maximum: number,
  fallback?: number
) {
  if (value === undefined && fallback !== undefined) return fallback;
  if (!value || !/^\d+$/.test(value)) fail('invalid_configuration');
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum)
    fail('invalid_configuration');
  return parsed;
}
function mark(value: string | undefined) {
  if (value === undefined || value.toLowerCase() === 'off') return 0;
  if (!/^(0x[0-9a-f]+|\d+)$/i.test(value)) fail('invalid_configuration');
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 0 || result > 0xffffffff)
    fail('invalid_configuration');
  return result;
}
function awgValue(name: string, fields: Map<string, string>) {
  const value = fields.get(name) ?? awgDefaults[name]!;
  if (name.startsWith('i')) return value;
  if (name.startsWith('h')) {
    const parts = value.split('-');
    if (parts.length > 2) fail('invalid_configuration');
    const values = parts.map((p) => integer(p, 0xffffffff));
    if (values.length === 2 && values[0]! > values[1]!)
      fail('invalid_configuration');
    return values.length === 2 && values[0] === values[1]
      ? String(values[0])
      : values.join('-');
  }
  return String(integer(value, 65535));
}
function address(value: string) {
  const [host, length, extra] = value.trim().split('/');
  const family = host ? isIP(host) : 0;
  if (!host || !family || extra !== undefined || length === undefined)
    fail('invalid_configuration');
  const bits = family === 4 ? 32 : 128;
  return `${normalizeCidr(`${host}/${bits}`).split('/')[0]}/${integer(length, bits)}`;
}
function same(a: unknown, b: unknown) {
  return JSON.stringify(a) === JSON.stringify(b);
}
function boolean(value: string | undefined) {
  if (value === undefined || value === 'off' || value === '0') return false;
  if (value === 'on' || value === '1') return true;
  fail('peer_advanced_security_unverified');
}
function validateEndpoint(value: string, seed: boolean) {
  const match = value.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/);
  const port = Number(match?.[3]);
  if (!match || !Number.isInteger(port) || port < 1 || port > 65535)
    fail('peer_configuration_unverified');
  const host = match[1] ?? match[2]!;
  const [ip, zone, extra] = host.split('%');
  if (
    extra !== undefined ||
    (zone !== undefined &&
      !/^\d+$/.test(zone) &&
      !InterfaceNameSchema.safeParse(zone).success)
  )
    fail('peer_configuration_unverified');
  if (
    !isIP(ip!) &&
    !(
      seed &&
      !zone &&
      /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(host)
    )
  )
    fail('peer_configuration_unverified');
}

/** Validate private saved/generated bytes before any guarded peer write. */
export function parseManagedInterfaceConfig(
  interfaceId: string,
  config: string
) {
  try {
    InterfaceNameSchema.parse(interfaceId);
    const parsed = parse(config, true);
    if (
      parsed.fields.get('table')?.toLowerCase() !== 'off' ||
      !parsed.fields.get('address')
    )
      fail('invalid_configuration');
    parsed.fields.get('address')!.split(',').map(address);
    if (
      !integer(parsed.fields.get('listenport'), 65535) ||
      !integer(parsed.fields.get('mtu'), 65535)
    )
      fail('invalid_configuration');
    for (const name of Object.keys(awgDefaults)) awgValue(name, parsed.fields);
    for (const peer of parsed.peers) {
      integer(peer.get('persistentkeepalive'), 65535, 0);
      boolean(peer.get('advancedsecurity'));
      if (peer.has('endpoint')) validateEndpoint(peer.get('endpoint')!, true);
    }
    verifyPeerSyncPresharedKeys(
      interfaceId,
      config,
      parsed.peers
        .map(
          (p) => `${p.get('publickey')}\t${p.get('presharedkey') ?? '(none)'}`
        )
        .join('\n')
    );
    return parsed;
  } catch {
    throw new ManagedInterfaceStateError(
      'invalid_configuration',
      InterfaceNameSchema.safeParse(interfaceId).success
        ? interfaceId
        : undefined
    );
  }
}

/** Server identity, addresses and hooks require the existing scoped restart. */
export function managedInterfaceRequiresRestart(
  previous: ManagedInterfaceConfig,
  target: ManagedInterfaceConfig
) {
  return !same([...previous.fields].sort(), [...target.fields].sort());
}

/** Exact configuration semantics; endpoint observations retain normal roaming. */
export function verifyManagedInterfaceState(
  interfaceId: string,
  config: string,
  observed: { showconf: string; addresses: string }
) {
  try {
    const expected = parseManagedInterfaceConfig(interfaceId, config),
      actual = parse(observed.showconf, false);
    const expectedKey = Buffer.from(
        deriveClientPublicKey(expected.fields.get('privatekey')!),
        'base64'
      ),
      actualKey = Buffer.from(
        deriveClientPublicKey(actual.fields.get('privatekey')!),
        'base64'
      );
    if (
      !timingSafeEqual(expectedKey, actualKey) ||
      integer(expected.fields.get('listenport'), 65535) !==
        integer(actual.fields.get('listenport'), 65535) ||
      mark(expected.fields.get('fwmark')) !==
        mark(actual.fields.get('fwmark')) ||
      Object.keys(awgDefaults).some(
        (name) =>
          awgValue(name, expected.fields) !== awgValue(name, actual.fields)
      )
    )
      fail('interface_parameters_unverified');
    const expectedPeers = new Map(
      expected.peers.map((p) => [p.get('publickey')!, p])
    );
    const awgConfigured = Object.keys(awgDefaults).some((name) =>
      expected.fields.has(name)
    );
    if (actual.peers.length !== expectedPeers.size)
      fail('peer_configuration_unverified');
    for (const peer of actual.peers) {
      const wanted = expectedPeers.get(peer.get('publickey')!);
      if (
        !wanted ||
        !same(
          canonicalPrefixes(peer.get('allowedips') ?? ''),
          canonicalPrefixes(wanted.get('allowedips') ?? '')
        ) ||
        integer(peer.get('persistentkeepalive'), 65535, 0) !==
          integer(wanted.get('persistentkeepalive'), 65535, 0)
      )
        fail('peer_configuration_unverified');
      const learnedAdvanced = boolean(peer.get('advancedsecurity'));
      if (
        (!awgConfigured && learnedAdvanced) ||
        (wanted.has('advancedsecurity') &&
          learnedAdvanced !== boolean(wanted.get('advancedsecurity')))
      )
        fail('peer_advanced_security_unverified');
      // Endpoints can legitimately change after authenticated roaming. Do not
      // claim published reachability, or equate a seed hostname with a live IP.
      if (peer.has('endpoint')) validateEndpoint(peer.get('endpoint')!, false);
    }
    verifyPeerSyncPresharedKeys(
      interfaceId,
      config,
      actual.peers
        .map(
          (p) => `${p.get('publickey')}\t${p.get('presharedkey') ?? '(none)'}`
        )
        .join('\n')
    );
    const links = JSON.parse(observed.addresses);
    if (!Array.isArray(links) || links.length !== 1)
      fail('interface_addresses_unverified');
    const link = links[0];
    if (
      link.ifname !== interfaceId ||
      !Array.isArray(link.flags) ||
      !link.flags.includes('UP') ||
      link.mtu !== integer(expected.fields.get('mtu'), 65535) ||
      !Array.isArray(link.addr_info)
    )
      fail('interface_addresses_unverified');
    const addresses = link.addr_info
      .filter(
        (a: { family: string; scope: string }) =>
          !(a.family === 'inet6' && a.scope === 'link')
      )
      .map(
        (a: {
          local: string;
          prefixlen: number;
          tentative?: boolean;
          dadfailed?: boolean;
        }) => {
          if (a.tentative || a.dadfailed)
            fail('interface_addresses_unverified');
          return address(`${a.local}/${a.prefixlen}`);
        }
      )
      .sort();
    if (
      !same(
        addresses,
        expected.fields.get('address')!.split(',').map(address).sort()
      )
    )
      fail('interface_addresses_unverified');
  } catch (error) {
    throw new ManagedInterfaceStateError(
      error instanceof ManagedInterfaceStateError
        ? error.code
        : 'state_unverified',
      InterfaceNameSchema.safeParse(interfaceId).success
        ? interfaceId
        : undefined
    );
  }
}

/**
 * Recovery only: known partial writes may be undone under the retained guard.
 * This never establishes Applied evidence; full verification is still required.
 */
export function verifyRecoverableManagedInterfaceState(
  interfaceId: string,
  configs: readonly string[],
  observed: { showconf: string; addresses: string },
  { allowPartialStart = false }: { allowPartialStart?: boolean } = {}
) {
  let scope = 'parse';
  try {
    if (configs.length < 1 || configs.length > 2) fail('unknown_partial_state');
    const expected = configs.map((config) =>
      parseManagedInterfaceConfig(interfaceId, config)
    );
    for (const config of configs) {
      try {
        verifyManagedInterfaceState(interfaceId, config, observed);
        return;
      } catch {
        /* A partial setconf/syncconf or quick startup is not Applied. */
      }
    }
    const actual = parse(observed.showconf, false, allowPartialStart),
      privateKey = actual.fields.get('privatekey'),
      publicKey = privateKey ? deriveClientPublicKey(privateKey) : null,
      links = JSON.parse(observed.addresses),
      blankUserspace =
        allowPartialStart &&
        !publicKey &&
        Array.isArray(links) &&
        links.length === 1 &&
        links[0].ifname === interfaceId &&
        links[0].linkinfo?.info_kind === 'tun' &&
        links[0].linkinfo?.info_data?.type === 'tun' &&
        links[0].linkinfo?.info_data?.persist === false &&
        Array.isArray(links[0].flags) &&
        !links[0].flags.includes('UP') &&
        Array.isArray(links[0].addr_info) &&
        links[0].addr_info.length === 0 &&
        links[0].mtu === 1420,
      keyMatches =
        publicKey &&
        expected.some(
          (e) =>
            deriveClientPublicKey(e.fields.get('privatekey')!) === publicKey
        );
    scope = 'server_identity';
    if (publicKey && !keyMatches) fail('unknown_partial_state');
    if (!publicKey && (!allowPartialStart || actual.peers.length > 0))
      fail('unknown_partial_state');
    scope = 'listen_port';
    if (
      !expected.some(
        (e) =>
          integer(e.fields.get('listenport'), 65535) ===
          integer(actual.fields.get('listenport'), 65535, 0)
      ) &&
      !(
        allowPartialStart &&
        (integer(actual.fields.get('listenport'), 65535, 0) === 0 ||
          blankUserspace)
      )
    )
      fail('unknown_partial_state');
    scope = 'interface_mark';
    if (
      !expected.some(
        (e) =>
          mark(e.fields.get('fwmark')) === mark(actual.fields.get('fwmark'))
      ) &&
      !(allowPartialStart && mark(actual.fields.get('fwmark')) === 0)
    )
      fail('unknown_partial_state');
    scope = 'interface_parameters';
    for (const name of Object.keys(awgDefaults)) {
      const value = awgValue(name, actual.fields);
      if (
        !expected.some((e) => awgValue(name, e.fields) === value) &&
        !(allowPartialStart && awgValue(name, new Map()) === value)
      )
        fail('unknown_partial_state');
    }
    scope = 'uninitialized_parameters';
    if (
      !publicKey &&
      ((!blankUserspace &&
        integer(actual.fields.get('listenport'), 65535, 0) !== 0) ||
        mark(actual.fields.get('fwmark')) !== 0 ||
        Object.keys(awgDefaults).some(
          (name) => awgValue(name, actual.fields) !== awgValue(name, new Map())
        ))
    )
      fail('unknown_partial_state');
    const peers = new Map<string, Map<string, string>[]>();
    for (const config of expected)
      for (const peer of config.peers) {
        const key = peer.get('publickey')!;
        peers.set(key, [...(peers.get(key) ?? []), peer]);
      }
    const awgConfigured = expected.some((e) =>
      Object.keys(awgDefaults).some((name) => e.fields.has(name))
    );
    scope = 'peer_state';
    for (const peer of actual.peers) {
      const key = peer.get('publickey')!,
        known = peers.get(key);
      if (!known) fail('unknown_partial_state');
      const prefixes = new Set(
        known.flatMap((p) => canonicalPrefixes(p.get('allowedips') ?? ''))
      );
      if (
        canonicalPrefixes(peer.get('allowedips') ?? '').some(
          (p) => !prefixes.has(p)
        )
      )
        fail('unknown_partial_state');
      const keepalive = integer(peer.get('persistentkeepalive'), 65535, 0);
      if (
        keepalive !== 0 &&
        !known.some(
          (p) => keepalive === integer(p.get('persistentkeepalive'), 65535, 0)
        )
      )
        fail('unknown_partial_state');
      if (boolean(peer.get('advancedsecurity')) && !awgConfigured)
        fail('unknown_partial_state');
      if (peer.has('endpoint')) validateEndpoint(peer.get('endpoint')!, false);
      const candidates = [
        undefined,
        ...known.map((p) => p.get('presharedkey')),
      ];
      if (
        !candidates.some((psk) => {
          try {
            verifyPeerSyncPresharedKeys(
              interfaceId,
              `[Peer]\nPublicKey = ${key}\n${psk ? `PresharedKey = ${psk}\n` : ''}`,
              `${key}\t${peer.get('presharedkey') ?? '(none)'}`
            );
            return true;
          } catch {
            return false;
          }
        })
      )
        fail('unknown_partial_state');
    }
    scope = 'addresses';
    if (!Array.isArray(links) || links.length !== 1)
      fail('unknown_partial_state');
    const link = links[0],
      allowedAddresses = new Set(
        expected.flatMap((e) =>
          e.fields.get('address')!.split(',').map(address)
        )
      ),
      allowedMtus = new Set(
        expected.map((e) => integer(e.fields.get('mtu'), 65535))
      );
    if (allowPartialStart) {
      allowedMtus.add(1420);
      allowedMtus.add(1500);
    }
    if (
      link.ifname !== interfaceId ||
      !Array.isArray(link.flags) ||
      !allowedMtus.has(link.mtu) ||
      !Array.isArray(link.addr_info)
    )
      fail('unknown_partial_state');
    for (const entry of link.addr_info) {
      if (entry.family === 'inet6' && entry.scope === 'link') continue;
      if (
        !publicKey ||
        !['inet', 'inet6'].includes(entry.family) ||
        !allowedAddresses.has(address(`${entry.local}/${entry.prefixlen}`))
      )
        fail('unknown_partial_state');
    }
  } catch {
    throw new ManagedInterfaceStateError(
      'unknown_partial_state',
      InterfaceNameSchema.safeParse(interfaceId).success
        ? interfaceId
        : undefined,
      scope
    );
  }
}
