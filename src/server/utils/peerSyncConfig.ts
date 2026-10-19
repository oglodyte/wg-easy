import { timingSafeEqual } from 'node:crypto';

import { InterfaceNameSchema } from '#shared/utils/schemas';

const CLEARED_PRESHARED_KEY = Buffer.alloc(32).toString('base64');

export class PeerSyncCredentialError extends Error {
  constructor(
    readonly code: string,
    readonly interfaceId?: string
  ) {
    super(`Peer synchronization: ${code}`);
    this.name = 'PeerSyncCredentialError';
  }
}

/** Saved/exported configurations retain omission; only private sync input clears. */
export function preparePeerSyncConfig(config: string) {
  const result: string[] = [];
  let peer = false,
    hasPsk = false;
  const finish = () => {
    if (peer && !hasPsk) result.push(`PresharedKey = ${CLEARED_PRESHARED_KEY}`);
  };
  for (const line of config.trimEnd().split(/\r?\n/)) {
    if (/^[ \t]*\[[^\]]+\][ \t]*$/.test(line)) {
      finish();
      peer = /^[ \t]*\[Peer\][ \t]*$/i.test(line);
      hasPsk = false;
    }
    if (peer && /^[ \t]*PresharedKey[ \t]*=/i.test(line)) hasPsk = true;
    result.push(line);
  }
  finish();
  return result.join('\n') + '\n';
}

function key(value: string) {
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 32 || decoded.toString('base64') !== value)
    throw new PeerSyncCredentialError('invalid_credential_state');
  return decoded;
}

/** Strict complete peer PSKs, compared only in memory; never echo input or causes. */
export function verifyPeerSyncPresharedKeys(
  interfaceId: string,
  config: string,
  observed: string
) {
  try {
    if (!InterfaceNameSchema.safeParse(interfaceId).success) throw new Error();
    const expected = new Map<string, Buffer>();
    let peer = false,
      publicKey: string | undefined,
      psk: string | undefined;
    const finish = () => {
      if (!peer) return;
      if (!publicKey || expected.has(publicKey)) throw new Error();
      key(publicKey);
      expected.set(publicKey, key(psk ?? CLEARED_PRESHARED_KEY));
    };
    for (const line of config.split(/\r?\n/)) {
      if (/^[ \t]*\[[^\]]+\][ \t]*$/.test(line)) {
        finish();
        peer = /^[ \t]*\[Peer\][ \t]*$/i.test(line);
        publicKey = undefined;
        psk = undefined;
      } else if (peer) {
        const match = line.match(
          /^[ \t]*(PublicKey|PresharedKey)[ \t]*=[ \t]*([^#]*?)[ \t]*(?:#.*)?$/i
        );
        if (!match) continue;
        if (match[1]!.toLowerCase() === 'publickey') {
          if (publicKey !== undefined) throw new Error();
          publicKey = match[2]!.trim();
        } else {
          if (psk !== undefined) throw new Error();
          psk = match[2]!.trim();
        }
      }
    }
    finish();
    const seen = new Set<string>();
    for (const line of observed
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)) {
      const [publicKey, value, extra] = line.split(/\s+/);
      if (!publicKey || !value || extra || seen.has(publicKey))
        throw new Error();
      seen.add(publicKey);
      const desired = expected.get(publicKey);
      if (
        !desired ||
        !timingSafeEqual(
          desired,
          key(value === '(none)' ? CLEARED_PRESHARED_KEY : value)
        )
      )
        throw new Error();
    }
    if (seen.size !== expected.size) throw new Error();
  } catch {
    throw new PeerSyncCredentialError(
      'preshared_keys_unverified',
      InterfaceNameSchema.safeParse(interfaceId).success
        ? interfaceId
        : undefined
    );
  }
}
