import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';

import { VpnKeySchema } from '#db/repositories/client/types';

/** Never include supplied credential values in exceptions. */
export class ClientCredentialError extends Error {
  constructor(readonly code: 'invalid_key' | 'key_mismatch') {
    super(`Client credentials: ${code}`);
  }
}
export function deriveClientPublicKey(privateKey: string) {
  if (!VpnKeySchema.safeParse(privateKey).success)
    throw new ClientCredentialError('invalid_key');
  const object = createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      Buffer.from(privateKey, 'base64'),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
  return createPublicKey(object)
    .export({ format: 'der', type: 'spki' })
    .subarray(-32)
    .toString('base64');
}
export type ClientCredentials = {
  privateKey: string;
  publicKey: string;
  preSharedKey: string | null;
};

/** Inactive until Phase 2. Omission preserves edits and generates new profiles. */
export function prepareClientCredentials(
  input: {
    privateKey?: string;
    publicKey?: string;
    preSharedKey?: string | null;
  },
  existing?: ClientCredentials
): ClientCredentials {
  for (const value of [input.privateKey, input.publicKey, input.preSharedKey])
    if (
      value !== undefined &&
      value !== null &&
      !VpnKeySchema.safeParse(value).success
    )
      throw new ClientCredentialError('invalid_key');
  if (Object.hasOwn(input, 'privateKey') && !input.privateKey)
    throw new ClientCredentialError('invalid_key');
  const privateKey =
    input.privateKey ??
    existing?.privateKey ??
    randomBytes(32).toString('base64');
  // An edit that omits identity must retain the exact accepted pair. Derive
  // only a newly supplied identity or an explicitly requested pair check.
  const publicKey =
    existing && input.privateKey === undefined && input.publicKey === undefined
      ? existing.publicKey
      : deriveClientPublicKey(privateKey);
  if (input.publicKey !== undefined && input.publicKey !== publicKey)
    throw new ClientCredentialError('key_mismatch');
  const preSharedKey =
    input.preSharedKey === undefined
      ? existing
        ? existing.preSharedKey
        : randomBytes(32).toString('base64')
      : input.preSharedKey;
  return { privateKey, publicKey, preSharedKey };
}
