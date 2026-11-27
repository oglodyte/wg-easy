import type { InterfaceType } from '#db/repositories/interface/types';

export function publicInterface(value: InterfaceType) {
  const { privateKey: _privateKey, headerProtectionKey, ...safe } = value;
  return { ...safe, hasHeaderProtectionKey: headerProtectionKey !== null };
}
