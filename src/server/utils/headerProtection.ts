import { HeaderProtectionKeySchema } from '#server/utils/types';

export class HeaderProtectionConfigurationError extends Error {
  constructor(readonly code: 'invalid_key' | 'invalid_padding') {
    super(`Header protection configuration: ${code}`);
  }
}

/** Validate stored + submitted state without exposing private parameter values. */
export function assertHeaderProtectionConfiguration(value: {
  headerProtectionKey: string | null;
  s1: number | null;
  s2: number | null;
  s3: number | null;
  s4: number | null;
}) {
  if (value.headerProtectionKey === null) return;
  if (!HeaderProtectionKeySchema.safeParse(value.headerProtectionKey).success) {
    throw new HeaderProtectionConfigurationError('invalid_key');
  }
  if (
    [value.s1, value.s2, value.s3, value.s4].some(
      (size) => size === null || !Number.isInteger(size) || size < 12
    )
  ) {
    throw new HeaderProtectionConfigurationError('invalid_padding');
  }
}
