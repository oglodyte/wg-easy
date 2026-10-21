export const PRIVATE_IPV4_PREFIXES = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
] as const;

export function parsePrefixList(value: string) {
  return value
    .split(/[,\n\r]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function withPrivateExclusions(value: string) {
  return [
    ...new Set([...parsePrefixList(value), ...PRIVATE_IPV4_PREFIXES]),
  ].join('\n');
}

/** Bind a preview to both the draft and the saved generation it was based on. */
export function previewMatches(
  preview: { draft: string; revision: number } | null,
  draft: string,
  revision: number | undefined
) {
  return (
    preview !== null && preview.draft === draft && preview.revision === revision
  );
}

/** Never show arbitrary exception bodies (which may contain submitted secrets). */
export function mutationErrorData(error: unknown): {
  message?: string;
  code?: string;
  detail?: {
    groupIds?: number[];
    clientIds?: number[];
    interfaceId?: string;
    destination?: string;
    budget?: string;
    limit?: number;
    actual?: number;
  };
} {
  const response = (
    error as {
      data?: { message?: string; data?: { code?: string; detail?: object } };
    }
  )?.data;
  return {
    message: response?.message,
    code: response?.data?.code,
    detail: response?.data?.detail,
  };
}
