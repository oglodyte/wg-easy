export function generateAwgParameterLines(
  parametersEnabled: boolean,
  parameters: Readonly<Record<string, string | number | boolean | null>>,
  runtimeBackend: string
) {
  if (runtimeBackend !== 'awg' || !parametersEnabled) {
    return [];
  }

  return Object.entries(parameters)
    .filter(
      ([_, value]) => value !== null && value !== undefined && value !== ''
    )
    .map(
      ([key, value]) =>
        `${key} = ${typeof value === 'boolean' ? (value ? 'on' : 'off') : value}`
    );
}
