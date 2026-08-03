export function generateAwgParameterLines(
  parametersEnabled: boolean,
  parameters: Readonly<Record<string, string | number | null>>,
  runtimeBackend: string
) {
  if (runtimeBackend !== 'awg' || !parametersEnabled) {
    return [];
  }

  return Object.entries(parameters)
    .filter(([_, value]) => !!value)
    .map(([key, value]) => `${key} = ${value}`);
}
