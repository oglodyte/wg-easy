import { describe, expect, test } from 'vitest';

import { GeneralUpdateSchema } from '#db/repositories/general/types';

describe('general settings validation', () => {
  test('accepts the payload returned by the general settings endpoint', () => {
    expect(
      GeneralUpdateSchema.parse({
        sessionTimeout: 3600,
        metricsPrometheus: true,
        metricsJson: false,
        metricsPassword: null,
      })
    ).toEqual({
      sessionTimeout: 3600,
      metricsPrometheus: true,
      metricsJson: false,
      metricsPassword: null,
    });
  });
});
