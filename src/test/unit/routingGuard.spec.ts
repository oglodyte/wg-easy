import { describe, expect, test, vi } from 'vitest';

import { firewallTestExports } from '#server/utils/firewall';
import {
  assertRoutingGuardState,
  buildRoutingGuard,
  RoutingGuard,
  routingGuardRestoreDocument,
  type RoutingGuardScope,
} from '#server/utils/routingGuard';

const scope: RoutingGuardScope = {
  direction: 'forward',
  inputInterface: 'wg0',
  source: '10.8.0.2/32',
  destination: '172.31.0.0/24',
};
const plan = buildRoutingGuard([scope], { protectedPaths: [] });
const jump =
  '-A FORWARD -s 10.8.0.2/32 -d 172.31.0.0/24 -i wg0 -m comment --comment "wg-easy routing guard scope" -j WG_ROUTE_GUARD';
const established =
  '-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT';
const empty =
  '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n';
const installed = `${empty.replace('COMMIT\n', '')}:WG_ROUTE_GUARD - [0:0]
-A WG_ROUTE_GUARD -m comment --comment "wg-easy routing guard owner ${plan.fingerprint}"
-A WG_ROUTE_GUARD -m comment --comment "wg-easy routing guard drop" -j DROP
${jump}
${established}
COMMIT
`;

describe('scoped routing transition guard', () => {
  test('canonicalizes/deduplicates scopes with deterministic identity', () => {
    const other = { ...scope, direction: 'input' as const };
    expect(
      buildRoutingGuard([scope, other, scope], { protectedPaths: [] })
    ).toEqual(buildRoutingGuard([other, scope], { protectedPaths: [] }));
    expect(
      buildRoutingGuard([{ ...scope, destination: '172.31.0.9/24' }], {
        protectedPaths: [],
      })
    ).toEqual(plan);
  });

  test('requires an interface and valid directional IPv4 matches', () => {
    for (const invalid of [
      { ...scope, inputInterface: undefined },
      { ...scope, inputInterface: 'wg0\n-j ACCEPT' },
      { ...scope, destination: '::/0' },
      { ...scope, source: '10.8.0.2' },
      { ...scope, direction: 'output' },
      { ...scope, direction: 'input', outputInterface: 'wg1' },
    ])
      expect(() =>
        buildRoutingGuard([invalid as RoutingGuardScope], {
          protectedPaths: [],
        })
      ).toThrow('invalid_scope');
  });

  test('refuses management intersections and permits independent paths', () => {
    expect(() =>
      buildRoutingGuard([scope], { protectedPaths: [scope] })
    ).toThrow('management_collision');
    expect(() =>
      buildRoutingGuard([scope], {
        protectedPaths: [{ ...scope, inputInterface: 'eth0' }],
      })
    ).not.toThrow();
    expect(() =>
      buildRoutingGuard([scope], {
        protectedPaths: [{ ...scope, destination: '192.0.2.0/24' }],
      })
    ).not.toThrow();
  });

  test('requires exact ownership, manifest, references and first hook position', () => {
    expect(() => assertRoutingGuardState(installed, plan)).not.toThrow();
    expect(() => assertRoutingGuardState(installed, null)).toThrow(
      'residual_guard'
    );
    expect(() =>
      assertRoutingGuardState(
        installed.replace(`${jump}\n${established}`, `${established}\n${jump}`),
        plan
      )
    ).toThrow('hook_bypassed');
    expect(() =>
      assertRoutingGuardState(installed.replace(jump, `${jump}\n${jump}`), plan)
    ).toThrow('manifest_mismatch');
    expect(() =>
      assertRoutingGuardState(
        installed.replace('COMMIT', '-A INPUT -j WG_ROUTE_GUARD\nCOMMIT'),
        plan
      )
    ).toThrow('manifest_mismatch');
    expect(() =>
      assertRoutingGuardState(
        installed.replace('COMMIT', '-A WG_ROUTE_GUARD -j ACCEPT\nCOMMIT'),
        plan
      )
    ).toThrow('manifest_mismatch');
    expect(() =>
      assertRoutingGuardState(
        installed.replace(plan.fingerprint, 'a'.repeat(64)),
        plan
      )
    ).toThrow('manifest_mismatch');
  });

  test('only deletes exact known hooks and its own chain on verified removal', () => {
    const document = routingGuardRestoreDocument(installed, null, plan)!;
    expect(document).toContain(jump.replace('-A ', '-D '));
    expect(document).toContain('-X WG_ROUTE_GUARD');
    expect(document).not.toContain('-F FORWARD');
    expect(document).not.toContain(established);
    expect(() => routingGuardRestoreDocument(installed, null, null)).toThrow();
    expect(() =>
      routingGuardRestoreDocument(empty, plan, { ...plan, fingerprint: 'bad' })
    ).toThrow();
  });

  test('keeps guard hooks first in the atomic client-firewall replacement', () => {
    const document = firewallTestExports.buildRestoreDocument({
      family: 4,
      states: [
        {
          wgInterface: { name: 'wg0', enabled: true, firewallEnabled: true },
          observedUp: true,
          clients: [],
          userConfig: { defaultAllowedIps: [] },
        },
      ] as never,
      existingSave: installed,
      guard: plan,
    });
    expect(document.indexOf('-I FORWARD 1 -i wg0')).toBeLessThan(
      document.indexOf(jump.replace('-A FORWARD ', '-I FORWARD 1 '))
    );
    expect(document).not.toContain('-F WG_ROUTE_GUARD');
    expect(() =>
      firewallTestExports.buildRestoreDocument({
        family: 4,
        states: [],
        existingSave: installed,
      })
    ).toThrow('residual_guard');
  });

  test('does not mutate Linux after failed preflight', async () => {
    const run = vi.fn(
      async (executable: string, args: readonly string[] = []) => {
        if (executable === 'iptables-save') return empty;
        if (args.includes('--test'))
          throw new Error('restore preflight rejected');
        throw new Error('unexpected mutation');
      }
    );
    await expect(new RoutingGuard(run).install(plan)).rejects.toThrow(
      'preflight rejected'
    );
    expect(
      run.mock.calls.filter(
        ([binary, args]) =>
          binary === 'iptables-restore' && !args?.includes('--test')
      )
    ).toHaveLength(0);
  });

  test('never removes an installed guard when its verification fails', async () => {
    let observations = 0;
    const run = vi.fn(
      async (executable: string, _args: readonly string[] = []) => {
        if (executable === 'iptables-save')
          return observations++ === 0 ? empty : installed.replace(jump, '');
        return '';
      }
    );
    await expect(new RoutingGuard(run).install(plan)).rejects.toThrow(
      'manifest_mismatch'
    );
    expect(
      run.mock.calls.filter(([binary]) => binary === 'iptables-restore')
    ).toHaveLength(2);
  });

  test('rejects the actual generated rule budget before accumulating excess rules', () => {
    const scopes = Array.from({ length: 44097 }, (_, i) => ({
      ...scope,
      source: `10.${Math.floor(i / 65536)}.${Math.floor(i / 256) % 256}.${i % 256}/32`,
    }));
    let caught: unknown;
    try {
      buildRoutingGuard(scopes, { protectedPaths: [] });
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({
      code: 'rule_budget_exceeded',
      detail: { actual: 44097, limit: 44096 },
    });
  });
});
