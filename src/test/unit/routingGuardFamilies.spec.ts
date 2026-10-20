import { describe, expect, test } from 'vitest';

import type { execFile } from '#server/utils/cmd';
import {
  assertRoutingGuardState,
  buildRoutingGuard,
  RoutingGuard,
  routingGuardRestoreDocument,
} from '#server/utils/routingGuard';

const empty =
  '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n';
const scope = {
  direction: 'forward' as const,
  inputInterface: 'wg0',
  source: '10.8.0.2/32',
  destination: '0.0.0.0/0',
};
const ipv6 = { ...scope, source: 'fd08::2/128', destination: '::/0' };
const plan = buildRoutingGuard([scope, ipv6], { protectedPaths: [] });
function kernel() {
  const saves = new Map<4 | 6, string>([
      [4, empty],
      [6, empty],
    ]),
    calls: { family: 4 | 6; test: boolean }[] = [];
  let failure = '';
  const run: typeof execFile = async (binary, args = [], options = {}) => {
    const family = binary.startsWith('ip6') ? 6 : 4;
    if (binary.endsWith('-save')) return saves.get(family)!;
    const testing = args.includes('--test');
    calls.push({ family, test: testing });
    if (failure === `${family}-${testing ? 'test' : 'write'}`)
      throw new Error('fixture failure');
    if (!testing) {
      const document = options.input!;
      saves.set(
        family,
        document.includes('-X WG_ROUTE_GUARD')
          ? empty
          : document
              .split('\n')
              .filter((l) => !l.startsWith('-F ') && !l.startsWith('-D '))
              .map((l) => l.replace(/^-I (INPUT|FORWARD|OUTPUT) 1 /, '-A $1 '))
              .join('\n')
      );
    }
    return '';
  };
  return {
    run,
    saves,
    calls,
    setFailure: (value: string) => {
      failure = value;
    },
  };
}
describe('dual-family exact transition guards', () => {
  test('replays a persisted guard rebase across mixed old/new families and removes an obsolete IPv6 guard', async () => {
    const k = kernel(),
      target = buildRoutingGuard(
        [
          { ...scope, destination: '172.31.0.0/16' },
          { ...ipv6, destination: '2001:db8::/32' },
        ],
        { protectedPaths: [] }
      );
    await new RoutingGuard(k.run).install(plan);
    k.setFailure('6-write');
    await expect(new RoutingGuard(k.run).ensure(target, plan)).rejects.toThrow(
      'fixture failure'
    );
    assertRoutingGuardState(k.saves.get(4)!, target, 4);
    assertRoutingGuardState(k.saves.get(6)!, plan, 6);
    k.setFailure('');
    await new RoutingGuard(k.run).ensure(target, plan);
    await new RoutingGuard(k.run).verify(target);
    const ipv4Only = buildRoutingGuard([scope], { protectedPaths: [] });
    await new RoutingGuard(k.run).ensure(ipv4Only, target);
    assertRoutingGuardState(k.saves.get(6)!, null, 6);
    await new RoutingGuard(k.run).verify(ipv4Only);
  });

  test('a guard rebase refuses unknown family state before any replacement', async () => {
    const k = kernel();
    await new RoutingGuard(k.run).install(plan);
    k.saves.set(
      6,
      k.saves.get(6)!.replace('COMMIT', '-A WG_ROUTE_GUARD -j ACCEPT\nCOMMIT')
    );
    k.calls.length = 0;
    const target = buildRoutingGuard([scope], { protectedPaths: [] });
    await expect(new RoutingGuard(k.run).ensure(target, plan)).rejects.toThrow(
      'residual_guard'
    );
    expect(k.calls).toEqual([]);
    assertRoutingGuardState(k.saves.get(4)!, plan, 4);
  });

  test('validates same-family matches and management intersections without cross-family false positives', () => {
    expect(() =>
      buildRoutingGuard([ipv6], { protectedPaths: [scope] })
    ).not.toThrow();
    expect(() => buildRoutingGuard([ipv6], { protectedPaths: [ipv6] })).toThrow(
      'management_collision'
    );
    expect(() =>
      buildRoutingGuard([{ ...ipv6, destination: '0.0.0.0/0' }], {
        protectedPaths: [],
      })
    ).toThrow('invalid_scope');
    expect(() =>
      buildRoutingGuard(
        [{ ...ipv6, inputInterface: undefined, source: '::/0' }],
        { protectedPaths: [] }
      )
    ).toThrow('invalid_scope');
  });
  test('preflights IPv6 before the first IPv4 write', async () => {
    const k = kernel();
    k.setFailure('6-test');
    await expect(new RoutingGuard(k.run).install(plan)).rejects.toThrow(
      'fixture failure'
    );
    expect(k.calls).toEqual([
      { family: 4, test: true },
      { family: 6, test: true },
    ]);
    expect(k.saves.get(4)).toBe(empty);
  });
  test('a new recovery instance repairs only the exact missing family after interrupted install and removal', async () => {
    const k = kernel();
    k.setFailure('6-write');
    await expect(new RoutingGuard(k.run).install(plan)).rejects.toThrow(
      'fixture failure'
    );
    assertRoutingGuardState(k.saves.get(4)!, plan, 4);
    assertRoutingGuardState(k.saves.get(6)!, null, 6);
    k.setFailure('');
    k.calls.length = 0;
    await new RoutingGuard(k.run).ensure(plan);
    expect(k.calls).toEqual([
      { family: 6, test: true },
      { family: 6, test: false },
    ]);
    await new RoutingGuard(k.run).verify(plan);
    k.setFailure('6-write');
    await expect(new RoutingGuard(k.run).remove(plan)).rejects.toThrow(
      'fixture failure'
    );
    assertRoutingGuardState(k.saves.get(4)!, null, 4);
    assertRoutingGuardState(k.saves.get(6)!, plan, 6);
    k.setFailure('');
    k.calls.length = 0;
    await new RoutingGuard(k.run).ensure(plan);
    expect(k.calls).toEqual([
      { family: 4, test: true },
      { family: 4, test: false },
    ]);
    await new RoutingGuard(k.run).remove(plan);
    await new RoutingGuard(k.run).verify(null, { families: [4, 6] });
  });
  test('unknown IPv6 state refuses any partial-family repair or deletion', async () => {
    const k = kernel();
    const installed = routingGuardRestoreDocument(empty, plan, null, 6)!
      .split('\n')
      .filter((l) => !l.startsWith('-F '))
      .map((l) => l.replace(/^-I (INPUT|FORWARD|OUTPUT) 1 /, '-A $1 '))
      .join('\n');
    k.saves.set(
      6,
      installed.replace('COMMIT', '-A WG_ROUTE_GUARD -j ACCEPT\nCOMMIT')
    );
    await expect(new RoutingGuard(k.run).ensure(plan)).rejects.toThrow(
      'residual_guard'
    );
    expect(k.calls).toEqual([]);
    expect(k.saves.get(4)).toBe(empty);
    expect(k.saves.get(6)).toContain('-j ACCEPT');
  });
});
