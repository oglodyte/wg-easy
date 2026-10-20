import { expect } from 'vitest';

import type { execFile } from '#server/utils/cmd';
import type { ManagedHookRule } from '#server/utils/managedServerHooks';
function ruleId(rule: ManagedHookRule) {
  return `${rule.family}:${rule.table} -A ${rule.chain} ${rule.args.join(' ')}`;
}
export function hookFirewall(previous: ManagedHookRule[], copies = 1) {
  const entries = previous.flatMap((r) =>
    Array.from({ length: copies }, () => ruleId(r))
  );
  const foreign = '4:filter -A FORWARD -m comment --comment foreign -j ACCEPT';
  entries.push(foreign);
  const writes: string[][] = [];
  let failAfter = -1;
  const run: typeof execFile = async (command, args = [], options = {}) => {
    if (command === 'ip') return JSON.stringify([{ dev: 'ens160' }]);
    const family = command.startsWith('iptables') ? 4 : 6;
    if (command.endsWith('-restore')) {
      const lines = options.input!.split('\n'),
        table = lines[0]!.slice(1),
        chain = lines[1]!.split(' ')[1]!,
        prefix = `${family}:${table} -A ${chain} `;
      expect(args).toContain('--noflush');
      if (args.includes('--test')) return '';
      const replacement = lines
          .filter((l) => l.startsWith(`-A ${chain} `))
          .map((l) => `${family}:${table} ${l}`),
        position = entries.findIndex((l) => l.startsWith(prefix));
      for (let i = entries.length - 1; i >= 0; i--)
        if (entries[i]!.startsWith(prefix)) entries.splice(i, 1);
      entries.splice(
        position < 0 ? entries.length : position,
        0,
        ...replacement
      );
      writes.push([...args]);
      if (writes.length === failAfter)
        throw new Error('simulated process exit after atomic replacement');
      return '';
    }
    const table = args[3]!,
      operation = args[4]!,
      chain = args[5]!;
    expect(args.slice(0, 3)).toEqual(['-w', '5', '-t']);
    if (operation === '-S')
      return entries
        .filter((entry) => entry.startsWith(`${family}:${table} -A ${chain} `))
        .map((entry) => entry.slice(entry.indexOf(' ') + 1))
        .join('\n');
    throw new Error('unexpected direct mutation');
  };
  return {
    entries,
    foreign,
    writes,
    run,
    setFailure: (count: number) => {
      failAfter = count;
    },
  };
}
