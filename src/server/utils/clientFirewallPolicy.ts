import { normalizeCidr, parseCidr } from 'cidr-tools';
import { isIPv4, isIPv6 } from 'is-ip';
import isCidr from 'is-cidr';
import z from 'zod';

import { InterfaceNameSchema } from '#shared/utils/schemas';
import type { PolicyClientFirewall } from '#shared/types/routingPolicy';

const entry = z
  .strictObject({
    interfaceId: InterfaceNameSchema,
    clientId: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    clientName: z
      .string()
      .max(256)
      .regex(/^client [0-9]+: [A-Za-z0-9 _.-]*$/),
    family: z.union([z.literal(4), z.literal(6)]),
    source: z.string(),
    destination: z.string(),
    port: z.number().int().min(1).max(65535).optional(),
    proto: z.enum(['tcp', 'udp', 'both']).optional(),
  })
  .superRefine((value, ctx) => {
    try {
      const validSource =
        value.family === 4 ? isIPv4(value.source) : isIPv6(value.source);
      const destination = parseCidr(value.destination);
      if (
        !validSource ||
        !(
          isIPv4(value.destination) ||
          isIPv6(value.destination) ||
          isCidr(value.destination)
        ) ||
        destination.version !== value.family ||
        (value.port === undefined) !== (value.proto === undefined) ||
        !value.clientName.startsWith(`client ${value.clientId}: `)
      )
        throw new Error();
    } catch {
      ctx.addIssue({ code: 'custom', message: 'Invalid client filter entry' });
    }
  });
export const ClientFirewallPolicySchema = z
  .strictObject({
    enableIpv6: z.boolean(),
    interfaces: z.array(
      z.strictObject({ interfaceId: InterfaceNameSchema, ipv6: z.boolean() })
    ),
    entries: z.array(entry),
  })
  .superRefine((value, ctx) => {
    const interfaces = new Map(value.interfaces.map((i) => [i.interfaceId, i]));
    if (
      interfaces.size !== value.interfaces.length ||
      value.interfaces.some((i) => i.ipv6 && !value.enableIpv6) ||
      value.entries.some(
        (e) =>
          !interfaces.has(e.interfaceId) ||
          (e.family === 6 && !interfaces.get(e.interfaceId)!.ipv6)
      )
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Invalid client filter interfaces',
      });
  });

export function validateClientFirewallPolicy(
  value: unknown
): PolicyClientFirewall {
  const parsed = ClientFirewallPolicySchema.safeParse(value);
  if (!parsed.success) throw new Error('Client firewall policy is invalid');
  return parsed.data;
}

/** Kernel save output adds host masks and protocol match modules. */
export function canonicalClientFirewallRule(value: string) {
  const args = clientFirewallRuleArguments(value);
  const result: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--comment') {
      result.push(arg, args[++i]!);
    } else if (arg === '-s' || arg === '-d') {
      const raw = args[++i]!;
      const address = normalizeCidr(
        raw.includes('/') ? raw : `${raw}/${isIPv6(raw) ? 128 : 32}`
      );
      if (!['0.0.0.0/0', '::/0'].includes(address)) result.push(arg, address);
    } else if (
      arg === '-m' &&
      ['tcp', 'udp'].includes(args[i + 1]!) &&
      args.indexOf('-p') >= 0 &&
      args[args.indexOf('-p') + 1] === args[i + 1]
    ) {
      i++;
    } else result.push(arg);
  }
  return JSON.stringify(result);
}

export function clientFirewallRuleArguments(value: string) {
  return (value.match(/"(?:\\.|[^"\\])*"|[^\s]+/g) ?? []).map((part) =>
    part.startsWith('"') ? (JSON.parse(part) as string) : part
  );
}
