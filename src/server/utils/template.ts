import { WG_ENV } from '#server/utils/config';
import { PortSchema } from '#server/utils/types';
import type { InterfaceType } from '#db/repositories/interface/types';
import {
  InterfaceNameSchema,
  Ipv4CidrSchema,
  Ipv6CidrSchema,
  NetworkDeviceSchema,
} from '#shared/utils/schemas';

/**
 * Replace all {{key}} in the template with the values[key]
 */
export function template(templ: string, values: Record<string, string>) {
  return templ.replace(/\{\{(\w+)\}\}/g, (match, key) => {
    return values[key] !== undefined ? values[key] : match;
  });
}

export function removeNewlines(templ: string) {
  return templ.replace(/\r\n|\r|\n/g, ' ');
}

/**
 * Available keys:
 * - name: managed interface name
 * - ipv4Cidr: IPv4 CIDR
 * - ipv6Cidr: IPv6 CIDR
 * - device: Network device
 * - port: Port number
 * - uiPort: UI port number
 */
export function iptablesTemplate(templ: string, wgInterface: InterfaceType) {
  return template(removeNewlines(templ), {
    name: InterfaceNameSchema.parse(wgInterface.name),
    ipv4Cidr: Ipv4CidrSchema.parse(wgInterface.ipv4Cidr),
    ipv6Cidr: Ipv6CidrSchema.parse(wgInterface.ipv6Cidr),
    device: NetworkDeviceSchema.parse(wgInterface.device),
    port: PortSchema.parse(wgInterface.port).toString(),
    uiPort: PortSchema.parse(Number(WG_ENV.PORT)).toString(),
  });
}
