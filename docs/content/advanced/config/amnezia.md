---
title: AmneziaWG
---

## Introduction

**AmneziaWG** is a modified version of the WireGuard protocol with enhanced traffic obfuscation capabilities. AmneziaWG's primary goal is to counter deep packet inspection (DPI) systems and bypass VPN blocking.

AmneziaWG adds multi-level transport-layer obfuscation by:

- Modifying packet headers
- Randomizing handshake message sizes
- Disguising traffic to resemble popular UDP protocols

These measures make it harder for third parties to analyze or identify your traffic, enhancing both privacy and security.

## Runtime and compatibility modes

wg-easy runs every managed interface through the AmneziaWG (`awg`) backend.
The kernel module is preferred, and the bundled `amneziawg-go` userspace
implementation is the supported fallback. Mount `/dev/net/tun` for userspace
operation. Set `AWG_FORCE_USERSPACE=true` if a present kernel module is
incompatible or unstable; this still uses the AWG backend.

There is no per-interface standard-WireGuard runtime backend. Instead, an
interface is compatible with standard WireGuard clients when **AWG parameters**
are disabled: wg-easy omits every AWG-only line from generated server and
client configurations. When AWG parameters are enabled, use an
AmneziaWG-compatible client and AmneziaWG export format; standard WireGuard
export is rejected.

For multi-interface operation, see [Managed Interfaces and Common
Routing](../multi-interface-routing.md).

## AmneziaWG Parameters

Parameter descriptions can be found in the [AmneziaWG documentation](https://docs.amnezia.org/documentation/amnezia-wg) and on the [kernel module page](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module).

All parameters except I1-I5 will be set at first startup. For information on how to set I1-I5 parameters, refer to the [AmneziaWG documentation](https://docs.amnezia.org/documentation/instructions/new-amneziawg-selfhosted/#how-to-extract-a-protocol-signature-for-amneziawg-15-manually).

If a parameter is not set, it will not be added to the configuration. If all AmneziaWG-specific parameters are absent, AmneziaWG will be fully compatible with standard WireGuard.

### Parameter Compatibility Table

| Parameter | Can differ between server and client | Configurable on server | Configurable on client   |
| --------- | ------------------------------------ | ---------------------- | ------------------------ |
| Jc        | :white_check_mark: Yes               | :white_check_mark:     | :white_check_mark:       |
| Jmin      | :white_check_mark: Yes               | :white_check_mark:     | :white_check_mark:       |
| Jmax      | :white_check_mark: Yes               | :white_check_mark:     | :white_check_mark:       |
| S1-S4     | :x: No, must match                   | :white_check_mark:     | :x: (copied from server) |
| H1-H4     | :x: No, must match                   | :white_check_mark:     | :x: (copied from server) |
| I1-I5     | :white_check_mark: Yes               | :white_check_mark:     | :white_check_mark:       |

## Client Applications

To be able to connect to wg-easy if AmneziaWG is enabled, you must have an AmneziaWG-compatible client. Where an AmneziaWG app is available for your platform, it is recommended to use it rather than Amnezia VPN.

Android:

- [AmneziaWG](https://play.google.com/store/apps/details?id=org.amnezia.awg) - AmneziaWG Official Client
- [WG Tunnel](https://play.google.com/store/apps/details?id=com.zaneschepke.wireguardautotunnel) - Third Party Client
- [Amnezia VPN](https://play.google.com/store/apps/details?id=org.amnezia.vpn) - Amnezia VPN Official Client

iOS and macOS:

- [AmneziaWG](https://apps.apple.com/us/app/amneziawg/id6478942365) - AmneziaWG Official Client
- [Amnezia VPN](https://apps.apple.com/us/app/amneziavpn/id1600529900) - Amnezia VPN Official Client

Windows:

- [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-windows-client/releases) - AmneziaWG Official Client (Requires building from source code)
- [Amnezia VPN](https://amnezia.org/downloads) - Amnezia VPN Official Client

Linux:

- [Amnezia VPN](https://amnezia.org/downloads) - Amnezia VPN Official Client
- [amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) - AmneziaWG Tools

OpenWRT:

- [AmneziaWG OpenWRT](https://github.com/Slava-Shchipunov/awg-openwrt) - AmneziaWG OpenWRT Packages
- [AmneziaWG OpenWRT](https://github.com/lolo6oT/awg-openwrt) - AmneziaWG OpenWRT Packages


## AWG 3.1 settings in this fork

Managed interfaces and client profiles support the upstream 3.1 settings. The
six timer/padding/attempt fields accept a decimal number or inclusive range
between 0 and 65535. Explicit zero and disabled boolean values are retained.
Unset new fields preserve existing configuration and runtime defaults.

The header protection key is a nonzero 32-byte canonical base64 secret. It is
never returned by settings APIs or preloaded in the editor. Keep, replace and
clear are explicit actions. Header protection requires S1–S4 to be at least 12
bytes. The key and RandomTrailers must match on both tunnel ends and are copied
to authorized client configuration exports. Redistribute profiles after changing
shared obfuscation parameters. Interface names remain immutable.

The image provides AWG 3.1 userspace. A host kernel module can support fewer
parameters; an unsupported setting must fail application verification, and the
UI must not report it applied. Docker UDP publication remains operator-managed.
WireGuard compatibility mode omits every AWG-only parameter from exports.

Upgrade this fork using its append-only migration history and a matched volume
snapshot. A database created directly by native upstream 15.5 is not an upgrade
input; startup refuses that lineage before migration.
