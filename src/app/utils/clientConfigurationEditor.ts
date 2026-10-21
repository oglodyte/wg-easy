export type CredentialDraft = {
  replacePrivateKey: boolean;
  privateKey: string;
  pskAction: 'preserve' | 'replace' | 'clear';
  preSharedKey: string;
};

export function blankCredentials(): CredentialDraft {
  return {
    replacePrivateKey: false,
    privateKey: '',
    pskAction: 'preserve',
    preSharedKey: '',
  };
}

/** Blank untouched secret controls must never replace an existing credential. */
export function credentialPayload(draft: CredentialDraft) {
  return {
    ...(draft.replacePrivateKey ? { privateKey: draft.privateKey.trim() } : {}),
    ...(draft.pskAction === 'replace'
      ? { preSharedKey: draft.preSharedKey.trim() }
      : {}),
    ...(draft.pskAction === 'clear' ? { preSharedKey: null } : {}),
  };
}

export function credentialsValid(draft: CredentialDraft) {
  const canonical = (value: string) =>
    /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(value.trim());
  return (
    (!draft.replacePrivateKey || canonical(draft.privateKey)) &&
    (draft.pskAction !== 'replace' || canonical(draft.preSharedKey))
  );
}

export const CLIENT_EDIT_FIELDS = [
  'name',
  'enabled',
  'expiresAt',
  'ipv4Address',
  'ipv6Address',
  'preUp',
  'postUp',
  'preDown',
  'postDown',
  'allowedIps',
  'serverAllowedIps',
  'firewallIps',
  'mtu',
  'jC',
  'jMin',
  'jMax',
  'i1',
  'i2',
  'i3',
  'i4',
  'i5',
  'persistentKeepalive',
  'serverEndpoint',
  'dns',
  'preferredConfigFormat',
] as const;

/** Exclude immutable identity, ownership, timestamps and redacted secret flags. */
export function clientEditPayload<T extends object>(
  data: T,
  credentials: CredentialDraft
): Record<string, unknown> {
  return {
    ...Object.fromEntries(
      CLIENT_EDIT_FIELDS.filter((key) => key in data).map((key) => [
        key,
        data[key as keyof T],
      ])
    ),
    ...credentialPayload(credentials),
  };
}

export type ClientConfigurationDraft = {
  name: string;
  enabled: boolean;
  expiresAt: string | null;
  ipv4Address: string;
  ipv6Address: string | null;
  allowedIps: string[] | null;
  serverAllowedIps: string[];
  firewallIps: string[] | null;
  dns: string[] | null;
  mtu: number | null;
  persistentKeepalive: number | null;
  serverEndpoint: string | null;
  preUp: string;
  postUp: string;
  preDown: string;
  postDown: string;
  jC: number | null;
  jMin: number | null;
  jMax: number | null;
  i1: string | null;
  i2: string | null;
  i3: string | null;
  i4: string | null;
  i5: string | null;
  preferredConfigFormat: 'auto' | 'wireguard' | 'amneziawg';
};

export function blankClientConfiguration(): ClientConfigurationDraft {
  return {
    name: '',
    enabled: true,
    expiresAt: null,
    ipv4Address: '',
    ipv6Address: null,
    allowedIps: null,
    serverAllowedIps: [],
    firewallIps: null,
    dns: null,
    mtu: null,
    persistentKeepalive: null,
    serverEndpoint: null,
    preUp: '',
    postUp: '',
    preDown: '',
    postDown: '',
    jC: null,
    jMin: null,
    jMax: null,
    i1: null,
    i2: null,
    i3: null,
    i4: null,
    i5: null,
    preferredConfigFormat: 'auto',
  };
}

export function clientCreatePayload(
  data: ClientConfigurationDraft,
  credentials: CredentialDraft,
  options: { interfaceId: string; disableIpv6: boolean; overrideAwg: boolean }
) {
  const body = clientEditPayload(data, credentials);
  if (!data.ipv4Address.trim()) delete body.ipv4Address;
  if (options.disableIpv6) body.ipv6Address = null;
  else if (!data.ipv6Address) delete body.ipv6Address;
  if (data.mtu === null) delete body.mtu;
  if (data.persistentKeepalive === null) delete body.persistentKeepalive;
  const awgFields = ['jC', 'jMin', 'jMax', 'i1', 'i2', 'i3', 'i4', 'i5'];
  return {
    ...Object.fromEntries(
      Object.entries(body).filter(
        ([key]) => options.overrideAwg || !awgFields.includes(key)
      )
    ),
    interfaceId: options.interfaceId,
  };
}
