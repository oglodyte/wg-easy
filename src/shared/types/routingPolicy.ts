/** Non-secret compiler contracts. Profile IDs and runtime peers stay distinct. */
export type PolicyInterface = {
  interfaceId: string;
  ipv4Cidr: string;
  publicKey?: string;
};
export type PolicyClient = {
  id: number;
  name: string;
  interfaceId: string;
  publicKey: string;
  ipv4Address: string;
  ipv6Address?: string | null;
  enabled: boolean;
  serverAllowedIps: readonly string[];
};
export type PolicyGroup = {
  id: number;
  name: string;
  routingSlot: number;
  enabled: boolean;
  natEnabled: boolean;
  allExitsDownPolicy: 'block' | 'host';
  routedIpv4Prefixes: readonly string[];
  excludedIpv4Prefixes?: readonly string[];
  memberClientIds: readonly number[];
  exits: readonly { clientId: number; enabled: boolean; priority: number }[];
};
export type PolicySnapshot = {
  interfaces: readonly PolicyInterface[];
  clients: readonly PolicyClient[];
  groups: readonly PolicyGroup[];
};
export type PolicyCell = {
  start: number;
  end: number; // Exclusive, including 2^32.
  groupId: number;
  originalPrefix: string;
  specificity: number;
};
export type PolicySource = {
  clientId: number;
  interfaceId: string;
  ipv4Address: string;
};
export type PolicyProgram = {
  groupIds: number[];
  sources: PolicySource[];
  cells: PolicyCell[];
  branches: { prefix: string; groupId: number }[];
};
export type PolicyClaim = {
  interval: number;
  groupId: number;
  clientId: number;
  interfaceId: string;
  peerId: string;
};
export type PolicyCounts = {
  intervals: number;
  programs: number;
  sourceDispatches: number;
  dispatchEntries: number;
  classifierRules: number;
  candidateClaims: number;
  winnerWork: number;
  candidateComparisons: number;
  generatedPeerPrefixes: number;
};
export type CompiledPolicy = {
  version: 2;
  fingerprint: string;
  bypassPrefixes: string[];
  intervals: { start: number; end: number }[];
  programs: PolicyProgram[];
  groups: {
    id: number;
    name: string;
    includedPrefixes: string[];
    excludedPrefixes: string[];
    effectivePrefixes: string[];
    shadowed: boolean;
    natEnabled: boolean;
    allExitsDownPolicy: 'block' | 'host';
  }[];
  candidateClaims: PolicyClaim[];
  basePeers: {
    clientId: number;
    interfaceId: string;
    peerId: string;
    prefixes: string[];
  }[];
  counts: PolicyCounts;
};

/** Effective filter inputs only; no credentials or executable rule arrays. */
export type PolicyClientFirewall = {
  enableIpv6: boolean;
  interfaces: { interfaceId: string; ipv6: boolean }[];
  entries: {
    interfaceId: string;
    clientId: number;
    clientName: string;
    family: 4 | 6;
    source: string;
    destination: string;
    port?: number;
    proto?: 'tcp' | 'udp' | 'both';
  }[];
};

/** Last verified runtime state only; never persist the static candidate proof. */
export type AppliedRoutingPolicyPlan = {
  version: 2;
  clientFirewall: PolicyClientFirewall;
  interfaces: {
    interfaceId: string;
    ipv4Cidr: string;
    enabled: boolean;
    observedUp: boolean;
  }[];
  siteRoutes: { interfaceId: string; prefixes: string[] }[];
  bypassPrefixes: string[];
  programs: {
    sources: PolicySource[];
    branches: {
      prefix: string;
      groupId: number;
      action: 'exit' | 'block' | 'host';
    }[];
  }[];
  groups: {
    id: number;
    routingSlot: number;
    enabled: boolean;
    allExitsDownPolicy: 'block' | 'host';
    natEnabled: boolean;
    selectedExitClientId: number | null;
    exitInterfaceId: string | null;
    serverIpv4Address: string | null;
    effectivePrefixes: string[];
  }[];
  peers: {
    clientId: number;
    interfaceId: string;
    peerId: string;
    prefixes: string[];
  }[];
};

/** Recovery stores no credentials, hooks, configs, or independent revision counter. */
export type RoutingPolicyJournal = {
  revision: number;
  fingerprint: string;
  plan: AppliedRoutingPolicyPlan;
};
export type RoutingPolicyGuardScope = {
  direction: 'input' | 'forward' | 'output';
  inputInterface?: string;
  outputInterface?: string;
  source: string;
  destination: string;
};
export type PendingPolicyTransition = RoutingPolicyJournal & {
  stage:
    'prepared' | 'guarded' | 'peers' | 'classified' | 'verified' | 'restoring';
  guardScopes: RoutingPolicyGuardScope[];
  backupBasenames: string[];
  errorCode: string | null;
};
