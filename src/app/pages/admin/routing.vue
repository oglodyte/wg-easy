<template>
  <main class="flex flex-col gap-5">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <p class="text-sm text-gray-500 dark:text-neutral-300">
          {{ $t('admin.routing.description') }}
        </p>
        <p class="mt-1 text-xs text-gray-500 dark:text-neutral-300">
          {{ $t('admin.routing.revisions', routingRevision) }}
        </p>
      </div>
      <BasePrimaryButton @click="startCreate">
        <IconsPlus class="mr-2 size-4" />{{ $t('admin.routing.add') }}
      </BasePrimaryButton>
    </div>

    <div
      v-if="routingData?.lastError"
      class="rounded border border-red-300 bg-red-50 p-3 text-sm text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-100"
    >
      <strong>{{ $t('admin.routing.reconciliationError') }}</strong>
      {{ routingData.lastError }}
    </div>

    <div class="grid gap-5 xl:grid-cols-[minmax(18rem,1fr)_minmax(0,2fr)]">
      <section class="space-y-3" aria-label="Routing groups">
        <button
          v-for="group in groups"
          :key="group.id"
          class="w-full rounded border p-3 text-left transition"
          :class="
            selectedGroupId === group.id
              ? 'border-red-800 bg-red-50 dark:bg-red-950'
              : 'border-gray-200 hover:border-red-300 dark:border-neutral-600'
          "
          @click="selectGroup(group)"
        >
          <div class="flex items-center justify-between gap-2">
            <span class="font-medium">{{ group.name }}</span>
            <span
              class="rounded px-2 py-0.5 text-xs"
              :class="statusClass(group)"
            >
              {{ statusLabel(group) }}
            </span>
          </div>
          <p class="mt-1 text-xs text-gray-500 dark:text-neutral-300">
            {{
              group.routedIpv4Prefixes.join(', ') ||
              $t('admin.routing.noPrefixes')
            }}
          </p>
          <p class="mt-1 text-xs text-gray-500 dark:text-neutral-300">
            {{
              $t('admin.routing.membersAndExits', [
                group.members.length,
                group.exits.length,
              ])
            }}
          </p>
        </button>
        <p
          v-if="groups.length === 0"
          class="text-sm text-gray-500 dark:text-neutral-300"
        >
          {{ $t('admin.routing.empty') }}
        </p>
      </section>

      <section
        v-if="form"
        class="min-w-0 rounded border border-gray-200 p-4 dark:border-neutral-600"
      >
        <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 class="text-lg font-semibold">
              {{
                selectedGroupId
                  ? $t('admin.routing.edit')
                  : $t('admin.routing.new')
              }}
            </h2>
            <p class="text-xs text-gray-500 dark:text-neutral-300">
              {{ $t('admin.routing.draftHelp') }}
            </p>
          </div>
          <BaseSecondaryButton v-if="selectedGroupId" @click="remove">
            <IconsDelete class="mr-2 size-4" />{{ $t('admin.routing.delete') }}
          </BaseSecondaryButton>
        </div>

        <p
          v-if="formError"
          class="mb-4 rounded border border-red-300 bg-red-50 p-3 text-sm text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-100"
        >
          {{ formError }}
        </p>

        <FormElement @submit.prevent="save">
          <FormGroup>
            <FormTextField
              id="routing-name"
              v-model="form.name"
              :label="$t('general.name')"
            />
            <FormSwitchField
              id="routing-enabled"
              v-model="form.enabled"
              :label="$t('client.enabled')"
              :description="$t('admin.routing.enabledHelp')"
            />
          </FormGroup>

          <FormGroup>
            <FormHeading>{{ $t('admin.routing.traffic') }}</FormHeading>
            <label class="text-sm font-medium">{{
              $t('admin.routing.prefixes')
            }}</label>
            <div class="space-y-2">
              <div
                v-for="(_, index) in form.routedIpv4Prefixes"
                :key="index"
                class="flex gap-2"
              >
                <input
                  v-model="form.routedIpv4Prefixes[index]"
                  class="min-w-0 flex-1 rounded border border-gray-300 bg-white p-2 dark:border-neutral-500 dark:bg-neutral-800"
                  inputmode="text"
                  placeholder="0.0.0.0/0"
                />
                <BaseSecondaryButton type="button" @click="removePrefix(index)"
                  >-</BaseSecondaryButton
                >
              </div>
              <BaseSecondaryButton
                type="button"
                @click="form.routedIpv4Prefixes.push('')"
              >
                {{ $t('form.add') }}
              </BaseSecondaryButton>
            </div>
            <FormSwitchField
              id="routing-nat"
              v-model="form.natEnabled"
              :label="$t('admin.routing.nat')"
              :description="$t('admin.routing.natHelp')"
            />
            <fieldset>
              <legend class="text-sm font-medium">
                {{ $t('admin.routing.allExitsDown') }}
              </legend>
              <label class="mt-2 flex gap-2 text-sm">
                <input
                  v-model="form.allExitsDownPolicy"
                  value="block"
                  type="radio"
                />
                <span>{{ $t('admin.routing.block') }}</span>
              </label>
              <label class="mt-2 flex gap-2 text-sm">
                <input
                  v-model="form.allExitsDownPolicy"
                  value="host"
                  type="radio"
                />
                <span>{{ $t('admin.routing.host') }}</span>
              </label>
            </fieldset>
          </FormGroup>

          <FormGroup>
            <FormHeading>{{ $t('admin.routing.members') }}</FormHeading>
            <p class="text-sm text-gray-500 dark:text-neutral-300">
              {{ $t('admin.routing.membersHelp') }}
            </p>
            <div
              v-for="interfaceGroup in clientsByInterface"
              :key="interfaceGroup.id"
              class="rounded border p-3 dark:border-neutral-600"
            >
              <h3 class="text-sm font-medium">{{ interfaceGroup.id }}</h3>
              <label
                v-for="client in interfaceGroup.clients"
                :key="client.id"
                class="mt-2 flex items-center gap-2 text-sm"
              >
                <input
                  :checked="form.memberClientIds.includes(client.id)"
                  :disabled="isExitCandidate(client.id)"
                  type="checkbox"
                  @change="toggleMember(client.id)"
                />
                <span>{{ clientLabel(client) }}</span>
                <span class="text-xs text-gray-500 dark:text-neutral-300">{{
                  client.ipv4Address
                }}</span>
                <span
                  v-if="!client.enabled"
                  class="text-xs text-yellow-700 dark:text-yellow-300"
                  >{{ $t('admin.routing.disabledClient') }}</span
                >
              </label>
            </div>
          </FormGroup>

          <FormGroup>
            <FormHeading>{{ $t('admin.routing.exits') }}</FormHeading>
            <p class="text-sm text-gray-500 dark:text-neutral-300">
              {{ $t('admin.routing.exitsHelp') }}
            </p>
            <div
              v-for="interfaceGroup in clientsByInterface"
              :key="interfaceGroup.id"
              class="rounded border p-3 dark:border-neutral-600"
            >
              <h3 class="text-sm font-medium">{{ interfaceGroup.id }}</h3>
              <div
                v-for="client in interfaceGroup.clients"
                :key="client.id"
                class="mt-3 rounded bg-gray-50 p-2 dark:bg-neutral-800"
              >
                <label class="flex items-center gap-2 text-sm">
                  <input
                    :checked="isExitCandidate(client.id)"
                    :disabled="form.memberClientIds.includes(client.id)"
                    type="checkbox"
                    @change="toggleExit(client.id)"
                  />
                  <span>{{ clientLabel(client) }}</span>
                  <span class="text-xs text-gray-500 dark:text-neutral-300">{{
                    client.ipv4Address
                  }}</span>
                </label>
                <div
                  v-if="candidate(client.id)"
                  class="mt-2 grid gap-2 sm:grid-cols-2"
                >
                  <label class="text-xs">
                    {{ $t('admin.routing.priority') }}
                    <input
                      v-model.number="candidate(client.id)!.priority"
                      class="ml-2 w-16 rounded border bg-white p-1 dark:bg-neutral-700"
                      min="0"
                      type="number"
                    />
                  </label>
                  <label class="flex items-center gap-2 text-xs">
                    <input
                      v-model="candidate(client.id)!.enabled"
                      type="checkbox"
                    />
                    {{ $t('admin.routing.candidateEnabled') }}
                  </label>
                </div>
              </div>
            </div>
          </FormGroup>

          <FormGroup>
            <FormHeading>{{ $t('admin.routing.readiness') }}</FormHeading>
            <p
              class="rounded border border-blue-300 bg-blue-50 p-3 text-sm text-blue-900 dark:border-blue-900 dark:bg-blue-950 dark:text-blue-100"
            >
              {{ $t('admin.routing.gatewayUnverified') }}
            </p>
            <div
              v-for="exit in sortedExits"
              :key="exit.clientId"
              class="rounded border p-3 dark:border-neutral-600"
            >
              <div class="flex flex-wrap items-center justify-between gap-2">
                <strong>{{ clientName(exit.clientId) }}</strong>
                <span class="text-xs"
                  >{{ $t('admin.routing.priority') }} {{ exit.priority }}</span
                >
              </div>
              <ul class="mt-2 list-inside list-disc text-sm">
                <li>{{ readinessConfiguration(exit.clientId) }}</li>
                <li>{{ readinessObserved(exit.clientId) }}</li>
                <li v-if="isSelected(exit.clientId)">
                  {{ $t('admin.routing.selectedExit') }}
                </li>
                <li v-if="isApplied(exit.clientId)">
                  {{ $t('admin.routing.appliedExit') }}
                </li>
              </ul>
              <p
                v-if="exitLoopRisk(exit.clientId)"
                class="mt-2 text-sm text-yellow-700 dark:text-yellow-300"
              >
                {{ $t('admin.routing.loopRisk') }}
              </p>
            </div>
            <p
              v-if="sortedExits.length === 0"
              class="text-sm text-gray-500 dark:text-neutral-300"
            >
              {{ $t('admin.routing.noExits') }}
            </p>
            <p class="text-sm text-yellow-800 dark:text-yellow-200">
              {{ $t('admin.routing.keepaliveReapply', { max: maxKeepalive }) }}
            </p>
            <p class="text-sm text-gray-500 dark:text-neutral-300">
              {{
                form.natEnabled
                  ? $t('admin.routing.natReturnPath')
                  : $t('admin.routing.noNatReturnPath')
              }}
            </p>
            <p
              v-if="memberFirewallWarning"
              class="text-sm text-yellow-800 dark:text-yellow-200"
            >
              {{ $t('admin.routing.firewallWarning') }}
            </p>
          </FormGroup>

          <FormGroup v-if="routingSettings">
            <FormHeading>{{ $t('admin.routing.advancedHealth') }}</FormHeading>
            <FormNumberField
              id="routing-health-interval"
              v-model="routingSettings.healthCheckIntervalSeconds"
              :label="$t('admin.routing.healthCheckInterval')"
            />
            <FormNumberField
              id="routing-health-timeout"
              v-model="routingSettings.healthTimeoutSeconds"
              :label="$t('admin.routing.healthTimeout')"
            />
            <FormNumberField
              id="routing-min-hold"
              v-model="routingSettings.minHoldSeconds"
              :label="$t('admin.routing.minimumHold')"
            />
            <FormNumberField
              id="routing-failback-delay"
              v-model="routingSettings.failbackDelaySeconds"
              :label="$t('admin.routing.failbackDelay')"
            />
            <BaseSecondaryButton type="button" @click="saveSettings">
              {{ $t('admin.routing.saveHealthSettings') }}
            </BaseSecondaryButton>
          </FormGroup>

          <FormGroup>
            <FormHeading>{{ $t('form.actions') }}</FormHeading>
            <FormPrimaryActionField type="submit" :label="$t('form.save')" />
            <FormSecondaryActionField
              :label="$t('form.revert')"
              @click="revert"
            />
          </FormGroup>
        </FormElement>
      </section>
      <section
        v-else
        class="rounded border border-dashed p-6 text-sm text-gray-500 dark:border-neutral-600 dark:text-neutral-300"
      >
        {{ $t('admin.routing.selectOrCreate') }}
      </section>
    </div>
  </main>
</template>

<script setup lang="ts">
type Client = {
  id: number;
  name: string;
  interfaceId: string;
  ipv4Address: string;
  enabled: boolean;
  persistentKeepalive: number;
  latestHandshakeAt: string | null;
  allowedIps: string[] | null;
};
type ClientSummary = Pick<
  Client,
  'id' | 'name' | 'interfaceId' | 'enabled' | 'persistentKeepalive'
>;
type Exit = { clientId: number; priority: number; enabled: boolean };
type Group = {
  id: number;
  name: string;
  enabled: boolean;
  natEnabled: boolean;
  allExitsDownPolicy: 'block' | 'host';
  routedIpv4Prefixes: string[];
  exits: Array<Exit & { client: ClientSummary }>;
  members: Array<{ clientId: number; client: ClientSummary }>;
  validationWarnings: string[];
  runtime: null | {
    status: string;
    reason: string | null;
    selectedExitClientId: number | null;
    appliedExitClientId: number | null;
    evaluatedRevision: number;
    appliedRevision: number | null;
  };
};
type RoutingData = {
  desiredRevision: number;
  appliedRevision: number;
  lastError?: string | null;
  groups: Group[];
};
type Form = Omit<
  Group,
  'id' | 'exits' | 'members' | 'runtime' | 'validationWarnings'
> & {
  exits: Exit[];
  memberClientIds: number[];
};
type RoutingSettings = {
  healthCheckIntervalSeconds: number;
  healthTimeoutSeconds: number;
  minHoldSeconds: number;
  failbackDelaySeconds: number;
};
type ApiRoutingSettings = {
  routingExitHealthCheckIntervalSeconds: number;
  routingExitHealthTimeoutSeconds: number;
  routingExitMinHoldSeconds: number;
  routingExitFailbackDelaySeconds: number;
};

const { t } = useI18n();
const toast = useToast();
const globalStore = useGlobalStore();
const { data: routingResponse, refresh: refreshRouting } = await useFetch(
  '/api/admin/routing-groups'
);
const { data: clientResponse, refresh: refreshClients } =
  await useFetch('/api/client');
const { data: settingsResponse, refresh: refreshSettings } = await useFetch(
  '/api/admin/routing-settings'
);
const routingData = computed(
  () => routingResponse.value as unknown as RoutingData | null
);
const groups = computed(() => routingData.value?.groups ?? []);
const clients = computed(() => (clientResponse.value ?? []) as Client[]);
const routingSettings = ref<RoutingSettings | null>(
  settingsResponse.value
    ? fromApiRoutingSettings(settingsResponse.value as ApiRoutingSettings)
    : null
);
const selectedGroupId = ref<number | null>(null);
const form = ref<Form | null>(null);
const formError = ref('');

const maxKeepalive = computed(() =>
  Math.floor((routingSettings.value?.healthTimeoutSeconds ?? 180) / 3)
);
const routingRevision = computed(() => {
  if (!routingData.value) return t('general.loading');
  return `${routingData.value.appliedRevision} / ${routingData.value.desiredRevision}`;
});
const clientsByInterface = computed(() => {
  const grouped = new Map<string, Client[]>();
  for (const wgInterface of globalStore.information?.interfaces ?? []) {
    grouped.set(wgInterface.name, []);
  }
  for (const client of clients.value) {
    const values = grouped.get(client.interfaceId) ?? [];
    values.push(client);
    grouped.set(client.interfaceId, values);
  }
  return [...grouped.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([id, values]) => ({
      id,
      clients: values.sort((a, b) => a.name.localeCompare(b.name)),
    }));
});
const sortedExits = computed(() =>
  [...(form.value?.exits ?? [])].sort(
    (left, right) => left.priority - right.priority
  )
);
const memberFirewallWarning = computed(() => {
  const interfaces = globalStore.information?.interfaces ?? [];
  return (form.value?.memberClientIds ?? []).some((clientId) => {
    const client = clients.value.find((item) => item.id === clientId);
    return interfaces.find((item) => item.name === client?.interfaceId)
      ?.firewallEnabled;
  });
});

function blankForm(): Form {
  return {
    name: '',
    enabled: false,
    natEnabled: true,
    allExitsDownPolicy: 'block',
    routedIpv4Prefixes: ['0.0.0.0/0'],
    exits: [],
    memberClientIds: [],
  };
}

function fromApiRoutingSettings(settings: ApiRoutingSettings): RoutingSettings {
  return {
    healthCheckIntervalSeconds: settings.routingExitHealthCheckIntervalSeconds,
    healthTimeoutSeconds: settings.routingExitHealthTimeoutSeconds,
    minHoldSeconds: settings.routingExitMinHoldSeconds,
    failbackDelaySeconds: settings.routingExitFailbackDelaySeconds,
  };
}

function selectGroup(group: Group) {
  selectedGroupId.value = group.id;
  formError.value = '';
  form.value = {
    name: group.name,
    enabled: group.enabled,
    natEnabled: group.natEnabled,
    allExitsDownPolicy: group.allExitsDownPolicy,
    routedIpv4Prefixes: [...group.routedIpv4Prefixes],
    exits: group.exits.map(({ clientId, priority, enabled }) => ({
      clientId,
      priority,
      enabled,
    })),
    memberClientIds: group.members.map(({ clientId }) => clientId),
  };
}

function startCreate() {
  selectedGroupId.value = null;
  formError.value = '';
  form.value = blankForm();
}

function candidate(clientId: number) {
  return form.value?.exits.find((exit) => exit.clientId === clientId);
}

function isExitCandidate(clientId: number) {
  return Boolean(candidate(clientId));
}

function toggleMember(clientId: number) {
  if (!form.value) return;
  const index = form.value.memberClientIds.indexOf(clientId);
  if (index === -1) form.value.memberClientIds.push(clientId);
  else form.value.memberClientIds.splice(index, 1);
}

function toggleExit(clientId: number) {
  if (!form.value) return;
  const index = form.value.exits.findIndex(
    (exit) => exit.clientId === clientId
  );
  if (index !== -1) {
    form.value.exits.splice(index, 1);
    return;
  }
  const priority =
    Math.max(-1, ...form.value.exits.map((exit) => exit.priority)) + 1;
  form.value.exits.push({ clientId, priority, enabled: true });
}

function removePrefix(index: number) {
  form.value?.routedIpv4Prefixes.splice(index, 1);
}

function clientFor(clientId: number) {
  return clients.value.find((client) => client.id === clientId);
}

function clientName(clientId: number) {
  const client = clientFor(clientId);
  return client
    ? `${clientLabel(client)} (${client.interfaceId})`
    : `#${clientId}`;
}

function clientLabel(client: Pick<Client, 'id' | 'name'>) {
  return t('admin.routing.clientLabel', { id: client.id, name: client.name });
}

function interfaceRuntime(clientId: number) {
  const interfaceId = clientFor(clientId)?.interfaceId;
  return globalStore.information?.interfaces?.find(
    (item) => item.name === interfaceId
  )?.runtime;
}

function readinessConfiguration(clientId: number) {
  const client = clientFor(clientId);
  const runtime = interfaceRuntime(clientId);
  if (!client?.enabled) return t('admin.routing.readinessClientDisabled');
  if (runtime?.status !== 'up' || !runtime.observedUp)
    return t('admin.routing.readinessInterfaceDown');
  if (
    client.persistentKeepalive <= 0 ||
    client.persistentKeepalive > maxKeepalive.value
  ) {
    return t('admin.routing.readinessKeepalive', { max: maxKeepalive.value });
  }
  return t('admin.routing.readinessConfigured');
}

function readinessObserved(clientId: number) {
  const handshake = clientFor(clientId)?.latestHandshakeAt;
  if (!handshake) return t('admin.routing.readinessNeverHandshaken');
  const fresh = Date.now() - new Date(handshake).getTime() <= 180_000;
  return fresh
    ? t('admin.routing.readinessHandshakeFresh', {
        time: formatDate(handshake),
      })
    : t('admin.routing.readinessHandshakeStale', {
        time: formatDate(handshake),
      });
}

function formatDate(value: string) {
  return new Date(value).toLocaleString();
}

function currentGroup() {
  return groups.value.find((group) => group.id === selectedGroupId.value);
}

function isSelected(clientId: number) {
  return currentGroup()?.runtime?.selectedExitClientId === clientId;
}

function isApplied(clientId: number) {
  return currentGroup()?.runtime?.appliedExitClientId === clientId;
}

function exitLoopRisk(clientId: number) {
  return clientFor(clientId)?.allowedIps?.includes('0.0.0.0/0') ?? false;
}

function statusLabel(group: Group) {
  return group.runtime?.status ?? (group.enabled ? 'pending' : 'disabled');
}

function statusClass(group: Group) {
  switch (statusLabel(group)) {
    case 'active':
      return 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200';
    case 'degraded':
    case 'blocked':
      return 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200';
    default:
      return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200';
  }
}

async function save() {
  if (!form.value) return;
  formError.value = '';
  const body = {
    ...form.value,
    routedIpv4Prefixes: form.value.routedIpv4Prefixes
      .map((value) => value.trim())
      .filter(Boolean),
    exits: form.value.exits.map((exit) => ({
      ...exit,
      priority: Number(exit.priority),
    })),
  };
  try {
    const response = await $fetch<{ group: Group }>(
      selectedGroupId.value
        ? `/api/admin/routing-groups/${selectedGroupId.value}`
        : '/api/admin/routing-groups',
      { method: 'post', body }
    );
    await Promise.all([
      refreshRouting(),
      refreshClients(),
      globalStore.refreshInformation(),
    ]);
    const updated = groups.value.find(
      (group) => group.id === response.group.id
    );
    if (updated) selectGroup(updated);
    toast.showToast({ type: 'success', message: t('toast.saved') });
  } catch (error) {
    formError.value =
      error instanceof Error ? error.message : t('toast.unknown');
  }
}

async function saveSettings() {
  if (!routingSettings.value) return;
  try {
    await $fetch('/api/admin/routing-settings', {
      method: 'post',
      body: routingSettings.value,
    });
    await Promise.all([
      refreshRouting(),
      refreshSettings(),
      globalStore.refreshInformation(),
    ]);
    routingSettings.value = settingsResponse.value
      ? fromApiRoutingSettings(settingsResponse.value as ApiRoutingSettings)
      : null;
    toast.showToast({ type: 'success', message: t('toast.saved') });
  } catch (error) {
    formError.value =
      error instanceof Error ? error.message : t('toast.unknown');
  }
}

function revert() {
  const group = currentGroup();
  if (group) selectGroup(group);
  else startCreate();
}

async function remove() {
  if (
    !selectedGroupId.value ||
    !window.confirm(t('admin.routing.deleteConfirm'))
  )
    return;
  try {
    await $fetch(`/api/admin/routing-groups/${selectedGroupId.value}`, {
      method: 'delete',
    });
    await Promise.all([refreshRouting(), globalStore.refreshInformation()]);
    selectedGroupId.value = null;
    form.value = null;
    toast.showToast({ type: 'success', message: t('admin.routing.deleted') });
  } catch (error) {
    formError.value =
      error instanceof Error ? error.message : t('toast.unknown');
  }
}
</script>
