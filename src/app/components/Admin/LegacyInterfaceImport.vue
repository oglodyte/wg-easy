<template>
  <form class="grid max-w-4xl gap-5" @submit.prevent="preview">
    <p>{{ t('admin.legacyImport.intro') }}</p>
    <label class="grid gap-2" for="legacy-file">
      {{ t('admin.legacyImport.file') }}
      <input
        id="legacy-file"
        type="file"
        accept=".json,application/json"
        :disabled="busy"
        @change="selectFile"
      />
    </label>
    <div v-if="file" class="grid gap-4 sm:grid-cols-2">
      <FormTextField
        v-for="field in textFields"
        :id="`import-${field.key}`"
        :key="field.key"
        v-model="settings[field.key]"
        :label="t(field.label)"
      />
      <FormNumberField
        v-for="field in numberFields"
        :id="`import-${field.key}`"
        :key="field.key"
        v-model="settings[field.key]"
        :label="t(field.label)"
      />
      <FormTextField
        id="import-dns"
        v-model="dns"
        :label="t('admin.legacyImport.dns')"
      />
      <FormTextField
        id="import-allowed"
        v-model="allowedIps"
        :label="t('admin.legacyImport.allowedIps')"
      />
      <label class="grid gap-2" for="import-mode"
        >{{ t('admin.legacyImport.mode') }}
        <select
          id="import-mode"
          v-model="settings.mode"
          class="rounded border bg-white p-2 dark:bg-neutral-800"
        >
          <option value="wireguard-compatible">WireGuard</option>
          <option value="amneziawg">AmneziaWG</option>
        </select>
      </label>
      <p class="text-sm">{{ t('admin.legacyImport.modeHelp') }}</p>
      <template v-if="settings.mode === 'amneziawg'">
        <FormTextField
          v-for="field in awgKeys"
          :id="`import-${field}`"
          :key="field"
          v-model="awg[field]"
          :label="field"
        />
      </template>
      <label
        v-for="field in hookKeys"
        :key="field"
        class="grid gap-2"
        :for="`import-${field}`"
      >
        {{ t(`admin.legacyImport.${field}`) }}
        <textarea
          :id="`import-${field}`"
          v-model="settings.hooks[field]"
          rows="3"
          class="rounded border bg-white p-2 font-mono text-sm dark:bg-neutral-800"
        />
      </label>
      <label class="flex items-start gap-2 sm:col-span-2"
        ><input v-model="settings.hooksReviewed" type="checkbox" />{{
          t('admin.legacyImport.hooksReviewed')
        }}</label
      >
    </div>
    <p v-if="error" role="alert" class="text-red-700 dark:text-red-400">
      {{ error }}
    </p>
    <div v-if="result" class="grid gap-3" aria-live="polite">
      <p>
        {{ result.ipv4Cidr }} ·
        {{ t('admin.legacyImport.clientCount', { count: result.count }) }}
        ·
        {{
          t('admin.legacyImport.stateCounts', {
            enabled: result.enabledCount,
            disabled: result.count - result.enabledCount,
            expiring: result.expiringCount,
          })
        }}
      </p>
      <ul
        v-if="result.blockers.length"
        class="list-inside list-disc text-red-700 dark:text-red-400"
      >
        <li v-for="(issue, index) in result.blockers" :key="index">
          {{ issueText(issue) }}
        </li>
      </ul>
      <ul v-if="result.warnings.length" class="list-inside list-disc">
        <li v-for="(issue, index) in result.warnings" :key="index">
          {{ issueText(issue) }}
        </li>
      </ul>
      <div class="max-h-72 overflow-auto">
        <table class="w-full text-left text-sm">
          <thead>
            <tr>
              <th>{{ t('client.name') }}</th>
              <th>IPv4</th>
              <th>{{ t('client.enabled') }}</th>
              <th>{{ t('admin.legacyImport.expiry') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="client in result.clients" :key="client.index">
              <td class="p-2">{{ client.name }}</td>
              <td class="p-2">{{ client.address }}</td>
              <td class="p-2">
                {{ t(client.enabled ? 'general.yes' : 'general.no') }}
              </td>
              <td class="p-2">{{ client.expiresAt ?? '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <p
      class="rounded bg-yellow-50 p-3 text-sm text-yellow-900 dark:bg-yellow-900 dark:text-yellow-100"
    >
      {{ t('admin.legacyImport.cutover') }}
    </p>
    <div class="flex flex-wrap gap-3">
      <BaseSecondaryButton type="submit" :disabled="!file || busy">{{
        t('admin.legacyImport.preview')
      }}</BaseSecondaryButton>
      <BasePrimaryButton
        type="button"
        :disabled="!canCreate || busy"
        @click="create"
        >{{ t('admin.legacyImport.create') }}</BasePrimaryButton
      >
      <NuxtLink to="/admin/interfaces">{{ t('dialog.cancel') }}</NuxtLink>
    </div>
  </form>
</template>
<script setup lang="ts">
const { t } = useI18n();
const file = ref('');
const busy = ref(false);
const error = ref('');
const settings = reactive({
  name: '',
  device: 'eth0',
  listenPort: 51822,
  ipv6Cidr: '',
  endpointHost: '',
  endpointPort: 51820,
  mtu: 1420,
  persistentKeepalive: 25,
  mode: 'wireguard-compatible',
  hooks: { preUp: '', postUp: '', preDown: '', postDown: '' },
  hooksReviewed: false,
});
const dns = ref('');
const allowedIps = ref('0.0.0.0/0');
const awgKeys = [
  'jc',
  'jmin',
  'jmax',
  's1',
  's2',
  'h1',
  'h2',
  'h3',
  'h4',
] as const;
const hookKeys = ['preUp', 'postUp', 'preDown', 'postDown'] as const;
const awg = reactive<Record<(typeof awgKeys)[number], string>>({
  jc: '',
  jmin: '',
  jmax: '',
  s1: '',
  s2: '',
  h1: '',
  h2: '',
  h3: '',
  h4: '',
});
const textFields = [
  { key: 'name', label: 'admin.interfaces.name' },
  { key: 'device', label: 'admin.interface.device' },
  { key: 'ipv6Cidr', label: 'admin.legacyImport.ipv6Cidr' },
  { key: 'endpointHost', label: 'admin.legacyImport.endpointHost' },
] as const;
const numberFields = [
  { key: 'listenPort', label: 'admin.interfaces.listenPort' },
  { key: 'endpointPort', label: 'admin.legacyImport.endpointPort' },
  { key: 'mtu', label: 'admin.legacyImport.mtu' },
  { key: 'persistentKeepalive', label: 'admin.legacyImport.keepalive' },
] as const;
type Issue = { code: string; field?: string; client?: number };
type Preview = {
  ipv4Cidr: string;
  detectedMode: string;
  awg: Record<string, unknown>;
  count: number;
  enabledCount: number;
  expiringCount: number;
  clients: {
    index: number;
    name: string;
    address: string;
    enabled: boolean;
    expiresAt: string | null;
  }[];
  blockers: Issue[];
  warnings: Issue[];
};
const result = ref<Preview>();
const validatedPayload = ref('');
const payload = computed(() => ({
  file: file.value,
  settings: {
    ...settings,
    hooks: { ...settings.hooks },
    dns: dns.value
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean),
    allowedIps: allowedIps.value
      .split(',')
      .map((v) => v.trim())
      .filter(Boolean),
    awg: Object.fromEntries(
      awgKeys
        .filter((k) => awg[k] !== '')
        .map((k) => [k, k.startsWith('h') ? awg[k] : Number(awg[k])])
    ),
  },
}));
const canCreate = computed(
  () =>
    !!result.value &&
    result.value.blockers.length === 0 &&
    validatedPayload.value === JSON.stringify(payload.value)
);
let generation = 0;
watch(
  payload,
  () => {
    generation++;
    validatedPayload.value = '';
  },
  { flush: 'sync' }
);
function issueText(issue: Issue) {
  return `${t(`admin.legacyImport.errors.${issue.code}`)}${issue.field ? ` (${issue.field})` : ''}${issue.client ? ` #${issue.client}` : ''}`;
}
function safeError(value: unknown) {
  const issues = (value as { data?: { data?: { issues?: Issue[] } } })?.data
    ?.data?.issues;
  return issues?.length
    ? issues.map(issueText).join('; ')
    : t('admin.legacyImport.errors.import_failed');
}
async function selectFile(event: Event) {
  const input = event.target as HTMLInputElement;
  const selected = input.files?.[0];
  file.value = '';
  result.value = undefined;
  error.value = '';
  if (!selected) return;
  if (selected.size > 10 * 1024 * 1024) {
    error.value = t('admin.legacyImport.errors.too_large');
    input.value = '';
    return;
  }
  const current = ++generation;
  const content = await selected.text();
  if (current !== generation) return;
  file.value = content;
  await preview(true);
}
async function preview(prefill: unknown = false) {
  busy.value = true;
  error.value = '';
  const current = generation;
  const sent = JSON.stringify(payload.value);
  try {
    const response = await $fetch<Preview>(
      '/api/admin/interfaces/import/preview',
      { method: 'post', body: payload.value }
    );
    if (current !== generation) return;
    if (prefill === true) {
      settings.mode = response.detectedMode;
      for (const k of awgKeys)
        awg[k] = response.awg[k] === undefined ? '' : String(response.awg[k]);
    }
    result.value = response;
    if (prefill !== true) validatedPayload.value = sent;
  } catch (e) {
    if (current === generation) error.value = safeError(e);
  } finally {
    busy.value = false;
  }
}
async function create() {
  if (!canCreate.value || busy.value) return;
  busy.value = true;
  error.value = '';
  try {
    const response = await $fetch<{ interfaceId: string }>(
      '/api/admin/interfaces/import/create',
      { method: 'post', body: payload.value }
    );
    file.value = '';
    validatedPayload.value = '';
    await navigateTo({
      path: `/admin/interfaces/${response.interfaceId}`,
      query: { legacyImport: '1' },
    });
  } catch (e) {
    error.value = safeError(e);
    validatedPayload.value = '';
  } finally {
    busy.value = false;
  }
}
onBeforeUnmount(() => {
  generation++;
  file.value = '';
  validatedPayload.value = '';
});
</script>
