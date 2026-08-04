<template>
  <main>
    <div class="mb-5 flex flex-wrap items-center justify-between gap-3">
      <p class="text-sm text-gray-500 dark:text-neutral-300">
        {{ $t('admin.interfaces.description') }}
      </p>
      <BaseDialog>
        <template #trigger>
          <BasePrimaryButton
            ><IconsPlus class="mr-2 size-4" />{{
              $t('admin.interfaces.add')
            }}</BasePrimaryButton
          >
        </template>
        <template #title>{{ $t('admin.interfaces.add') }}</template>
        <template #description>
          <div class="grid gap-3">
            <FormTextField
              id="name"
              v-model="newInterface.name"
              :label="$t('admin.interfaces.name')"
            />
            <FormTextField
              id="device"
              v-model="newInterface.device"
              :label="$t('admin.interface.device')"
            />
            <FormNumberField
              id="port"
              v-model="newInterface.port"
              :label="$t('admin.interfaces.listenPort')"
            />
            <FormTextField
              id="ipv4Cidr"
              v-model="newInterface.ipv4Cidr"
              label="IPv4 CIDR"
            />
            <FormTextField
              id="ipv6Cidr"
              v-model="newInterface.ipv6Cidr"
              label="IPv6 CIDR"
            />
            <label class="text-sm font-medium" for="cloneFrom">{{
              $t('admin.interfaces.cloneFrom')
            }}</label>
            <select
              id="cloneFrom"
              v-model="newInterface.cloneFromInterfaceId"
              class="rounded border border-gray-300 bg-white p-2 dark:border-neutral-500 dark:bg-neutral-800"
            >
              <option
                v-for="item in interfaces"
                :key="item.name"
                :value="item.name"
              >
                {{ item.name }}
              </option>
            </select>
            <p class="text-xs text-gray-500 dark:text-neutral-300">
              {{ $t('admin.interfaces.cloneHelp') }}
            </p>
          </div>
        </template>
        <template #actions>
          <DialogClose as-child
            ><BaseSecondaryButton>{{
              $t('dialog.cancel')
            }}</BaseSecondaryButton></DialogClose
          >
          <BasePrimaryButton @click="create">{{
            $t('dialog.create')
          }}</BasePrimaryButton>
        </template>
      </BaseDialog>
    </div>
    <div class="overflow-x-auto">
      <table class="w-full text-left text-sm">
        <thead class="border-b dark:border-neutral-600">
          <tr>
            <th class="p-2">{{ $t('admin.interfaces.name') }}</th>
            <th class="p-2">{{ $t('client.enabled') }}</th>
            <th class="p-2">{{ $t('admin.interfaces.listenPort') }}</th>
            <th class="p-2">IPv4 CIDR</th>
            <th class="p-2">{{ $t('admin.interfaces.runtime') }}</th>
            <th class="p-2"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in interfaces"
            :key="item.name"
            class="border-b dark:border-neutral-600"
          >
            <td class="p-2 font-medium">
              {{ item.name }}
              <span
                v-if="item.isDefault"
                class="ml-1 rounded bg-red-800 px-1.5 py-0.5 text-xs text-white"
                >{{ $t('admin.interfaces.default') }}</span
              >
            </td>
            <td class="p-2">
              {{ item.enabled ? $t('general.yes') : $t('general.no') }}
            </td>
            <td class="p-2">{{ item.port }}</td>
            <td class="p-2">{{ item.ipv4Cidr }}</td>
            <td class="p-2">
              <span :class="runtimeClass(item.runtime?.status)">{{
                item.runtime?.status ?? $t('admin.interfaces.unknown')
              }}</span>
            </td>
            <td class="p-2 text-right">
              <NuxtLink :to="`/admin/interfaces/${item.name}`"
                ><BaseSecondaryButton as="span">{{
                  $t('admin.interfaces.manage')
                }}</BaseSecondaryButton></NuxtLink
              >
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </main>
</template>

<script setup lang="ts">
type ManagedInterface = {
  name: string;
  port: number;
  ipv4Cidr: string;
  enabled: boolean;
  isDefault: boolean;
  runtime?: { status?: string };
};
const { data, refresh } = await useFetch('/api/admin/interfaces');
const interfaces = computed(() => (data.value ?? []) as ManagedInterface[]);
const globalStore = useGlobalStore();
const { t } = useI18n();
const initial = () => ({
  name: '',
  device: 'eth0',
  port: 51821,
  ipv4Cidr: '10.252.0.0/24',
  ipv6Cidr: 'fd42:252::/64',
  cloneFromInterfaceId:
    interfaces.value.find((item) => item.isDefault)?.name ?? 'wg0',
});
const newInterface = ref(initial());
const create = useSubmit(
  async () => {
    const result = await $fetch<{ interface: { name: string } }>(
      '/api/admin/interfaces',
      { method: 'post', body: newInterface.value }
    );
    await globalStore.refreshInformation();
    await navigateTo({
      path: `/admin/interfaces/${result.interface.name}`,
      query: { reviewHooks: '1' },
    });
  },
  { revert: async () => refresh(), successMsg: t('admin.interfaces.created') }
);
function runtimeClass(status?: string) {
  return status === 'up'
    ? 'text-green-700 dark:text-green-400'
    : status === 'degraded'
      ? 'text-red-700 dark:text-red-400'
      : 'text-yellow-700 dark:text-yellow-300';
}
</script>
