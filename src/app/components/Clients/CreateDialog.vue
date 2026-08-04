<template>
  <BaseDialog :trigger-class="triggerClass">
    <template #trigger>
      <slot />
    </template>
    <template #title>
      {{ $t('client.new') }}
    </template>
    <template #description>
      <div class="flex flex-col">
        <FormTextField id="name" v-model="name" :label="$t('client.name')" />
        <label class="text-sm font-medium" for="interfaceId">{{
          $t('client.interface')
        }}</label>
        <select
          id="interfaceId"
          v-model="interfaceId"
          class="rounded border border-gray-300 bg-white p-2 dark:border-neutral-500 dark:bg-neutral-800"
        >
          <option
            v-for="item in interfaces"
            :key="item.interfaceId"
            :value="item.interfaceId"
          >
            {{ item.interfaceId
            }}{{ item.default ? ` — ${$t('admin.interfaces.default')}` : '' }}
          </option>
        </select>
        <p
          v-if="selectedInterface?.warning"
          class="rounded border border-yellow-400 bg-yellow-50 p-2 text-sm text-yellow-900 dark:bg-yellow-950 dark:text-yellow-100"
        >
          {{ selectedInterface.warning }}
        </p>
        <FormDateField
          id="expiresAt"
          v-model="expiresAt"
          :label="$t('client.expireDate')"
        />
      </div>
    </template>
    <template #actions>
      <DialogClose as-child>
        <BaseSecondaryButton>{{ $t('dialog.cancel') }}</BaseSecondaryButton>
      </DialogClose>
      <DialogClose as-child>
        <BasePrimaryButton @click="createClient">
          {{ $t('client.create') }}
        </BasePrimaryButton>
      </DialogClose>
    </template>
  </BaseDialog>
</template>

<script lang="ts" setup>
const name = ref<string>('');
const expiresAt = ref<string | null>(null);
const clientsStore = useClientsStore();
const { data: metadata } = await useFetch('/api/client/creation-metadata');
const interfaces = computed(() => metadata.value ?? []);
const interfaceId = ref<string>('');
const selectedInterface = computed(() =>
  interfaces.value.find((item) => item.interfaceId === interfaceId.value)
);
watch(
  interfaces,
  (items) => {
    if (!interfaceId.value) {
      interfaceId.value =
        items.find((item) => item.default)?.interfaceId ??
        items[0]?.interfaceId ??
        '';
    }
  },
  { immediate: true }
);

const { t } = useI18n();

defineProps<{ triggerClass?: string }>();

function createClient() {
  return _createClient({
    name: name.value,
    expiresAt: expiresAt.value,
    interfaceId: interfaceId.value || undefined,
  });
}

const _createClient = useSubmit(
  (data) =>
    $fetch('/api/client', {
      method: 'post',
      body: data,
    }),
  {
    revert: () => clientsStore.refresh(),
    successMsg: t('client.created'),
  }
);
</script>
