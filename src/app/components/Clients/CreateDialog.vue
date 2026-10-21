<template>
  <BaseDialog
    :open="open"
    :trigger-class="triggerClass"
    content-class="overflow-y-auto"
    @update:open="resetOnOpen"
  >
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
          {{
            $t(
              !selectedInterface.enabled
                ? 'client.interfaceDisabledWarning'
                : 'client.interfaceDegradedWarning',
              [interfaceId]
            )
          }}
        </p>
        <FormDateField
          id="expiresAt"
          v-model="expiresAt"
          :label="$t('client.expireDate')"
        />
        <ClientsCredentialsFields v-model="credentials" creating />
        <NuxtLink
          to="/clients/new"
          class="mt-3 underline"
          @click="open = false"
          >{{ $t('client.fullConfiguration') }}</NuxtLink
        >
        <p
          v-if="formError"
          role="alert"
          class="mt-2 text-red-700 dark:text-red-200"
        >
          {{ formError }}
        </p>
      </div>
    </template>
    <template #actions>
      <DialogClose as-child>
        <BaseSecondaryButton>{{ $t('dialog.cancel') }}</BaseSecondaryButton>
      </DialogClose>
      <BasePrimaryButton :disabled="busy" @click="createClient">
        {{ $t('client.create') }}
      </BasePrimaryButton>
    </template>
  </BaseDialog>
</template>

<script lang="ts" setup>
import {
  blankCredentials,
  credentialPayload,
  credentialsValid,
} from '~/utils/clientConfigurationEditor';
import { mutationErrorData } from '~/utils/routingEditor';
const credentials = ref(blankCredentials());
const open = ref(false);
const busy = ref(false);
const formError = ref('');
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

function resetOnOpen(value: boolean) {
  open.value = value;
  if (!value) {
    credentials.value = blankCredentials();
    return;
  }
  formError.value = '';
  name.value = '';
  expiresAt.value = null;
}

async function createClient() {
  if (busy.value) return;
  formError.value = '';
  if (!credentialsValid(credentials.value)) {
    formError.value = t('client.configurationErrors.invalid_key');
    return;
  }
  busy.value = true;
  try {
    const result = await $fetch('/api/client', {
      method: 'post',
      body: {
        name: name.value,
        expiresAt: expiresAt.value,
        interfaceId: interfaceId.value || undefined,
        ...credentialPayload(credentials.value),
      },
    });
    open.value = false;
    credentials.value = blankCredentials();
    await clientsStore.refresh();
    useToast().showToast({
      type: result.runtime.status === 'applied' ? 'success' : 'error',
      message: t(
        result.runtime.status === 'applied'
          ? 'client.created'
          : 'client.configurationPending'
      ),
    });
  } catch (error) {
    formError.value =
      mutationErrorData(error).message ??
      t('client.configurationErrors.invalid_configuration');
  } finally {
    busy.value = false;
  }
}
onBeforeUnmount(() => {
  credentials.value = blankCredentials();
});
</script>
