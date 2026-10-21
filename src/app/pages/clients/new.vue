<template>
  <main>
    <Panel>
      <PanelHead
        ><PanelHeadTitle>{{ $t('client.new') }}</PanelHeadTitle></PanelHead
      >
      <PanelBody>
        <FormElement @submit.prevent="create">
          <FormGroup>
            <label for="interfaceId">{{ $t('client.interface') }}</label>
            <select
              id="interfaceId"
              v-model="interfaceId"
              class="rounded border bg-white p-2 dark:bg-neutral-800"
            >
              <option
                v-for="item in interfaces"
                :key="item.interfaceId"
                :value="item.interfaceId"
              >
                {{ item.interfaceId }}
              </option>
            </select>
            <p
              v-if="selectedInterface && !selectedInterface.enabled"
              class="col-span-full text-sm"
            >
              {{ $t('client.interfaceDisabledWarning', [interfaceId]) }}
            </p>
            <p
              v-else-if="selectedInterface?.runtimeStatus === 'degraded'"
              class="col-span-full text-sm"
            >
              {{ $t('client.interfaceDegradedWarning') }}
            </p>
          </FormGroup>
          <ClientsConfigurationFields
            v-model="data"
            v-model:override-awg="overrideAwg"
            creating
            :awg-enabled="awgEnabled"
          />
          <ClientsCredentialsFields v-model="credentials" creating />
          <p class="text-sm">{{ $t('client.remoteConfigurationHelp') }}</p>
          <p
            v-if="formError"
            role="alert"
            class="rounded border border-red-400 p-3"
          >
            {{ formError }}
          </p>
          <FormGroup>
            <FormPrimaryActionField
              type="submit"
              :disabled="busy || !interfaceId"
              :label="$t('client.create')"
            />
          </FormGroup>
        </FormElement>
      </PanelBody>
    </Panel>
  </main>
</template>
<script setup lang="ts">
import {
  blankClientConfiguration,
  blankCredentials,
  clientCreatePayload,
  credentialsValid,
} from '~/utils/clientConfigurationEditor';
import { mutationErrorData } from '~/utils/routingEditor';
const { t } = useI18n();
const { data: metadata } = await useFetch('/api/client/creation-metadata');
const interfaces = computed(() => metadata.value ?? []);
const interfaceId = ref(
  interfaces.value.find((item) => item.default)?.interfaceId ??
    interfaces.value[0]?.interfaceId ??
    ''
);
const selectedInterface = computed(() =>
  interfaces.value.find((item) => item.interfaceId === interfaceId.value)
);
const awgEnabled = computed(
  () =>
    selectedInterface.value?.compatibleExportFormats.includes('wireguard') ===
    false
);
const data = ref(blankClientConfiguration());
const credentials = ref(blankCredentials());
const overrideAwg = ref(false);
const busy = ref(false);
const formError = ref('');
async function create() {
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
      body: clientCreatePayload(data.value, credentials.value, {
        interfaceId: interfaceId.value,
        overrideAwg: overrideAwg.value && awgEnabled.value,
      }),
    });
    credentials.value = blankCredentials();
    useToast().showToast({
      type: result.runtime.status === 'applied' ? 'success' : 'error',
      message: t(
        result.runtime.status === 'applied'
          ? 'client.configurationApplied'
          : 'client.configurationPending'
      ),
    });
    await navigateTo(`/clients/${result.clientId}`);
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
