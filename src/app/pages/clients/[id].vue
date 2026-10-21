<template>
  <main v-if="data">
    <Panel>
      <PanelHead>
        <PanelHeadTitle>
          {{ data.name }}
        </PanelHeadTitle>
      </PanelHead>
      <PanelBody>
        <FormElement @submit.prevent="submit">
          <FormGroup>
            <FormHeading>{{ $t('client.interface') }}</FormHeading>
            <FormInfoField
              id="interface"
              :label="$t('client.interface')"
              :data="data.interface.name"
            />
            <FormInfoField
              id="interfaceEndpoint"
              :label="$t('admin.interfaces.endpoint')"
              :data="`${data.interface.endpointHost}:${data.interface.endpointPort}`"
            />
            <FormInfoField
              id="observedEndpoint"
              :label="$t('client.endpoint')"
              :description="$t('client.endpointDesc')"
              :data="data.endpoint ?? $t('client.notConnected')"
            />
            <FormInfoField
              id="interfaceFormat"
              :label="$t('admin.interfaces.defaultFormat')"
              :data="data.interface.defaultConfigFormat"
            />
          </FormGroup>
          <ClientsConfigurationFields
            v-model="data"
            :awg-enabled="data.interface.awgParametersEnabled"
          />
          <ClientsCredentialsFields
            v-model="credentials"
            :public-key="data.publicKey"
            :has-pre-shared-key="data.hasPreSharedKey"
          />
          <p class="text-sm">{{ $t('client.remoteConfigurationHelp') }}</p>
          <p
            v-if="formError"
            role="alert"
            class="rounded border border-red-400 p-3 text-sm"
          >
            {{ formError }}
          </p>
          <p
            v-if="runtimeMessage"
            role="status"
            class="rounded border p-3 text-sm"
          >
            {{ runtimeMessage }}
          </p>
          <FormGroup>
            <FormHeading>{{ $t('form.actions') }}</FormHeading>
            <label class="col-span-full text-sm font-medium" for="configFormat">
              {{ $t('client.configFormat') }}
            </label>
            <select
              id="configFormat"
              v-model="configFormat"
              class="col-span-full rounded border border-gray-300 bg-white p-2 dark:border-neutral-500 dark:bg-neutral-800"
            >
              <option value="auto">{{ $t('client.autoFormat') }}</option>
              <option
                value="wireguard"
                :disabled="data.interface.awgParametersEnabled"
              >
                WireGuard
              </option>
              <option value="amneziawg">AmneziaWG</option>
            </select>
            <FormPrimaryActionField
              type="submit"
              :disabled="busy"
              :label="$t('form.save')"
            />
            <FormSecondaryActionField
              :label="$t('form.revert')"
              @click="revert"
            />
            <ClientsDeleteDialog
              trigger-class="col-span-2"
              :client-name="data.name"
              @delete="deleteClient"
            >
              <FormSecondaryActionField
                :label="$t('client.delete')"
                class="inline-block w-full"
                as="span"
              />
            </ClientsDeleteDialog>
            <ClientsConfigDialog
              trigger-class="col-span-2"
              :client-id="data.id"
              :format="configFormat"
            >
              <FormSecondaryActionField
                :label="$t('client.viewConfig')"
                class="inline-block w-full"
                as="span"
              />
            </ClientsConfigDialog>
          </FormGroup>
        </FormElement>
      </PanelBody>
    </Panel>
  </main>
</template>

<script lang="ts" setup>
import type { TypedInternalResponse } from 'nitropack/types';

import {
  blankCredentials,
  clientEditPayload,
  credentialsValid,
} from '~/utils/clientConfigurationEditor';
import { mutationErrorData } from '~/utils/routingEditor';
type ClientDetail = TypedInternalResponse<
  '/api/client/:clientId',
  unknown,
  'get'
>;
const { t } = useI18n();
const route = useRoute();
const id = route.params.id as string;
const { data: saved, refresh } = await useFetch<ClientDetail>(
  `/api/client/${id}` as never,
  { method: 'get' }
);
const data = ref(saved.value ? structuredClone(toRaw(saved.value)) : null);
const credentials = ref(blankCredentials());
const busy = ref(false);
const formError = ref('');
const runtimeMessage = ref('');
const configFormat = ref<'auto' | 'wireguard' | 'amneziawg'>('auto');
async function submit() {
  if (!data.value || busy.value) return;
  formError.value = '';
  runtimeMessage.value = '';
  if (!credentialsValid(credentials.value)) {
    formError.value = t('client.configurationErrors.invalid_key');
    return;
  }
  busy.value = true;
  try {
    const response = await $fetch<{
      runtime: { status: string; appliedRevision?: number };
    }>(`/api/client/${id}` as never, {
      method: 'post',
      body: clientEditPayload(data.value, credentials.value),
    });
    credentials.value = blankCredentials();
    await refresh();
    data.value = saved.value ? structuredClone(toRaw(saved.value)) : null;
    runtimeMessage.value = t(
      response.runtime.status === 'applied'
        ? 'client.configurationApplied'
        : 'client.configurationPending'
    );
    useToast().showToast({
      type: response.runtime.status === 'applied' ? 'success' : 'error',
      message: runtimeMessage.value,
    });
  } catch (error) {
    formError.value =
      mutationErrorData(error).message ??
      t('client.configurationErrors.invalid_configuration');
  } finally {
    busy.value = false;
  }
}
async function revert() {
  await refresh();
  data.value = saved.value ? structuredClone(toRaw(saved.value)) : null;
  credentials.value = blankCredentials();
  formError.value = '';
  runtimeMessage.value = '';
}
const _deleteClient = useSubmit(
  () => $fetch<unknown>(`/api/client/${id}` as never, { method: 'delete' }),
  {
    revert: async (success) => {
      if (success) await navigateTo('/');
    },
  }
);
function deleteClient() {
  return _deleteClient(undefined);
}
onBeforeUnmount(() => {
  credentials.value = blankCredentials();
});
</script>
