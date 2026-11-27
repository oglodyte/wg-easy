<template>
  <main v-if="interfaceData && defaults && hooks">
    <p
      v-if="route.query.legacyImport"
      class="mb-4 rounded bg-yellow-50 p-3 text-yellow-900 dark:bg-yellow-900 dark:text-yellow-100"
    >
      {{ $t('admin.legacyImport.saved') }}
      {{ $t('admin.legacyImport.cutover') }}
    </p>
    <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 class="text-lg font-semibold">{{ interfaceData.name }}</h2>
        <p class="text-sm text-gray-500 dark:text-neutral-300">
          {{ runtimeSummary }}
        </p>
      </div>
      <div class="flex gap-2">
        <BaseSecondaryButton
          v-if="!interfaceData.isDefault"
          @click="setDefault"
          >{{ $t('admin.interfaces.makeDefault') }}</BaseSecondaryButton
        ><BaseSecondaryButton @click="restart">{{
          $t('admin.interface.restart')
        }}</BaseSecondaryButton>
      </div>
    </div>
    <div
      v-if="interfaceData.runtime?.lastError"
      class="mb-4 rounded border border-red-300 bg-red-50 p-3 text-sm text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-100"
    >
      {{ interfaceData.runtime.lastError }}
    </div>
    <div
      v-if="needsHookReview && !hooksReviewed"
      class="mb-4 rounded border border-yellow-400 bg-yellow-50 p-3 text-sm text-yellow-900 dark:bg-yellow-950 dark:text-yellow-100"
    >
      <p>{{ $t('admin.interfaces.hookReviewRequired') }}</p>
      <label class="mt-2 flex gap-2"
        ><input v-model="hooksReviewed" type="checkbox" />{{
          $t('admin.interfaces.hookReviewAcknowledgement')
        }}</label
      >
    </div>
    <nav class="mb-5 flex flex-wrap gap-2" aria-label="Interface settings">
      <button
        v-for="item in tabs"
        :key="item.id"
        class="rounded px-3 py-2 text-sm"
        :class="
          tab === item.id
            ? 'bg-red-800 text-white'
            : 'bg-gray-100 dark:bg-neutral-600'
        "
        @click="tab = item.id"
      >
        {{ item.label }}
      </button>
    </nav>
    <FormElement
      v-if="
        tab === 'overview' ||
        tab === 'connection' ||
        tab === 'awg' ||
        tab === 'firewall'
      "
      @submit.prevent="saveInterface"
    >
      <FormGroup v-if="tab === 'overview'"
        ><FormHeading>{{ $t('form.sectionGeneral') }}</FormHeading
        ><FormSwitchField
          id="enabled"
          v-model="interfaceData.enabled"
          :label="$t('client.enabled')"
          :description="$t('admin.interfaces.enabledDesc')" /><label
          class="text-sm font-medium"
          for="defaultConfigFormat"
          >{{ $t('admin.interfaces.defaultFormat') }}</label
        ><select
          id="defaultConfigFormat"
          v-model="interfaceData.defaultConfigFormat"
          class="rounded border border-gray-300 bg-white p-2 dark:border-neutral-500 dark:bg-neutral-800"
        >
          <option
            value="wireguard"
            :disabled="interfaceData.awgParametersEnabled"
          >
            WireGuard
          </option>
          <option value="amneziawg">AmneziaWG</option></select
        ><FormInfoField
          id="runtime"
          :label="$t('admin.interfaces.runtime')"
          :data="
            interfaceData.runtime?.status ?? $t('admin.interfaces.unknown')
          " /><FormInfoField
          id="revision"
          :label="$t('admin.interfaces.revisions')"
          :data="revision" /><FormInfoField
          id="cidr"
          label="IPv4 CIDR"
          :data="interfaceData.ipv4Cidr" /><FormPrimaryActionField
          type="submit"
          :label="$t('form.save')"
      /></FormGroup>
      <FormGroup v-if="tab === 'connection'"
        ><FormHeading>{{ $t('admin.config.connection') }}</FormHeading
        ><FormNumberField
          id="listenPort"
          v-model="interfaceData.port"
          :label="$t('admin.interfaces.listenPort')"
          :description="$t('admin.interfaces.listenPortDesc')" /><FormTextField
          id="device"
          v-model="interfaceData.device"
          :label="$t('admin.interface.device')" /><FormNumberField
          id="mtu"
          v-model="interfaceData.mtu"
          :label="$t('general.mtu')" />
        <p class="col-span-full text-sm text-gray-500 dark:text-neutral-300">
          {{ $t('admin.interfaces.publicationGuidance') }}
        </p>
        <FormPrimaryActionField type="submit" :label="$t('form.save')"
      /></FormGroup>
      <FormGroup v-if="tab === 'awg'"
        ><FormHeading>{{ $t('awg.obfuscationParameters') }}</FormHeading
        ><FormSwitchField
          id="awgParametersEnabled"
          v-model="interfaceData.awgParametersEnabled"
          :label="$t('admin.interfaces.awgEnabled')" /><FormNullNumberField
          id="jC"
          v-model="interfaceData.jC"
          :label="$t('awg.jCLabel')" /><FormNullNumberField
          id="jMin"
          v-model="interfaceData.jMin"
          :label="$t('awg.jMinLabel')" /><FormNullNumberField
          id="jMax"
          v-model="interfaceData.jMax"
          :label="$t('awg.jMaxLabel')" /><FormNullTextField
          id="h1"
          v-model="interfaceData.h1"
          :label="$t('awg.h1Label')" /><FormNullTextField
          id="h2"
          v-model="interfaceData.h2"
          :label="$t('awg.h2Label')" /><FormNullTextField
          id="h3"
          v-model="interfaceData.h3"
          :label="$t('awg.h3Label')" /><FormNullTextField
          id="h4"
          v-model="interfaceData.h4"
          :label="$t('awg.h4Label')" />
        <FormNullNumberField
          id="s1"
          v-model="interfaceData.s1"
          :label="$t('awg.s1Label')"
          :description="$t('awg.s1Description')" />
        <FormNullNumberField
          id="s2"
          v-model="interfaceData.s2"
          :label="$t('awg.s2Label')"
          :description="$t('awg.s2Description')" />
        <FormNullNumberField
          id="s3"
          v-model="interfaceData.s3"
          :label="$t('awg.s3Label')"
          :description="$t('awg.s3Description')" />
        <FormNullNumberField
          id="s4"
          v-model="interfaceData.s4"
          :label="$t('awg.s4Label')"
          :description="$t('awg.s4Description')" />
        <FormNullTextField
          id="i1"
          v-model="interfaceData.i1"
          :label="$t('awg.i1Label')"
          :description="$t('awg.i1Description')" />
        <FormNullTextField
          id="i2"
          v-model="interfaceData.i2"
          :label="$t('awg.i2Label')"
          :description="$t('awg.i2Description')" />
        <FormNullTextField
          id="i3"
          v-model="interfaceData.i3"
          :label="$t('awg.i3Label')"
          :description="$t('awg.i3Description')" />
        <FormNullTextField
          id="i4"
          v-model="interfaceData.i4"
          :label="$t('awg.i4Label')"
          :description="$t('awg.i4Description')" />
        <FormNullTextField
          id="i5"
          v-model="interfaceData.i5"
          :label="$t('awg.i5Label')"
          :description="$t('awg.i5Description')" />
        <FormNullTextField
          id="contentPaddingAddition"
          v-model="interfaceData.contentPaddingAddition"
          :label="$t('awg.contentPaddingAdditionLabel')"
          :description="$t('awg.contentPaddingAdditionDescription')" />
        <FormNullTextField
          id="rekeyAfterTime"
          v-model="interfaceData.rekeyAfterTime"
          :label="$t('awg.rekeyAfterTimeLabel')"
          :description="$t('awg.rekeyAfterTimeDescription')" />
        <FormNullTextField
          id="rekeyTimeout"
          v-model="interfaceData.rekeyTimeout"
          :label="$t('awg.rekeyTimeoutLabel')"
          :description="$t('awg.rekeyTimeoutDescription')" />
        <FormNullTextField
          id="rejectAfterTime"
          v-model="interfaceData.rejectAfterTime"
          :label="$t('awg.rejectAfterTimeLabel')"
          :description="$t('awg.rejectAfterTimeDescription')" />
        <FormNullTextField
          id="keepaliveTimeout"
          v-model="interfaceData.keepaliveTimeout"
          :label="$t('awg.keepaliveTimeoutLabel')"
          :description="$t('awg.keepaliveTimeoutDescription')" />
        <FormNullTextField
          id="maxHandshakeAttempts"
          v-model="interfaceData.maxHandshakeAttempts"
          :label="$t('awg.maxHandshakeAttemptsLabel')"
          :description="$t('awg.maxHandshakeAttemptsDescription')" />
        <FormNullSwitchField
          id="randomTrailers"
          v-model="interfaceData.randomTrailers"
          :label="$t('awg.randomTrailersLabel')"
          :description="$t('awg.randomTrailersDescription')" />
        <FormNullSwitchField
          id="disableCookies"
          v-model="interfaceData.disableCookies"
          :label="$t('awg.disableCookiesLabel')"
          :description="$t('awg.disableCookiesDescription')" />
        <label for="headerProtectionAction">{{
          $t('awg.headerProtectionKeyLabel')
        }}</label>
        <select id="headerProtectionAction" v-model="headerProtectionAction">
          <option value="preserve">
            {{ $t('awg.preserveHeaderProtectionKey') }}
          </option>
          <option value="replace">
            {{ $t('awg.replaceHeaderProtectionKey') }}
          </option>
          <option value="clear">
            {{ $t('awg.clearHeaderProtectionKey') }}
          </option>
        </select>
        <template v-if="headerProtectionAction === 'replace'"
          ><FormLabel for="headerProtectionKey">{{
            $t('awg.headerProtectionKeyLabel')
          }}</FormLabel
          ><BaseInput
            id="headerProtectionKey"
            v-model.trim="headerProtectionKey"
            type="password"
            autocomplete="new-password"
        /></template>
        <p class="col-span-full">
          {{
            $t(
              interfaceData.hasHeaderProtectionKey
                ? 'awg.headerProtectionKeyConfigured'
                : 'awg.headerProtectionKeyAbsent'
            )
          }}
        </p>
        <FormPrimaryActionField type="submit" :label="$t('form.save')"
      /></FormGroup>
      <FormGroup v-if="tab === 'firewall'"
        ><FormHeading>{{ $t('admin.interface.firewall') }}</FormHeading
        ><FormSwitchField
          id="firewallEnabled"
          v-model="interfaceData.firewallEnabled"
          :label="$t('admin.interface.firewallEnabled')"
          :description="
            $t('admin.interface.firewallEnabledDesc')
          " /><FormPrimaryActionField type="submit" :label="$t('form.save')"
      /></FormGroup>
    </FormElement>
    <FormElement v-if="tab === 'defaults'" @submit.prevent="saveDefaults"
      ><FormGroup
        ><FormHeading>{{ $t('admin.interfaces.clientDefaults') }}</FormHeading
        ><FormTextField
          id="host"
          v-model="defaults.host"
          :label="$t('general.host')" /><FormNumberField
          id="endpointPort"
          v-model="defaults.port"
          :label="$t('admin.interfaces.endpointPort')"
          :description="$t('admin.interfaces.endpointPortDesc')"
      /></FormGroup>
      <FormGroup>
        <FormHeading>{{ $t('general.allowedIps') }}</FormHeading>
        <FormArrayField
          v-model="defaults.defaultAllowedIps"
          name="defaultAllowedIps"
        />
      </FormGroup>
      <FormGroup>
        <FormHeading>{{ $t('general.dns') }}</FormHeading>
        <FormArrayField v-model="defaults.defaultDns" name="defaultDns" />
      </FormGroup>
      <FormGroup>
        <FormHeading>{{ $t('form.sectionAdvanced') }}</FormHeading>
        <FormNumberField
          id="defaultMtu"
          v-model="defaults.defaultMtu"
          :label="$t('general.mtu')" /><FormNumberField
          id="defaultPersistentKeepalive"
          v-model="defaults.defaultPersistentKeepalive"
          :label="$t('general.persistentKeepalive')" /><FormPrimaryActionField
          type="submit"
          :label="$t('form.save')" /></FormGroup
    ></FormElement>
    <FormElement v-if="tab === 'hooks'" @submit.prevent="saveHooks"
      ><FormGroup
        ><FormHeading>{{ $t('hooks.preUp') }}</FormHeading
        ><FormTextArea
          id="preUp"
          v-model="hooks.preUp"
          :label="$t('hooks.preUp')" /><FormTextArea
          id="postUp"
          v-model="hooks.postUp"
          :label="$t('hooks.postUp')" /><FormTextArea
          id="preDown"
          v-model="hooks.preDown"
          :label="$t('hooks.preDown')" /><FormTextArea
          id="postDown"
          v-model="hooks.postDown"
          :label="$t('hooks.postDown')" /><FormPrimaryActionField
          type="submit"
          :label="$t('form.save')" /></FormGroup
    ></FormElement>
    <FormElement v-if="tab === 'danger'" @submit.prevent="remove"
      ><FormGroup
        ><FormHeading>{{ $t('admin.interfaces.danger') }}</FormHeading>
        <p class="col-span-full text-sm">
          {{ $t('admin.interfaces.deleteHelp') }}
        </p>
        <FormSecondaryActionField
          :label="$t('admin.interfaces.delete')"
          @click="remove" /></FormGroup
    ></FormElement>
  </main>
</template>

<script setup lang="ts">
import type { HooksUpdateType } from '#db/repositories/hooks/types';
import type { InterfaceUpdateType } from '#db/repositories/interface/types';
import type { UserConfigUpdateType } from '#db/repositories/userConfig/types';

type InterfaceRuntime = {
  status?: string;
  lastError?: string | null;
  desiredRevision?: number;
  appliedRevision?: number;
};
type InterfaceDetail = Omit<InterfaceUpdateType, 'headerProtectionKey'> & {
  hasHeaderProtectionKey: boolean;
  name: string;
  isDefault: boolean;
  runtime?: InterfaceRuntime;
};

const route = useRoute();
const interfaceId = route.params.interfaceId as string;
const { t } = useI18n();
const globalStore = useGlobalStore();
const { data: interfaceData, refresh: refreshInterface } =
  await useFetch<InterfaceDetail>(`/api/admin/interfaces/${interfaceId}`, {
    deep: true,
  });
const { data: defaults, refresh: refreshDefaults } =
  await useFetch<UserConfigUpdateType>(
    `/api/admin/interfaces/${interfaceId}/userconfig`,
    { deep: true }
  );
const { data: hooks, refresh: refreshHooks } = await useFetch<HooksUpdateType>(
  `/api/admin/interfaces/${interfaceId}/hooks`
);
const tab = ref('overview');
const headerProtectionAction = ref<'preserve' | 'replace' | 'clear'>(
  'preserve'
);
const headerProtectionKey = ref('');
const hooksReviewed = ref(false);
const needsHookReview = computed(() => route.query.reviewHooks === '1');
const tabs = computed(() => [
  { id: 'overview', label: t('admin.interfaces.overview') },
  { id: 'connection', label: t('admin.config.connection') },
  { id: 'awg', label: t('awg.obfuscationParameters') },
  { id: 'defaults', label: t('admin.interfaces.clientDefaults') },
  { id: 'hooks', label: t('pages.admin.hooks') },
  { id: 'firewall', label: t('admin.interface.firewall') },
  { id: 'danger', label: t('admin.interfaces.danger') },
]);
const revision = computed(
  () =>
    `${interfaceData.value?.runtime?.appliedRevision ?? 0} / ${interfaceData.value?.runtime?.desiredRevision ?? 0}`
);
const runtimeSummary = computed(
  () =>
    `${t('admin.interfaces.runtime')}: ${interfaceData.value?.runtime?.status ?? t('admin.interfaces.unknown')}`
);
const saveInterface = useSubmit(
  () => {
    if (!interfaceData.value) throw new Error('Interface data is unavailable');
    if (
      interfaceData.value.enabled &&
      needsHookReview.value &&
      !hooksReviewed.value
    )
      throw new Error(t('admin.interfaces.hookReviewRequired'));
    return $fetch(`/api/admin/interfaces/${interfaceId}`, {
      method: 'post',
      body: {
        ...interfaceData.value,
        ...(headerProtectionAction.value === 'replace'
          ? { headerProtectionKey: headerProtectionKey.value.trim() }
          : headerProtectionAction.value === 'clear'
            ? { headerProtectionKey: null }
            : {}),
      },
    });
  },
  {
    revert: async (success) => {
      headerProtectionKey.value = '';
      headerProtectionAction.value = 'preserve';
      await refreshInterface();
      if (!success) return;
    },
    successMsg: t('toast.saved'),
  }
);
const saveDefaults = useSubmit(
  () =>
    $fetch(`/api/admin/interfaces/${interfaceId}/userconfig`, {
      method: 'post',
      body: defaults.value,
    }),
  { revert: async () => refreshDefaults(), successMsg: t('toast.saved') }
);
const saveHooks = useSubmit(
  () =>
    $fetch(`/api/admin/interfaces/${interfaceId}/hooks`, {
      method: 'post',
      body: hooks.value,
    }),
  { revert: async () => refreshHooks(), successMsg: t('toast.saved') }
);
async function restart() {
  await $fetch(`/api/admin/interfaces/${interfaceId}/restart`, {
    method: 'post',
  });
  await refreshInterface();
}
async function setDefault() {
  await $fetch(`/api/admin/interfaces/${interfaceId}/default`, {
    method: 'post',
  });
  await globalStore.refreshInformation();
  await refreshInterface();
}
async function remove() {
  if (!window.confirm(t('admin.interfaces.deleteConfirm'))) return;
  await $fetch(`/api/admin/interfaces/${interfaceId}`, { method: 'delete' });
  await navigateTo('/admin/interfaces');
}
</script>
