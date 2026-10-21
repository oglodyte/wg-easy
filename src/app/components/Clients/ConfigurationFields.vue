<template>
  <FormGroup>
    <FormHeading>
      {{ $t('form.sectionGeneral') }}
    </FormHeading>
    <FormTextField id="name" v-model="data.name" :label="$t('general.name')" />
    <FormSwitchField
      id="enabled"
      v-model="data.enabled"
      :label="$t('client.enabled')"
    />
    <FormDateField
      id="expiresAt"
      v-model="data.expiresAt"
      :description="$t('client.expireDateDesc')"
      :label="$t('client.expireDate')"
    />
  </FormGroup>
  <FormGroup>
    <FormHeading>{{ $t('client.address') }}</FormHeading>
    <p v-if="creating" class="col-span-full text-sm">
      {{ $t('client.automaticAddresses') }}
    </p>
    <FormSwitchField
      v-if="creating"
      id="disableIpv6"
      v-model="disableIpv6"
      :label="$t('client.disableIpv6')"
    />
    <FormTextField id="ipv4Address" v-model="data.ipv4Address" label="IPv4" />
    <FormTextField
      v-if="!creating || !disableIpv6"
      id="ipv6Address"
      :model-value="data.ipv6Address ?? ''"
      label="IPv6"
      @update:model-value="data.ipv6Address = $event || null"
    />
    <FormNullTextField
      id="serverEndpoint"
      v-model="data.serverEndpoint"
      :label="$t('client.serverEndpoint')"
      :description="$t('client.serverEndpointHelp')"
    />
  </FormGroup>
  <FormGroup>
    <FormHeading :description="$t('client.allowedIpsDesc')">
      {{ $t('general.allowedIps') }}
    </FormHeading>
    <FormNullArrayField v-model="data.allowedIps" name="allowedIps" />
  </FormGroup>
  <FormGroup>
    <FormHeading :description="$t('client.serverAllowedIpsDesc')">
      {{ $t('client.serverAllowedIps') }}
    </FormHeading>
    <FormArrayField v-model="data.serverAllowedIps" name="serverAllowedIps" />
  </FormGroup>
  <FormGroup>
    <FormHeading :description="$t('client.firewallIpsDesc')">
      {{ $t('client.firewallIps') }}
    </FormHeading>
    <FormNullArrayField
      v-model="data.firewallIps"
      allow-empty
      name="firewallIps"
    />
  </FormGroup>
  <FormGroup>
    <FormHeading :description="$t('client.dnsDesc')">
      {{ $t('general.dns') }}
    </FormHeading>
    <FormNullArrayField v-model="data.dns" allow-empty name="dns" />
  </FormGroup>
  <FormGroup>
    <FormHeading>{{ $t('form.sectionAdvanced') }}</FormHeading>
    <p v-if="creating" class="col-span-full text-sm">
      {{ $t('client.inheritNumbers') }}
    </p>
    <FormOptionalNumberField
      id="mtu"
      v-model="data.mtu"
      :description="$t('client.mtuDesc')"
      :label="$t('general.mtu')"
    />
    <FormOptionalNumberField
      id="persistentKeepalive"
      v-model="data.persistentKeepalive"
      :description="$t('client.persistentKeepaliveDesc')"
      :label="$t('general.persistentKeepalive')"
    />
  </FormGroup>
  <FormGroup v-if="creating && awgEnabled">
    <FormSwitchField
      id="override-awg"
      v-model="overrideAwg"
      :label="$t('client.overrideAwg')"
    />
  </FormGroup>
  <FormGroup v-if="awgEnabled && (!creating || overrideAwg)">
    <FormHeading>{{ $t('awg.obfuscationParameters') }}</FormHeading>

    <FormOptionalNumberField
      id="jC"
      v-model="data.jC"
      :label="$t('awg.jCLabel')"
      :description="$t('awg.jCDescription')"
    />
    <FormOptionalNumberField
      id="Jmin"
      v-model="data.jMin"
      :label="$t('awg.jMinLabel')"
      :description="$t('awg.jMinDescription')"
    />
    <FormOptionalNumberField
      id="Jmax"
      v-model="data.jMax"
      :label="$t('awg.jMaxLabel')"
      :description="$t('awg.jMaxDescription')"
    />

    <div class="col-span-full text-sm">* {{ $t('awg.mtuNote') }}</div>

    <FormNullTextField
      id="i1"
      v-model="data.i1"
      :label="$t('awg.i1Label')"
      :description="$t('awg.i1Description')"
    />
    <FormNullTextField
      id="i2"
      v-model="data.i2"
      :label="$t('awg.i2Label')"
      :description="$t('awg.i2Description')"
    />
    <FormNullTextField
      id="i3"
      v-model="data.i3"
      :label="$t('awg.i3Label')"
      :description="$t('awg.i3Description')"
    />
    <FormNullTextField
      id="i4"
      v-model="data.i4"
      :label="$t('awg.i4Label')"
      :description="$t('awg.i4Description')"
    />
    <FormNullTextField
      id="i5"
      v-model="data.i5"
      :label="$t('awg.i5Label')"
      :description="$t('awg.i5Description')"
    />
  </FormGroup>
  <FormGroup>
    <FormHeading :description="$t('client.hooksDescription')">
      {{ $t('client.hooks') }}
    </FormHeading>
    <FormTextArea
      id="PreUp"
      v-model="data.preUp"
      :description="$t('client.hooksLeaveEmpty')"
      :label="$t('hooks.preUp')"
    />
    <FormTextArea
      id="PostUp"
      v-model="data.postUp"
      :description="$t('client.hooksLeaveEmpty')"
      :label="$t('hooks.postUp')"
    />
    <FormTextArea
      id="PreDown"
      v-model="data.preDown"
      :description="$t('client.hooksLeaveEmpty')"
      :label="$t('hooks.preDown')"
    />
    <FormTextArea
      id="PostDown"
      v-model="data.postDown"
      :description="$t('client.hooksLeaveEmpty')"
      :label="$t('hooks.postDown')"
    />
  </FormGroup>
  <FormGroup>
    <label for="preferredConfigFormat">{{
      $t('client.preferredConfigFormat')
    }}</label>
    <select
      id="preferredConfigFormat"
      v-model="data.preferredConfigFormat"
      class="rounded border bg-white p-2 dark:bg-neutral-800"
    >
      <option value="auto">{{ $t('client.autoFormat') }}</option>
      <option value="wireguard" :disabled="awgEnabled">WireGuard</option>
      <option value="amneziawg">AmneziaWG</option>
    </select>
    <p v-if="!awgEnabled" class="col-span-full text-sm">
      {{ $t('client.compatibilityParameters') }}
    </p>
  </FormGroup>
</template>
<script setup lang="ts" generic="T extends ClientConfigurationDraft">
import type { ClientConfigurationDraft } from '~/utils/clientConfigurationEditor';
defineProps<{ creating?: boolean; awgEnabled: boolean }>();
const data = defineModel<T>({ required: true });
const disableIpv6 = defineModel<boolean>('disableIpv6', { default: false });
const overrideAwg = defineModel<boolean>('overrideAwg', { default: false });
</script>
