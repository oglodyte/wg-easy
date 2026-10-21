<template>
  <FormGroup>
    <FormHeading>{{ $t('client.credentials') }}</FormHeading>
    <p class="col-span-full text-sm">
      {{
        $t(
          creating ? 'client.creationCredentialsHelp' : 'client.credentialsHelp'
        )
      }}
    </p>
    <FormInfoField
      v-if="publicKey && !data.replacePrivateKey"
      id="publicKey"
      :label="$t('client.publicKey')"
      :data="publicKey"
    />
    <FormSwitchField
      id="replacePrivateKey"
      v-model="data.replacePrivateKey"
      :label="
        $t(creating ? 'client.supplyPrivateKey' : 'client.replacePrivateKey')
      "
    />
    <template v-if="data.replacePrivateKey">
      <label for="privateKey">{{ $t('client.privateKey') }}</label>
      <BaseInput
        id="privateKey"
        v-model.trim="data.privateKey"
        type="password"
        autocomplete="new-password"
        spellcheck="false"
      />
      <p class="col-span-full text-sm">
        {{ $t('client.derivedPublicKeyHelp') }}
      </p>
    </template>
    <label for="pskAction">{{ $t('client.preSharedKey') }}</label>
    <select
      id="pskAction"
      v-model="data.pskAction"
      class="rounded border bg-white p-2 dark:bg-neutral-800"
    >
      <option value="preserve">
        {{
          $t(
            creating
              ? 'client.generatePreSharedKey'
              : 'client.preservePreSharedKey'
          )
        }}
      </option>
      <option value="replace">{{ $t('client.replacePreSharedKey') }}</option>
      <option value="clear">{{ $t('client.clearPreSharedKey') }}</option>
    </select>
    <template v-if="data.pskAction === 'replace'">
      <label for="preSharedKey">{{ $t('client.preSharedKey') }}</label>
      <BaseInput
        id="preSharedKey"
        v-model.trim="data.preSharedKey"
        type="password"
        autocomplete="new-password"
        spellcheck="false"
      />
    </template>
    <p
      v-if="hasPreSharedKey !== undefined && !creating"
      class="col-span-full text-sm"
    >
      {{
        $t(
          hasPreSharedKey
            ? 'client.preSharedKeySet'
            : 'client.preSharedKeyUnset'
        )
      }}
    </p>
  </FormGroup>
</template>
<script setup lang="ts">
import type { CredentialDraft } from '~/utils/clientConfigurationEditor';
defineProps<{
  creating?: boolean;
  publicKey?: string;
  hasPreSharedKey?: boolean;
}>();
const data = defineModel<CredentialDraft>({ required: true });
watch(
  () => data.value.replacePrivateKey,
  (enabled) => {
    if (!enabled) data.value.privateKey = '';
  }
);
watch(
  () => data.value.pskAction,
  (action) => {
    if (action !== 'replace') data.value.preSharedKey = '';
  }
);
</script>
