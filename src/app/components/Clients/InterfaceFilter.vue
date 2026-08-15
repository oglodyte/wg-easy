<template>
  <select
    v-model="selected"
    class="rounded bg-white px-2 py-2 text-sm shadow-sm ring-1 ring-gray-300 dark:bg-neutral-800 dark:ring-neutral-700"
    :aria-label="$t('client.interfaceFilter')"
  >
    <option value="">{{ $t('client.allInterfaces') }}</option>
    <option v-for="item in interfaces" :key="item.name" :value="item.name">
      {{ item.name }}
    </option>
  </select>
</template>
<script setup lang="ts">
const clientsStore = useClientsStore();
const globalStore = useGlobalStore();
const interfaces = computed(() => globalStore.information?.interfaces ?? []);
const selected = computed({
  get: () => clientsStore.interfaceId ?? '',
  set: (value) => clientsStore.setInterfaceFilter(value || undefined),
});
</script>
