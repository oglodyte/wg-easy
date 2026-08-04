<template><div /></template>
<script setup lang="ts">
const { data } = await useFetch('/api/information');
await navigateTo(
  `/admin/interfaces/${data.value?.defaultInterfaceId ?? 'wg0'}`,
  { replace: true }
);
</script>
