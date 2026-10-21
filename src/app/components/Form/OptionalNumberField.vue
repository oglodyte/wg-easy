<template>
  <FormLabel :for="id">{{ label }}</FormLabel>
  <BaseInput
    :id="id"
    :model-value="data ?? ''"
    type="number"
    :name="id"
    @update:model-value="update"
  />
  <p v-if="description" class="col-span-full text-xs">{{ description }}</p>
</template>
<script setup lang="ts">
defineProps<{ id: string; label: string; description?: string }>();
const data = defineModel<number | null>();
function update(value: unknown) {
  data.value = value === '' || value === null ? null : Number(value);
}
</script>
