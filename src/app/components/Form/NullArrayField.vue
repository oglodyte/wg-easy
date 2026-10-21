<template>
  <div class="flex flex-col gap-2">
    <div v-if="data === null">
      {{ emptyText || $t('form.nullNoItems') }}
    </div>
    <div v-for="(item, i) in data" v-else :key="i">
      <div class="mt-1 flex flex-row gap-1">
        <input
          :value="item"
          :name="name"
          type="text"
          class="rounded-lg border-2 border-gray-100 text-gray-500 focus:border-red-800 focus:outline-0 focus:ring-0 dark:border-neutral-800 dark:bg-neutral-700 dark:text-neutral-200 dark:placeholder:text-neutral-400"
          @input="update($event, i)"
        />
        <BaseSecondaryButton type="button" class="rounded-lg" @click="del(i)">
          {{ '-' }}
        </BaseSecondaryButton>
      </div>
    </div>
    <p v-if="allowEmpty && data?.length === 0" class="text-xs">
      {{ $t('form.emptyOverride') }}
    </p>
    <div v-if="allowEmpty" class="flex flex-wrap gap-2 text-xs">
      <BaseSecondaryButton type="button" @click="data = null">{{
        $t('form.inherit')
      }}</BaseSecondaryButton>
      <BaseSecondaryButton type="button" @click="data = []">{{
        $t('form.clearOverride')
      }}</BaseSecondaryButton>
    </div>
    <div class="mt-2">
      <BasePrimaryButton type="button" class="rounded-lg" @click="add">
        {{ $t('form.add') }}
      </BasePrimaryButton>
    </div>
  </div>
</template>

<script lang="ts" setup>
const data = defineModel<string[] | null>();
const props = defineProps<{
  emptyText?: string[];
  name: string;
  allowEmpty?: boolean;
}>();

function update(e: Event, i: number) {
  const v = (e.target as HTMLInputElement).value;
  if (!data.value) {
    return;
  }
  data.value[i] = v;
}

function add() {
  if (data.value === undefined) {
    return;
  }
  if (data.value === null) {
    data.value = [''];
  } else {
    data.value.push('');
  }
}

function del(i: number) {
  if (!data.value) {
    return;
  }
  data.value.splice(i, 1);
  if (data.value.length === 0 && !props.allowEmpty) {
    data.value = null;
  }
}
</script>
