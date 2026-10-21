<template>
  <div
    class="col-span-full space-y-3 rounded border p-3 text-sm dark:border-neutral-600"
    aria-live="polite"
  >
    <p>{{ $t('admin.routing.previewAdvisory') }}</p>
    <p>
      {{
        $t('admin.routing.previewRevisions', {
          desired: preview.desiredRevision,
          applied: preview.observed.appliedRevision ?? '—',
        })
      }}
    </p>
    <p>
      {{
        $t(
          preview.observed.pendingStage
            ? 'admin.routing.transitionPending'
            : 'admin.routing.noGuardPending'
        )
      }}
    </p>
    <p v-if="preview.explanation">{{ explain(preview.explanation) }}</p>
    <ul class="list-inside list-disc">
      <li v-for="(example, index) in preview.winnerExamples" :key="index">
        {{ explain(example) }}
      </li>
    </ul>
    <div
      v-for="group in preview.groups"
      :key="group.id"
      class="rounded bg-gray-50 p-2 dark:bg-neutral-800"
    >
      <strong>{{ group.name }}</strong>
      <p>
        {{
          $t(
            group.shadowed
              ? 'admin.routing.shadowed'
              : 'admin.routing.effectiveCoverage',
            { prefixes: group.effectivePrefixes.join(', ') || '—' }
          )
        }}
      </p>
      <p>
        {{
          $t('admin.routing.allDownPreview', {
            action: $t(`admin.routing.${group.allExitsDownPolicy}`),
          })
        }}
      </p>
      <p>{{ observed(group.id) }}</p>
    </div>
    <details>
      <summary>{{ $t('admin.routing.generatedDetails') }}</summary>
      <dl class="grid grid-cols-2 gap-2 break-words">
        <template v-for="(count, name) in preview.counts" :key="name"
          ><dt>{{ $t(`admin.routing.counts.${name}`) }}</dt>
          <dd>{{ count }}</dd></template
        >
      </dl>
      <p>
        {{
          $t('admin.routing.bypassPrefixes', {
            prefixes: preview.bypassPrefixes.join(', '),
          })
        }}
      </p>
    </details>
  </div>
</template>

<script setup lang="ts">
import type { TypedInternalResponse } from 'nitropack/types';
type Preview = TypedInternalResponse<
  '/api/admin/routing-groups/preview',
  unknown,
  'post'
>;
const props = defineProps<{
  preview: Preview;
  clients: { id: number; name: string; interfaceId: string }[];
  groups: { id: number; name: string }[];
}>();
const { t } = useI18n();
function client(id: number | null) {
  const profile = props.clients.find((value) => value.id === id);
  return profile ? `#${id} ${profile.name} (${profile.interfaceId})` : '—';
}
function observed(id: number) {
  const state = props.preview.observed.groups.find(
    (group) => group.groupId === id
  );
  return t('admin.routing.observedGateways', {
    selected: client(state?.selectedExitClientId ?? null),
    applied: client(state?.appliedExitClientId ?? null),
    revision: state?.appliedRevision ?? '—',
  });
}
function explain(example: NonNullable<Preview['explanation']>) {
  if (!example.winner)
    return t(
      example.outcome === 'managed_network_bypass'
        ? 'admin.routing.explanationBypass'
        : 'admin.routing.explanationHost',
      {
        member: client(example.memberClientId),
        destination: example.destinationIpv4,
      }
    );
  const group = props.preview.groups.find(
    (value) => value.id === example.winner!.groupId
  );
  return t('admin.routing.explanationWinner', {
    member: client(example.memberClientId),
    destination: example.destinationIpv4,
    prefix: example.winner.originalPrefix,
    group: group?.name ?? `#${example.winner.groupId}`,
  });
}
</script>
