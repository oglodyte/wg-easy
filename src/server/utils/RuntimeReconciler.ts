import type {
  InterfaceChangeImpact,
  InterfaceRuntimeAction,
  MutationResult,
} from '#shared/types/runtime';

type ReconcileRequest = {
  reasons: readonly string[];
  impacts: readonly InterfaceChangeImpact[];
};

type ReconcileExecutor = (request: ReconcileRequest) => Promise<MutationResult>;

type Waiter = {
  resolve: (result: MutationResult) => void;
  reject: (error: unknown) => void;
};

const actionPriority: Record<InterfaceRuntimeAction, number> = {
  none: 0,
  sync: 1,
  restart: 2,
  up: 3,
  down: 3,
};

export function mergeRuntimeActions(
  current: InterfaceRuntimeAction | undefined,
  next: InterfaceRuntimeAction
): InterfaceRuntimeAction {
  if (!current) return next;
  if (actionPriority[next] > actionPriority[current]) return next;
  if (actionPriority[next] < actionPriority[current]) return current;
  // For equally strong desired-state transitions, the newest request wins.
  return next;
}

export async function runIsolatedInterfaceOperations<T>(
  items: readonly T[],
  getInterfaceId: (item: T) => string,
  operation: (item: T) => Promise<void>
) {
  const failures: { interfaceId: string; error: unknown }[] = [];
  for (const item of items) {
    try {
      await operation(item);
    } catch (error) {
      failures.push({ interfaceId: getInterfaceId(item), error });
    }
  }
  return failures;
}

/**
 * One process-wide serialized coordinator. Requests received during an active
 * pass are coalesced into a fresh follow-up pass instead of reusing stale
 * state captured by the request that is already running.
 */
export class RuntimeReconciler {
  #executor: ReconcileExecutor;
  #running = false;
  #scheduled = false;
  #reasons = new Set<string>();
  #impacts = new Map<string, InterfaceRuntimeAction>();
  #waiters: Waiter[] = [];
  #stopping = false;

  constructor(executor: ReconcileExecutor) {
    this.#executor = executor;
  }

  requestReconcile(
    reason: string,
    impacts: readonly InterfaceChangeImpact[] = []
  ): Promise<MutationResult> {
    if (this.#stopping) {
      return Promise.reject(new Error('Runtime reconciler is shutting down'));
    }

    this.#reasons.add(reason);
    for (const impact of impacts) {
      this.#impacts.set(
        impact.interfaceId,
        mergeRuntimeActions(
          this.#impacts.get(impact.interfaceId),
          impact.action
        )
      );
    }

    const result = new Promise<MutationResult>((resolve, reject) => {
      this.#waiters.push({ resolve, reject });
    });
    if (!this.#running && !this.#scheduled) {
      this.#scheduled = true;
      queueMicrotask(() => {
        this.#scheduled = false;
        void this.#drain();
      });
    }
    return result;
  }

  async stop() {
    this.#stopping = true;
    while (this.#running || this.#scheduled) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }

  async #drain() {
    if (this.#running) return;
    this.#running = true;

    try {
      while (this.#waiters.length > 0) {
        const reasons = [...this.#reasons];
        const impacts = [...this.#impacts].map(([interfaceId, action]) => ({
          interfaceId,
          action,
        }));
        const waiters = this.#waiters;

        this.#reasons = new Set();
        this.#impacts = new Map();
        this.#waiters = [];

        try {
          const result = await this.#executor({ reasons, impacts });
          for (const waiter of waiters) waiter.resolve(result);
        } catch (error) {
          for (const waiter of waiters) waiter.reject(error);
        }
      }
    } finally {
      this.#running = false;
      if (this.#waiters.length > 0) void this.#drain();
    }
  }
}
