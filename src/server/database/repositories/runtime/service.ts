import { eq, inArray, sql } from 'drizzle-orm';

import { interfaceRuntimeState, runtimeReconciliationState } from './schema';

import type { DBType } from '#db/sqlite';

type DesiredStateDatabase = Pick<DBType, 'update'>;

export function getSafeRuntimeErrorMessage(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  const commandFailure = message.match(
    /^(\S+ failed with (?:exit code \d+|signal \S+))/
  );
  return commandFailure?.[1] ?? message;
}

export async function bumpDesiredRevision(
  db: DesiredStateDatabase,
  interfaceIds: readonly string[]
) {
  const [runtime] = await db
    .update(runtimeReconciliationState)
    .set({
      desiredRevision: sql`${runtimeReconciliationState.desiredRevision} + 1`,
      status: 'pending',
      lastError: null,
    })
    .where(eq(runtimeReconciliationState.id, 1))
    .returning({ desiredRevision: runtimeReconciliationState.desiredRevision })
    .execute();

  if (!runtime) {
    throw new Error('Runtime reconciliation state not found');
  }

  const uniqueInterfaceIds = [...new Set(interfaceIds)];
  if (uniqueInterfaceIds.length > 0) {
    await db
      .update(interfaceRuntimeState)
      .set({
        desiredRevision: sql`${interfaceRuntimeState.desiredRevision} + 1`,
        status: 'pending',
        lastError: null,
      })
      .where(inArray(interfaceRuntimeState.interfaceId, uniqueInterfaceIds))
      .execute();
  }

  return runtime.desiredRevision;
}

export class RuntimeStateService {
  #db: DBType;

  constructor(db: DBType) {
    this.#db = db;
  }

  async getGlobal() {
    const state = await this.#db.query.runtimeReconciliationState
      .findFirst({
        where: eq(runtimeReconciliationState.id, 1),
      })
      .execute();
    if (!state) {
      throw new Error('Runtime reconciliation state not found');
    }
    return state;
  }

  async getInterface(interfaceId: string) {
    const state = await this.#db.query.interfaceRuntimeState
      .findFirst({
        where: eq(interfaceRuntimeState.interfaceId, interfaceId),
      })
      .execute();
    if (!state) {
      throw new Error(`Runtime state for interface ${interfaceId} not found`);
    }
    return state;
  }

  getAllInterfaces() {
    return this.#db.query.interfaceRuntimeState
      .findMany({
        orderBy: (table, { asc }) => asc(table.interfaceId),
      })
      .execute();
  }

  async markApplying() {
    const [state] = await this.#db
      .update(runtimeReconciliationState)
      .set({
        status: 'applying',
        lastStartedAt: new Date().toISOString(),
        lastError: null,
      })
      .where(eq(runtimeReconciliationState.id, 1))
      .returning({
        desiredRevision: runtimeReconciliationState.desiredRevision,
      })
      .execute();
    if (!state) throw new Error('Runtime reconciliation state not found');
    return state.desiredRevision;
  }

  async markInterfaceApplying(
    interfaceId: string,
    status: 'starting' | 'stopping'
  ) {
    await this.#db
      .update(interfaceRuntimeState)
      .set({ status, lastError: null })
      .where(eq(interfaceRuntimeState.interfaceId, interfaceId))
      .execute();
  }

  async markInterfaceApplied(
    interfaceId: string,
    observedUp: boolean,
    appliedRevision?: number
  ) {
    await this.#db.transaction(async (tx) => {
      const state = await tx.query.interfaceRuntimeState
        .findFirst({
          where: eq(interfaceRuntimeState.interfaceId, interfaceId),
        })
        .execute();
      if (!state) {
        throw new Error(`Runtime state for interface ${interfaceId} not found`);
      }
      const targetRevision = appliedRevision ?? state.desiredRevision;
      const stillPending = state.desiredRevision > targetRevision;
      const now = new Date().toISOString();
      await tx
        .update(interfaceRuntimeState)
        .set({
          appliedRevision: targetRevision,
          status: stillPending ? 'pending' : observedUp ? 'up' : 'disabled',
          observedUp,
          restartRequired: stillPending ? state.restartRequired : false,
          lastStartedAt:
            observedUp && !state.observedUp ? now : state.lastStartedAt,
          lastStoppedAt:
            !observedUp && state.observedUp ? now : state.lastStoppedAt,
          lastAppliedAt: now,
          lastError: null,
        })
        .where(eq(interfaceRuntimeState.interfaceId, interfaceId))
        .execute();
    });
  }

  async markInterfaceFailed(
    interfaceId: string,
    error: unknown,
    observedUp = false,
    restartRequired = true
  ) {
    const message = getSafeRuntimeErrorMessage(error);
    await this.#db
      .update(interfaceRuntimeState)
      .set({
        status: 'degraded',
        observedUp,
        restartRequired,
        lastError: message,
      })
      .where(eq(interfaceRuntimeState.interfaceId, interfaceId))
      .execute();
  }

  async markGlobalApplied(appliedRevision?: number) {
    await this.#db.transaction(async (tx) => {
      const state = await tx.query.runtimeReconciliationState
        .findFirst({ where: eq(runtimeReconciliationState.id, 1) })
        .execute();
      if (!state) throw new Error('Runtime reconciliation state not found');
      const targetRevision = appliedRevision ?? state.desiredRevision;
      const stillPending = state.desiredRevision > targetRevision;
      const now = new Date().toISOString();
      await tx
        .update(runtimeReconciliationState)
        .set({
          appliedRevision: targetRevision,
          status: stillPending ? 'pending' : 'idle',
          lastSucceededAt: now,
          lastError: null,
        })
        .where(eq(runtimeReconciliationState.id, 1))
        .execute();
    });
    return this.getGlobal();
  }

  async markGlobalPending({ ensureUnapplied = false } = {}) {
    await this.#db.transaction(async (tx) => {
      const state = await tx.query.runtimeReconciliationState
        .findFirst({ where: eq(runtimeReconciliationState.id, 1) })
        .execute();
      if (!state) throw new Error('Runtime reconciliation state not found');
      await tx
        .update(runtimeReconciliationState)
        .set({
          desiredRevision:
            ensureUnapplied && state.desiredRevision <= state.appliedRevision
              ? state.appliedRevision + 1
              : state.desiredRevision,
          status: 'pending',
          lastError: null,
        })
        .where(eq(runtimeReconciliationState.id, 1))
        .execute();
    });
    return this.getGlobal();
  }

  async markGlobalFailed(error: unknown) {
    const message = getSafeRuntimeErrorMessage(error);
    await this.#db
      .update(runtimeReconciliationState)
      .set({ status: 'degraded', lastError: message })
      .where(eq(runtimeReconciliationState.id, 1))
      .execute();
    return this.getGlobal();
  }
}

export function toSafeRuntimeState<T extends { lastError: unknown }>(state: T) {
  const { lastError: _lastError, ...safeState } = state;
  return safeState;
}
