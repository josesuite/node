import type { Limits } from '../../policy/limits.ts';

/** Mutable counters owned by one operation and shared by every nested layer. */
export class OperationBudget {
  private readonly limits: Limits;
  private jsonNodes = 0;
  private layers = 0;
  private attempts = 0;

  constructor(limits: Limits) {
    this.limits = limits;
  }

  consumeJsonNodes(count: number): boolean {
    this.jsonNodes += count;
    return this.jsonNodes <= this.limits.jsonNodes;
  }

  consumeLayer(): boolean {
    this.layers += 1;
    return this.layers <= this.limits.cryptographicLayers;
  }

  consumeAttempt(): boolean {
    this.attempts += 1;
    return this.attempts <= this.limits.cryptographicAttempts;
  }
}
