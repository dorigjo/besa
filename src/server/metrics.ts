export interface MetricsSnapshot {
  startedAt: string;
  uptimeSeconds: number;
  requestsTotal: number;
  requestsByRoute: Record<string, number>;
  requestsByStatus: Record<string, number>;
  rateLimitedTotal: number;
}

/**
 * In-memory, per-process request counters for the hosted verifier's
 * GET /metrics route. Route names passed to record() must come from a
 * fixed, known set (see routeLabel() in hosted-verifier.ts), never a raw
 * request URL — an unbounded label space would let a caller inflate this
 * object's memory by requesting many distinct nonsense paths.
 */
export class Metrics {
  readonly #startedAt = Date.now();
  #requestsTotal = 0;
  readonly #byRoute = new Map<string, number>();
  readonly #byStatus = new Map<string, number>();
  #rateLimited = 0;

  record(route: string, status: number): void {
    this.#requestsTotal += 1;
    this.#byRoute.set(route, (this.#byRoute.get(route) ?? 0) + 1);
    const statusKey = String(status);
    this.#byStatus.set(statusKey, (this.#byStatus.get(statusKey) ?? 0) + 1);
  }

  recordRateLimited(): void {
    this.#rateLimited += 1;
  }

  snapshot(now: number = Date.now()): MetricsSnapshot {
    return {
      startedAt: new Date(this.#startedAt).toISOString(),
      uptimeSeconds: Math.floor((now - this.#startedAt) / 1000),
      requestsTotal: this.#requestsTotal,
      requestsByRoute: Object.fromEntries(this.#byRoute),
      requestsByStatus: Object.fromEntries(this.#byStatus),
      rateLimitedTotal: this.#rateLimited,
    };
  }
}
