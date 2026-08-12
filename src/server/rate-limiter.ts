const DEFAULT_WINDOW_MS = 60_000;
const MAX_TRACKED_KEYS = 10_000;

interface Window {
  count: number;
  windowStart: number;
}

export interface RateLimitResult {
  allowed: boolean;
  retryAfterMs: number;
}

/**
 * Ephemeral, per-process, fixed-window rate limiter keyed by an arbitrary
 * string (the hosted verifier uses the client's remote address). Bounded to
 * MAX_TRACKED_KEYS distinct keys to prevent unbounded memory growth from an
 * attacker cycling through many source addresses.
 *
 * Deliberately mutates a private Map rather than following this codebase's
 * usual immutable-update convention: this is per-request-hot-path counter
 * state, never signed, never persisted, and never shared outside this
 * instance — the immutability rule exists to prevent hidden side effects on
 * shared domain objects, which does not apply here.
 */
export class RateLimiter {
  readonly #limit: number;
  readonly #windowMs: number;
  readonly #windows = new Map<string, Window>();

  constructor(limit: number, windowMs: number = DEFAULT_WINDOW_MS) {
    if (!Number.isSafeInteger(limit) || limit <= 0) {
      throw new Error("rate limit must be a positive integer");
    }
    if (!Number.isSafeInteger(windowMs) || windowMs <= 0) {
      throw new Error("rate limit window must be a positive integer");
    }
    this.#limit = limit;
    this.#windowMs = windowMs;
  }

  attempt(key: string, now: number = Date.now()): RateLimitResult {
    const existing = this.#windows.get(key);

    if (!existing || now - existing.windowStart >= this.#windowMs) {
      this.#evictIfFull();
      this.#windows.set(key, { count: 1, windowStart: now });
      return { allowed: true, retryAfterMs: 0 };
    }

    if (existing.count < this.#limit) {
      existing.count += 1;
      return { allowed: true, retryAfterMs: 0 };
    }

    return {
      allowed: false,
      retryAfterMs: this.#windowMs - (now - existing.windowStart),
    };
  }

  get trackedKeyCount(): number {
    return this.#windows.size;
  }

  #evictIfFull(): void {
    if (this.#windows.size < MAX_TRACKED_KEYS) return;
    const oldestKey = this.#windows.keys().next().value;
    if (oldestKey !== undefined) this.#windows.delete(oldestKey);
  }
}
