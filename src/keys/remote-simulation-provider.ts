import { publicKeyId, signWithKeyPair, validateKeyPair, type KeyPair } from "../crypto.js";
import type { KeyProvider } from "./provider.js";

export type RemoteFailureMode =
  | "none"
  | "timeout"
  | "provider-error"
  | "cancelled"
  | "invalid-signature";

export interface RemoteSimulationOptions {
  latencyMs?: number;
  timeoutMs?: number;
  maxRetries?: number;
  failureMode?: RemoteFailureMode;
  /**
   * For failureMode "timeout"/"provider-error": simulated round trips fail
   * through this attempt number (1-indexed) and succeed from the next
   * attempt onward — models a transient remote failure that recovers, not
   * a permanently down one. Omitted (default: every attempt fails, the
   * existing "permanently down" behavior). No effect on "cancelled" (never
   * retried by design) or "invalid-signature" (the round trip itself
   * succeeds; only its content is corrupted, independent of retry logic).
   */
  failUntilAttempt?: number;
}

const DEFAULT_LATENCY_MS = 15;
const DEFAULT_TIMEOUT_MS = 2000;
const DEFAULT_MAX_RETRIES = 2;

/**
 * Simulates an Application -> HTTP -> Signing-Service -> Ed25519 provider
 * entirely in-process: no sockets, no cloud SDK, no new dependency. Exists
 * to prove KeyProvider is genuinely swappable — a second, structurally
 * different implementation of the same three-method interface, exercised
 * through the exact same signManifestWithProvider/createReceiptWithProvider
 * call sites as LocalKeyProvider.
 *
 * Signing itself still routes through signWithKeyPair() (the same
 * primitive LocalKeyProvider uses), so this class never becomes a second
 * real crypto pipeline — only the async network shape (latency, timeout,
 * retries, injectable failures) is simulated on top of it.
 */
export class RemoteSimulationProvider implements KeyProvider {
  readonly #keypair: KeyPair;
  readonly #latencyMs: number;
  readonly #timeoutMs: number;
  readonly #maxRetries: number;
  readonly #failureMode: RemoteFailureMode;
  readonly #failUntilAttempt: number;
  #attempts = 0;

  constructor(keypair: KeyPair, options: RemoteSimulationOptions = {}) {
    if (!validateKeyPair(keypair)) {
      throw new Error("invalid or mismatched Ed25519 key pair");
    }
    this.#keypair = keypair;
    this.#latencyMs = options.latencyMs ?? DEFAULT_LATENCY_MS;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.#failureMode = options.failureMode ?? "none";
    this.#failUntilAttempt = options.failUntilAttempt ?? Number.POSITIVE_INFINITY;
  }

  /**
   * Attempt count of the most recently *completed* call on this instance.
   * Each call tracks its own attempts locally and writes this field exactly
   * once, when it settles — so one call's in-progress retry loop can never
   * be reset or overwritten mid-flight by another concurrent call on the
   * same instance. Under concurrency this still reflects only whichever
   * call finished last, not a per-call-isolated count: it is a diagnostic
   * aid for sequential/test use, not a production observability primitive.
   * A real remote-provider client must not model retry counts as instance
   * state for exactly this reason.
   */
  get lastAttemptCount(): number {
    return this.#attempts;
  }

  getPublicKey(): Promise<string> {
    return this.#call(() => this.#keypair.publicKeyDer);
  }

  getKeyId(): Promise<string> {
    return this.#call(() => publicKeyId(this.#keypair.publicKeyDer));
  }

  sign(payload: Uint8Array): Promise<Uint8Array> {
    return this.#call(() => {
      const signature = signWithKeyPair(payload, this.#keypair);
      if (this.#failureMode !== "invalid-signature") {
        return signature;
      }
      const corrupted = Buffer.from(signature);
      corrupted[0] = corrupted[0]! ^ 0xff;
      return corrupted;
    });
  }

  async #call<T>(produce: () => T): Promise<T> {
    // `attempts` is local to this call, not shared instance state — a
    // concurrent call on the same provider cannot reset or corrupt it
    // mid-loop. `this.#attempts` is written exactly once, when this call
    // settles, from this call's own fully-accumulated count.
    let attempts = 0;
    let lastError: unknown;

    for (let attempt = 0; attempt <= this.#maxRetries; attempt++) {
      attempts += 1;
      try {
        const result = await this.#roundTrip(produce, attempts);
        this.#attempts = attempts;
        return result;
      } catch (error) {
        lastError = error;
        // A cancelled request models the caller giving up, not the
        // network failing — a real HTTP client does not retry that.
        if (this.#failureMode === "cancelled") {
          this.#attempts = attempts;
          throw error;
        }
      }
    }

    this.#attempts = attempts;
    throw lastError instanceof Error
      ? lastError
      : new Error("remote signing provider failed");
  }

  #roundTrip<T>(produce: () => T, attemptNumber: number): Promise<T> {
    // Only "timeout"/"provider-error" ever recover across attempts — a
    // transient remote failure that clears up by itself. "cancelled" and
    // "invalid-signature" are unaffected by failUntilAttempt: cancellation
    // is never retried (see #call), and invalid-signature corrupts the
    // successful round trip's payload rather than failing the round trip.
    const isRetryableFailureMode =
      this.#failureMode === "timeout" || this.#failureMode === "provider-error";
    const stillFailing = isRetryableFailureMode && attemptNumber <= this.#failUntilAttempt;

    const networkDelayMs =
      stillFailing && this.#failureMode === "timeout"
        ? this.#timeoutMs + this.#latencyMs
        : this.#latencyMs;

    return new Promise<T>((resolve, reject) => {
      let settled = false;

      const timeoutTimer = setTimeout(() => {
        if (settled) return;
        settled = true;
        clearTimeout(networkTimer);
        reject(new Error(`remote signing service timed out after ${this.#timeoutMs}ms`));
      }, this.#timeoutMs);

      const networkTimer = setTimeout(() => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutTimer);

        if (stillFailing && this.#failureMode === "provider-error") {
          reject(new Error("remote signing service returned an error"));
          return;
        }
        if (this.#failureMode === "cancelled") {
          reject(new Error("request cancelled before the remote signing service responded"));
          return;
        }
        try {
          resolve(produce());
        } catch (error) {
          reject(error);
        }
      }, networkDelayMs);
    });
  }
}
