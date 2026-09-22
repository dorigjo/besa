import { canonicalize, sha256Hex } from "./crypto.js";

export type ReplayStoreMode = "verification-only" | "enforced";
export type ReplayConsumeStatus =
  | "consumed"
  | "replay"
  | "not-enforced"
  | "unavailable";

export interface ReplayConsumeResult {
  status: ReplayConsumeStatus;
  reasonCode: string;
  detail: string;
  enforced: boolean;
}

export interface ReplayStore {
  readonly mode: ReplayStoreMode;
  consume(
    key: string,
    expiresAt: string,
    now?: Date,
  ): Promise<ReplayConsumeResult>;
}

export const REPLAY_REASON = {
  CONSUMED: "REPLAY_CONSUMED",
  DETECTED: "REPLAY_DETECTED",
  NOT_ENFORCED: "REPLAY_NOT_ENFORCED",
  UNAVAILABLE: "REPLAY_STORE_UNAVAILABLE",
  INVALID: "REPLAY_INPUT_INVALID",
} as const;

const HASH_PATTERN = /^[a-f0-9]{64}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

function isCanonicalTimestamp(value: string): boolean {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function validateConsumeInput(
  key: string,
  expiresAt: string,
  now: Date,
): ReplayConsumeResult | undefined {
  if (
    key.length === 0 ||
    key.length > 512 ||
    !isCanonicalTimestamp(expiresAt) ||
    !Number.isFinite(now.getTime()) ||
    Date.parse(expiresAt) <= now.getTime()
  ) {
    return {
      status: "unavailable",
      reasonCode: REPLAY_REASON.INVALID,
      detail: "replay key, expiry, or verification time is invalid",
      enforced: true,
    };
  }
  return undefined;
}

export function replayKey(actionHash: string, nonce: string): string {
  if (!HASH_PATTERN.test(actionHash)) {
    throw new TypeError("actionHash must be 64 lowercase hexadecimal characters");
  }
  if (!NONCE_PATTERN.test(nonce)) {
    throw new TypeError("nonce must be 16-128 base64url characters");
  }
  return sha256Hex(
    `besa:replay-key:v1\0${canonicalize({ actionHash, nonce })}`,
  );
}

export class VerificationOnlyReplayStore implements ReplayStore {
  readonly mode = "verification-only" as const;

  async consume(
    key: string,
    expiresAt: string,
    now = new Date(),
  ): Promise<ReplayConsumeResult> {
    const invalid = validateConsumeInput(key, expiresAt, now);
    if (invalid) return { ...invalid, enforced: false };
    return {
      status: "not-enforced",
      reasonCode: REPLAY_REASON.NOT_ENFORCED,
      detail: "nonce is cryptographically bound but one-time use is not enforced",
      enforced: false,
    };
  }
}

export interface InMemoryReplayStoreOptions {
  maxEntries?: number;
}

export class InMemoryReplayStore implements ReplayStore {
  readonly mode = "enforced" as const;
  readonly #maxEntries: number;
  readonly #entries = new Map<string, number>();

  constructor(options: InMemoryReplayStoreOptions = {}) {
    const maxEntries = options.maxEntries ?? 10_000;
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 1_000_000) {
      throw new TypeError("maxEntries must be an integer between 1 and 1000000");
    }
    this.#maxEntries = maxEntries;
  }

  async consume(
    key: string,
    expiresAt: string,
    now = new Date(),
  ): Promise<ReplayConsumeResult> {
    const invalid = validateConsumeInput(key, expiresAt, now);
    if (invalid) return invalid;

    const nowMs = now.getTime();
    for (const [storedKey, expiry] of this.#entries) {
      if (expiry <= nowMs) this.#entries.delete(storedKey);
    }

    if (this.#entries.has(key)) {
      return {
        status: "replay",
        reasonCode: REPLAY_REASON.DETECTED,
        detail: "replay key has already been consumed",
        enforced: true,
      };
    }
    if (this.#entries.size >= this.#maxEntries) {
      return {
        status: "unavailable",
        reasonCode: REPLAY_REASON.UNAVAILABLE,
        detail: "replay store capacity is exhausted",
        enforced: true,
      };
    }

    this.#entries.set(key, Date.parse(expiresAt));
    return {
      status: "consumed",
      reasonCode: REPLAY_REASON.CONSUMED,
      detail: "replay key was atomically consumed",
      enforced: true,
    };
  }
}
