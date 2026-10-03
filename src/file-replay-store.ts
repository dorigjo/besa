import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { canonicalize, sha256Hex } from "./crypto.js";
import { REPLAY_REASON, type ReplayConsumeResult, type ReplayStore } from "./replay.js";

export interface FileReplayStoreOptions {
  durability?: "power-loss" | "process";
}

function checkDirectory(path: string): void {
  let current = path;
  for (;;) {
    const stat = lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("unsafe replay directory");
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function syncDirectory(path: string): void {
  const descriptor = openSync(path, "r");
  try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}

export class FileReplayStore implements ReplayStore {
  readonly mode = "enforced" as const;
  readonly directory: string;
  readonly durability: "power-loss" | "process";

  constructor(directory: string, options: FileReplayStoreOptions = {}) {
    if (typeof directory !== "string" || !directory.trim()) throw new TypeError("replay directory required");
    this.directory = resolve(directory);
    this.durability = options.durability ?? "power-loss";
    if (this.durability !== "power-loss" && this.durability !== "process") {
      throw new TypeError("unsupported replay durability");
    }
  }

  async consume(key: string, expiresAt: string, now = new Date()): Promise<ReplayConsumeResult> {
    const result = (status: ReplayConsumeResult["status"], reasonCode: string,
      detail: string): ReplayConsumeResult => ({ status, reasonCode, detail, enforced: true });
    if (typeof key !== "string" || !key.length || key.length > 512 ||
        typeof expiresAt !== "string" || !Number.isFinite(Date.parse(expiresAt)) ||
        new Date(expiresAt).toISOString() !== expiresAt || !(now instanceof Date) ||
        !Number.isFinite(now.getTime()) || Date.parse(expiresAt) <= now.getTime()) {
      return result("unavailable", REPLAY_REASON.INVALID, "invalid replay input");
    }
    let descriptor: number | undefined;
    try {
      // Provision this private directory on trusted local storage. Directory
      // replacement by a privileged local actor is outside this adapter's trust boundary.
      mkdirSync(this.directory, { recursive: true, mode: 0o700 });
      checkDirectory(this.directory);
      if (this.durability === "power-loss") {
        if (process.platform === "win32") throw new Error("directory sync unsupported on Windows");
        let directory = this.directory;
        for (;;) {
          syncDirectory(directory);
          const parent = dirname(directory);
          if (parent === directory) break;
          directory = parent;
        }
      }
      const digest = sha256Hex(`besa:file-replay-key:v1\0${key}`);
      const path = join(this.directory, `${digest}.json`);
      try { descriptor = openSync(path, "wx", 0o600); } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") {
          // Even an empty/partial claim is spent: crash recovery never retries an uncertain attempt.
          return result("replay", REPLAY_REASON.DETECTED, "replay key has already been consumed");
        }
        throw error;
      }
      writeFileSync(descriptor, `${canonicalize({ recordVersion: 1, keyDigest: digest,
        expiresAt, consumedAt: now.toISOString() })}\n`, "utf8");
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = undefined;
      if (this.durability === "power-loss") syncDirectory(this.directory);
      return result("consumed", REPLAY_REASON.CONSUMED, "replay claim persisted exclusively");
    } catch {
      return result("unavailable", REPLAY_REASON.UNAVAILABLE, "replay claim could not be committed");
    } finally {
      if (descriptor !== undefined) {
        try { closeSync(descriptor); } catch { /* A failed claim remains spent. */ }
      }
    }
  }
}
