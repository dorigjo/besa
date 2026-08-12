import { randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

export const MAX_ARTIFACT_BYTES = 1_048_576;

function rejectSymlink(path: string): void {
  // Fail closed if the final path is already a symlink: an atomic rename or
  // exclusive create must never be redirected through an attacker-planted link.
  let stats;
  try {
    stats = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }

  if (stats.isSymbolicLink()) {
    throw new Error(`refusing to write through symlink at ${path}`);
  }
}

function sleepMs(milliseconds: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function renameReplace(from: string, to: string): void {
  // The rename is the atomic replace. On Windows, MoveFileEx transiently fails
  // with EPERM/EACCES/EBUSY when a virus scanner, search indexer, or filesystem
  // filter holds a short-lived handle on the destination it just watched being
  // created — a single-writer OS artifact, not write contention (callers such as
  // the meter serialize writes behind a lock). We retry the same atomic replace
  // a bounded number of times; this preserves atomicity and never widens any
  // window in which a partial file is observable. Non-Windows renames once and
  // surfaces any error immediately. This mirrors Node's own fs.rm retry policy.
  if (process.platform !== "win32") {
    renameSync(from, to);
    return;
  }

  const maxAttempts = 10;
  const backoffMs = 10;

  for (let attempt = 1; ; attempt += 1) {
    try {
      renameSync(from, to);
      return;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      const transient =
        code === "EPERM" || code === "EACCES" || code === "EBUSY";

      if (!transient || attempt >= maxAttempts) {
        throw error;
      }

      sleepMs(backoffMs);
    }
  }
}

function fsyncParentDirectory(path: string): void {
  // Durably persist the directory entry after rename/create. Directory fsync is
  // a POSIX durability guarantee; Windows cannot fsync a directory handle, so
  // any failure here is a best-effort no-op rather than a hard error.
  let descriptor: number | undefined;
  try {
    descriptor = openSync(dirname(path), "r");
    fsyncSync(descriptor);
  } catch {
    // Platform does not support directory fsync; skip silently.
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // Directory handle already gone; nothing to clean up.
      }
    }
  }
}

export function readUtf8File(
  path: string,
  maximumBytes = MAX_ARTIFACT_BYTES,
): string {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
    throw new TypeError("maximumBytes must be a positive safe integer");
  }

  const descriptor = openSync(path, "r");

  try {
    if (!fstatSync(descriptor).isFile()) {
      throw new Error(`refusing to read non-regular file at ${path}`);
    }

    const buffer = Buffer.allocUnsafe(maximumBytes + 1);
    let total = 0;

    while (total <= maximumBytes) {
      const count = readSync(
        descriptor,
        buffer,
        total,
        maximumBytes + 1 - total,
        null,
      );
      if (count === 0) break;
      total += count;
    }

    if (total > maximumBytes) {
      throw new Error(
        `file at ${path} exceeds the ${String(maximumBytes)} byte limit`,
      );
    }

    return new TextDecoder("utf-8", { fatal: true }).decode(
      buffer.subarray(0, total),
    );
  } finally {
    closeSync(descriptor);
  }
}

export function readJsonFile(path: string): unknown {
  // Read and parse are separate try/catch blocks so a missing file, a
  // permission error, or an oversized/non-regular file surfaces with its
  // own already-clear message instead of being mislabeled "invalid JSON" —
  // a caller hitting ENOENT should be told the file doesn't exist, not
  // sent looking for a JSON syntax error that isn't there.
  const contents = readUtf8File(path);

  try {
    return JSON.parse(contents) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`invalid JSON at ${path}: ${message}`);
  }
}

export function writeJsonAtomic(
  path: string,
  value: unknown,
  mode = 0o600,
): void {
  const contents = JSON.stringify(value, null, 2) + "\n";

  if (Buffer.byteLength(contents, "utf8") > MAX_ARTIFACT_BYTES) {
    throw new Error(`refusing to write oversized JSON artifact at ${path}`);
  }

  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  rejectSymlink(path);
  const temporaryPath = `${path}.${String(process.pid)}.${randomUUID()}.tmp`;
  let descriptor: number | undefined;

  try {
    descriptor = openSync(temporaryPath, "wx", mode);
    writeFileSync(descriptor, contents, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameReplace(temporaryPath, path);

    try {
      chmodSync(path, mode);
    } catch {
      // Windows does not apply POSIX modes; ACL custody remains operator-owned.
    }

    fsyncParentDirectory(path);
  } finally {
    if (descriptor !== undefined) {
      closeSync(descriptor);
    }
    if (existsSync(temporaryPath)) {
      unlinkSync(temporaryPath);
    }
  }
}

export function writeJsonExclusive(
  path: string,
  value: unknown,
  mode = 0o600,
): void {
  const contents = JSON.stringify(value, null, 2) + "\n";

  if (Buffer.byteLength(contents, "utf8") > MAX_ARTIFACT_BYTES) {
    throw new Error(`refusing to write oversized JSON artifact at ${path}`);
  }

  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  rejectSymlink(path);
  const descriptor = openSync(path, "wx", mode);
  let complete = false;

  try {
    writeFileSync(descriptor, contents, "utf8");
    fsyncSync(descriptor);
    complete = true;
  } finally {
    closeSync(descriptor);
    if (!complete && existsSync(path)) {
      unlinkSync(path);
    }
  }

  try {
    chmodSync(path, mode);
  } catch {
    if (process.platform !== "win32") throw new Error(`cannot protect ${path}`);
  }

  fsyncParentDirectory(path);
}
