import { randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

export const MAX_ARTIFACT_BYTES = 1_048_576;

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
  try {
    return JSON.parse(readUtf8File(path)) as unknown;
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
  const temporaryPath = `${path}.${String(process.pid)}.${randomUUID()}.tmp`;
  let descriptor: number | undefined;

  try {
    descriptor = openSync(temporaryPath, "wx", mode);
    writeFileSync(descriptor, contents, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporaryPath, path);

    try {
      chmodSync(path, mode);
    } catch {
      // Windows does not apply POSIX modes; ACL custody remains operator-owned.
    }
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
}
