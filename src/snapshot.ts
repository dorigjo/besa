import { canonicalize } from "./crypto.js";

function freezeJson(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  for (const child of Object.values(value)) freezeJson(child);
  Object.freeze(value);
}

// Detach caller-owned data before any await; callbacks see only this snapshot.
export function snapshotJson<T>(value: T): T {
  const copy = JSON.parse(canonicalize(value)) as T;
  freezeJson(copy);
  return copy;
}
