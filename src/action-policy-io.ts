import { extname } from "node:path";
import { parse as parseYaml } from "yaml";
import { readUtf8File } from "./io.js";
import { validateActionPolicy, type ActionPolicyV1 } from "./action-policy.js";

export function loadActionPolicy(path: string): ActionPolicyV1 {
  const source = readUtf8File(path);
  const extension = extname(path).toLowerCase();
  let value: unknown;

  if (extension === ".json") {
    value = JSON.parse(source) as unknown;
  } else if (extension === ".yaml" || extension === ".yml") {
    value = parseYaml(source, {
      maxAliasCount: 50,
      strict: true,
      uniqueKeys: true,
    });
  } else {
    throw new Error("action policy path must end in .json, .yaml, or .yml");
  }

  const validation = validateActionPolicy(value);
  if (!validation.ok || !validation.policy) {
    throw new Error(`Invalid action policy:\n  - ${validation.errors.join("\n  - ")}`);
  }
  return validation.policy;
}
