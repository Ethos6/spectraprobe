import { randomBytes } from "node:crypto";

/** Short random id with a prefix, e.g. ev_3f9a2c, fn_71b0de. */
export function makeId(prefix: string): string {
  return `${prefix}_${randomBytes(4).toString("hex")}`;
}
