/**
 * A value that came from a scanned account: names, native IDs, props,
 * evidence and API error text. Escape it before display and never treat it
 * as markup, code or instructions (UI, MCP, logs). The brand exists only in
 * types; it has a string key because RPC types drop symbol-keyed members.
 */
export type Untrusted<T> = T & { readonly __untrusted: true };

export const untrusted = <T>(value: T): Untrusted<T> => value as Untrusted<T>;

/**
 * A JSON value. Nested values are typed `object` because RPC types reject
 * `unknown` and do not terminate on a recursive JSON type.
 */
export type Json = string | number | boolean | null | object;
export type JsonRecord = { [key: string]: Json };
