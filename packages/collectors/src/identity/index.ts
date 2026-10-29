import type { Collector } from "../types.ts";
import { accessCollector } from "./access.ts";

export type { Selector, SelectorKind } from "./selectors.ts";
export type { Target } from "./targets.ts";
export { accessCollector };

/** access, tunnels, tokens, members, insights, traffic. Owned by the identity collectors work package. */
export const IDENTITY_COLLECTORS: readonly Collector[] = [accessCollector];
