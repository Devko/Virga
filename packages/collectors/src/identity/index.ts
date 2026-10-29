import type { Collector } from "../types.ts";
import { accessCollector } from "./access.ts";
import { membersCollector } from "./members.ts";
import { tokensCollector } from "./tokens.ts";
import { tunnelsCollector } from "./tunnels.ts";

export type { Selector, SelectorKind } from "./selectors.ts";
export type { Target } from "./targets.ts";
export { accessCollector, membersCollector, tokensCollector, tunnelsCollector };

/** access, tunnels, tokens, members, insights, traffic. Owned by the identity collectors work package. */
export const IDENTITY_COLLECTORS: readonly Collector[] = [
  accessCollector,
  tunnelsCollector,
  tokensCollector,
  membersCollector,
];
