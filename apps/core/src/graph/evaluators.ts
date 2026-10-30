import { evaluateExposure } from "@virga/exposure";
import { type CompiledRule, evaluateRules, RULES } from "@virga/rules";
import { type AdvisorySource, NO_ADVISORY_FEED } from "./vulns.ts";

/** The derived steps a scan runs inside the graph object. Tests replace them. */
export interface Evaluators {
  exposure: typeof evaluateExposure;
  rules: typeof evaluateRules;
  ruleSet: readonly CompiledRule[];
  /** Advisories for the vulns step; none until the mirror exists (decision 0009). */
  advisories: AdvisorySource;
}

export const DEFAULT_EVALUATORS: Evaluators = {
  exposure: evaluateExposure,
  rules: evaluateRules,
  ruleSet: RULES,
  advisories: NO_ADVISORY_FEED,
};
