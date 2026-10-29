import { evaluateExposure } from "@virga/exposure";
import { type CompiledRule, evaluateRules, RULES } from "@virga/rules";

/** The derived steps a scan runs inside the graph object. Tests replace them. */
export interface Evaluators {
  exposure: typeof evaluateExposure;
  rules: typeof evaluateRules;
  ruleSet: readonly CompiledRule[];
}

export const DEFAULT_EVALUATORS: Evaluators = {
  exposure: evaluateExposure,
  rules: evaluateRules,
  ruleSet: RULES,
};
