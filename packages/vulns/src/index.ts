export { cvss3BaseScore, rankOfScore } from "./cvss.ts";
export {
  isKnownExploited,
  KEV_LIMITS,
  type KevCatalog,
  type KevResult,
  readKevCatalog,
} from "./kev.ts";
export { type AdvisoryMatch, type Decision, evaluateRange, matchAdvisory } from "./match.ts";
export {
  type AdvisoryFeed,
  type NpmAffected,
  OSV_LIMITS,
  OSV_SCHEMA_VERSION,
  type OsvAdvisory,
  type OsvEvent,
  type OsvRange,
  type OsvRecordResult,
  type OsvSeverity,
  readOsvFeed,
  readOsvRecord,
} from "./osv.ts";
export { type NpmPurl, npmNameKey, parseNpmPurl } from "./purl.ts";
export {
  type RematchInput,
  type RematchResult,
  rematch,
  type UnknownMatch,
  type UnparsedPackage,
} from "./rematch.ts";
export { compareSemver, parseSemver, type SemVer } from "./semver.ts";
export {
  isMaliciousPackageAdvisory,
  MALICIOUS_ID_PREFIX,
  type SeverityRank,
  severityRank,
} from "./severity.ts";
