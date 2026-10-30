/**
 * Reader for the gitleaks JSON report (`gitleaks dir|git --report-format json`).
 *
 * Format followed: gitleaks 8, an array of findings as in `report.Finding`
 * (`RuleID`, `File`, `StartLine`, `EndLine`, `Secret`, `Match`, and since
 * 8.19 `Line`). Written from the documentation and the finding type, not
 * yet checked against captured output (S-07).
 *
 * `Secret` is read once, to find a known prefix, and then dropped. `Match`
 * and `Line` also hold the secret and are never read. The result keeps the
 * rule ID, the file, the lines, the prefix and a fixed mask.
 */

import { Fields } from "./fields.ts";
import { parseJson } from "./json.ts";
import { resolveLimits } from "./limits.ts";
import { type ReaderOptions, ReportBuilder, type ScanReport } from "./report.ts";
import { holdsSecretPiece, maskSecret, secretBody } from "./secrets.ts";
import { FIELD_LIMITS, RULE_ID } from "./text.ts";

const TOOL = "gitleaks";

export function readGitleaks(input: string | Uint8Array, options: ReaderOptions = {}): ScanReport {
  const limits = resolveLimits(options.limits);
  const f = new Fields(TOOL);
  const findings = f.array(parseJson(input, limits, TOOL), "", limits.maxSecrets);
  const out = new ReportBuilder(TOOL, limits, f);
  findings.forEach((value, i) => {
    const at = `/${i}`;
    const finding = f.object(value, at);
    const ruleId = f.matching(
      f.string(finding, "RuleID", at),
      `${at}/RuleID`,
      RULE_ID,
      FIELD_LIMITS.ruleId,
    );
    const file = f.text(f.string(finding, "File", at), `${at}/File`, FIELD_LIMITS.path, true);
    const line = f.integer(finding, "StartLine", at);
    const endLine = f.integer(finding, "EndLine", at);
    if (endLine < line) f.fail("out_of_range", `${at}/EndLine`);
    // The only read of the secret. It goes out of scope with this callback.
    const secret = f.string(finding, "Secret", at);
    const { prefix, masked } = maskSecret(secret);
    // A file or rule named after the secret, or after six characters of
    // it, would carry it out.
    const body = secretBody(secret, prefix);
    if (body !== null && (holdsSecretPiece(file, body) || holdsSecretPiece(ruleId, body))) {
      f.fail("secret_in_kept_field", at);
    }
    out.addSecret({ ruleId, file, line, endLine, prefix, masked });
  });
  return out.build();
}
