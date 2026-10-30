export const TOOLS = ["osv-scanner", "trivy", "gitleaks"] as const;
export type Tool = (typeof TOOLS)[number];

/** Why a report was rejected. A rejected report is never partly used. */
export const REJECTION_REASONS = [
  /** The report is larger than `maxBytes`. */
  "too_large",
  /** Not UTF-8 (bytes), or a lone surrogate in the text (string). */
  "invalid_encoding",
  /** Not JSON as RFC 8259 defines it, a byte order mark or trailing data included. */
  "invalid_json",
  "too_deep",
  "too_many_values",
  /** An array, or a list in the normalized result, has more items than allowed. */
  "too_many_items",
  "too_many_keys",
  "string_too_long",
  "number_out_of_range",
  "duplicate_key",
  "wrong_type",
  "missing_field",
  /** A string with a control character, a lone surrogate or a bidi control. */
  "invalid_text",
  /** A string that breaks its pattern (ID, purl, label, severity). */
  "invalid_format",
  "unsupported_version",
  "out_of_range",
  /** A kept field contains the secret of its finding, or a Cloudflare token. */
  "secret_in_kept_field",
] as const;
export type RejectionReason = (typeof REJECTION_REASONS)[number];

/**
 * The only error a reader throws for bad input. The message names the tool,
 * the reason and where: a JSON pointer built from Virga's own field names and
 * array indices, or a character offset. It never quotes the input, so neither
 * a secret nor a hostile string can travel in it.
 */
export class ScannerOutputRejected extends Error {
  override readonly name = "ScannerOutputRejected";
  readonly tool: Tool;
  readonly reason: RejectionReason;
  readonly at: string;

  constructor(tool: Tool, reason: RejectionReason, at: string) {
    super(`${tool} output rejected: ${reason} at ${at}`);
    this.tool = tool;
    this.reason = reason;
    this.at = at;
  }
}
