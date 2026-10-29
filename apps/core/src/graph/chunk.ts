import type { CollectorOutput } from "@virga/collectors";
import { type InsightRow, LIMITS, type SignalRow } from "@virga/graph";

// prepareBatch checks nodes and edges. Signals and insights carry strings
// from the scanned account too, so they get the same kind of limits here.
const NODE_ID_MAX = LIMITS.nativeId + 64;
const SIGNAL_NAME = /^[a-z][a-z0-9_]{0,63}$/;
const SIGNAL_VALUE_MAX = 1024;
const INSIGHT_FIELD_MAX = 256;
const encoder = new TextEncoder();

function text(value: unknown, max: number, what: string): string {
  if (typeof value !== "string" || value === "") throw new TypeError(`${what} must be a string`);
  if (value.length > max) throw new RangeError(`${what} longer than ${max} characters`);
  return value;
}

const optionalText = (value: unknown, max: number, what: string): string | null =>
  value === null || value === undefined ? null : text(value, max, what);

function checkSignal(signal: SignalRow): SignalRow {
  const value = signal.value;
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new TypeError("signal value must be finite");
  }
  if (typeof value === "string" && value.length > SIGNAL_VALUE_MAX) {
    throw new RangeError(`signal value longer than ${SIGNAL_VALUE_MAX} characters`);
  }
  if (value !== null && typeof value !== "number" && typeof value !== "string") {
    throw new TypeError("signal value must be a number, a string or null");
  }
  const name = text(signal.name, 64, "signal name");
  if (!SIGNAL_NAME.test(name)) throw new TypeError(`invalid signal name ${name}`);
  return { nodeId: text(signal.nodeId, NODE_ID_MAX, "signal nodeId"), name, value };
}

function checkInsight(insight: InsightRow): InsightRow {
  if (insight.payload === null || typeof insight.payload !== "object") {
    throw new TypeError("insight payload must be an object");
  }
  if (encoder.encode(JSON.stringify(insight.payload)).length > LIMITS.propsBytes) {
    throw new RangeError(`insight payload larger than ${LIMITS.propsBytes} bytes`);
  }
  return {
    id: text(insight.id, LIMITS.nativeId, "insight id"),
    type: text(insight.type, INSIGHT_FIELD_MAX, "insight type"),
    severity: optionalText(insight.severity, INSIGHT_FIELD_MAX, "insight severity"),
    subjectId: optionalText(insight.subjectId, NODE_ID_MAX, "insight subjectId"),
    payload: insight.payload,
  };
}

export interface CheckedOutput {
  output: CollectorOutput;
  signals: SignalRow[];
  insights: InsightRow[] | null;
}

/**
 * Validates one chunk of collector output before it is written. Insights
 * replace the whole table, so they are accepted only from a single-chunk
 * class: a later chunk would otherwise drop the rows of the earlier ones.
 */
export function checkOutput(output: CollectorOutput, singleChunk: boolean): CheckedOutput {
  if (!Array.isArray(output?.nodes) || !Array.isArray(output.edges)) {
    throw new TypeError("collector output must have nodes and edges arrays");
  }
  const signals = (output.signals ?? []).map(checkSignal);
  if (output.insights !== undefined && !singleChunk) {
    throw new TypeError("insights must come from a collector with a single chunk");
  }
  const insights = output.insights === undefined ? null : output.insights.map(checkInsight);
  return { output, signals, insights };
}
