import type { Json } from "../src/rpc.ts";

/**
 * Display helpers for strings from scanned accounts. They are rendered as
 * React text only, never as markup. Control and bidirectional formatting
 * characters are replaced, so a name cannot reorder or hide what follows it.
 */

// C0 and C1 controls, bidi embeddings, overrides and isolates, zero-width marks.
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching them is the point.
const INVISIBLE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

export function shown(value: string, max = 300): string {
  const clean = value.replace(INVISIBLE, "\ufffd");
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

/** An untrusted string, shortened, with the full value as a tooltip. */
export function Text({ value, max = 120 }: { value: string | null | undefined; max?: number }) {
  if (value === null || value === undefined || value === "")
    return <span className="muted">—</span>;
  const full = shown(value, 4000);
  const short = shown(value, max);
  return (
    <span className="untrusted" title={full === short ? undefined : full}>
      {short}
    </span>
  );
}

export function time(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  const date = new Date(ms);
  return Number.isNaN(date.getTime())
    ? "—"
    : `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

const MAX_ITEMS = 100;

/** Evidence and props: nested JSON as definition lists, every value as text. */
export function JsonView({ value, depth = 0 }: { value: Json | undefined; depth?: number }) {
  if (value === null || value === undefined) return <span className="muted">null</span>;
  if (typeof value === "string") return <Text value={value} max={500} />;
  if (typeof value === "number" || typeof value === "boolean") {
    return <span className="literal">{String(value)}</span>;
  }
  if (depth >= 6) return <span className="muted">…</span>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="muted">[]</span>;
    return (
      <ol className="json-list">
        {value.slice(0, MAX_ITEMS).map((item, i) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: list items have no identity of their own.
          <li key={i}>
            <JsonView value={item as Json} depth={depth + 1} />
          </li>
        ))}
        {value.length > MAX_ITEMS && <li className="muted">{value.length - MAX_ITEMS} more</li>}
      </ol>
    );
  }
  const entries = Object.entries(value as Record<string, Json>);
  if (entries.length === 0) return <span className="muted">{"{}"}</span>;
  return (
    <dl className="json-object">
      {entries.slice(0, MAX_ITEMS).map(([key, item]) => (
        <div key={key}>
          <dt>
            <Text value={key} max={80} />
          </dt>
          <dd>
            <JsonView value={item} depth={depth + 1} />
          </dd>
        </div>
      ))}
      {entries.length > MAX_ITEMS && <div className="muted">{entries.length - MAX_ITEMS} more</div>}
    </dl>
  );
}
