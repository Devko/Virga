import cytoscape, { type ElementDefinition, type StylesheetJson } from "cytoscape";
import { useEffect, useRef } from "react";
import type { Neighborhood } from "../src/rpc.ts";
import { shown } from "./text.tsx";

/**
 * The graph neighborhood, drawn by Cytoscape on a canvas: labels from the
 * account are canvas text, never DOM markup.
 */

const ENTRY = new Set([
  "worker_route",
  "worker_custom_domain",
  "workers_dev",
  "worker_preview_url",
  "pages_domain",
  "pages_preview",
  "r2_public_domain",
  "tunnel_hostname",
]);
const CONTROL = new Set(["access_app", "access_policy", "access_group", "everyone"]);
const WORKLOAD = new Set(["worker_script", "worker_version", "pages_project", "tunnel"]);

function kind(type: string): string {
  if (ENTRY.has(type)) return "entry";
  if (CONTROL.has(type)) return "control";
  if (WORKLOAD.has(type)) return "workload";
  return "other";
}

const STYLE: StylesheetJson = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      "font-size": 10,
      "text-valign": "bottom",
      "text-margin-y": 4,
      "text-wrap": "ellipsis",
      "text-max-width": "140px",
      color: "#555",
      "background-color": "#8a99ad",
      width: 18,
      height: 18,
    },
  },
  { selector: "node.entry", style: { "background-color": "#d9822b", shape: "diamond" } },
  { selector: "node.control", style: { "background-color": "#3c8d5a", shape: "round-rectangle" } },
  { selector: "node.workload", style: { "background-color": "#4a6fa5" } },
  { selector: "node.root", style: { "border-width": 3, "border-color": "#c23030" } },
  {
    selector: "node.missing",
    style: { "background-opacity": 0.15, "border-width": 1, "border-style": "dashed" },
  },
  { selector: "node:selected", style: { "border-width": 3, "border-color": "#111" } },
  {
    selector: "edge",
    style: {
      label: "data(label)",
      "font-size": 8,
      color: "#777",
      width: 1.5,
      "line-color": "#b8c2cc",
      "target-arrow-color": "#b8c2cc",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "text-rotation": "autorotate",
    },
  },
];

const nodeKey = (id: string) => `n:${id}`;

export function graphElements(neighborhood: Neighborhood): ElementDefinition[] {
  const present = new Set<string>();
  const nodes: ElementDefinition[] = [];
  for (const node of neighborhood.nodes) {
    present.add(node.id);
    nodes.push({
      data: { id: nodeKey(node.id), ref: node.id, label: shown(node.name ?? node.nativeId, 40) },
      classes: [kind(node.type), node.id === neighborhood.root ? "root" : ""].join(" ").trim(),
    });
  }
  for (const id of neighborhood.missing) {
    if (present.has(id)) continue;
    present.add(id);
    nodes.push({
      data: { id: nodeKey(id), ref: id, label: shown(id, 40) },
      classes: `${kind(id.split(":")[0] ?? "")} missing`,
    });
  }
  const edges: ElementDefinition[] = neighborhood.edges
    .filter((e) => present.has(e.src) && present.has(e.dst))
    .map((e) => ({
      data: {
        id: `e:${e.id}`,
        source: nodeKey(e.src),
        target: nodeKey(e.dst),
        label: e.key ? `${e.type} ${shown(e.key, 24)}` : e.type,
      },
    }));
  return [...nodes, ...edges];
}

// Cytoscape adds a <style> element with this ID unless one exists; the CSP
// would block it, and the rule it carries is in styles.css.
function claimStylesheetId(): void {
  const id = "__________cytoscape_stylesheet";
  if (document.getElementById(id)) return;
  const marker = document.createElement("meta");
  marker.id = id;
  document.head.append(marker);
}

export function GraphView({
  neighborhood,
  onSelect,
}: {
  neighborhood: Neighborhood;
  onSelect: (nodeId: string) => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  const select = useRef(onSelect);
  select.current = onSelect;

  useEffect(() => {
    if (!container.current) return;
    claimStylesheetId();
    const cy = cytoscape({
      container: container.current,
      elements: graphElements(neighborhood),
      style: STYLE,
      layout: {
        name: "breadthfirst",
        directed: false,
        roots: [nodeKey(neighborhood.root)],
        spacingFactor: 1.2,
        padding: 20,
      },
      minZoom: 0.2,
      maxZoom: 3,
    });
    cy.on("tap", "node", (event) => select.current(String(event.target.data("ref"))));
    return () => cy.destroy();
  }, [neighborhood]);

  return <div ref={container} className="graph" role="img" aria-label="Graph neighborhood" />;
}
