// MULTI-OSINT-TOOL :: relationship graph. SVG only, no external libraries, no inline styles.
// Identity is carried by POSITION and a text LABEL (the sector name), never by colour alone. The one accent marks
// entities seen by two or more tools. A table of the same relationships is always shown beside the drawing.
import { h, svg, shorten, plural } from "./mot_dom.js";

const MAX_DRAWN = 48;
const RING = [170, 212];
const SECTOR_R = 254;
const ARC_R = 238;
const GAP = 0.075;
const TAU = Math.PI * 2;

const TYPE_NAME = {
  email: "Email", username: "Username", domain: "Domain", subdomain: "Subdomain", host: "Host", ip: "IP address", ips: "IP address",
  asn: "Network (ASN)", phone: "Phone", url: "Web address", onion: "Dark-web address", account: "Account", org: "Organisation",
  breach: "Breach", leak: "Leak", cve: "Vulnerability", service: "Service", subject: "Subject", hash: "Hash", commit: "Commit", password: "Password",
};
export const typeName = (t) => TYPE_NAME[t] || String(t || "other").replace(/_/g, " ");

const f1 = (n) => (Math.round(n * 10) / 10).toString();
const pt = (r, a) => [r * Math.cos(a), r * Math.sin(a)];
const srcCount = (n) => (Array.isArray(n.sources) ? n.sources.length : 0);

function arcPath(r, a0, a1) {
  const [x0, y0] = pt(r, a0);
  const [x1, y1] = pt(r, a1);
  const large = a1 - a0 > Math.PI ? 1 : 0;
  return `M${f1(x0)} ${f1(y0)} A${r} ${r} 0 ${large} 1 ${f1(x1)} ${f1(y1)}`;
}

function legendDot(kind) {
  return svg("svg", { viewBox: "-8 -8 16 16", class: "legend-dot " + kind, "aria-hidden": "true", focusable: "false" }, svg("circle", { r: "6" }));
}

/**
 * relationshipGraph(graph, {masked: Set("type|value"), showMasked, onPick(node, hidden)})
 * The graph is a star: the searched item (the node with no sources) in the centre, each entity on a ring.
 */
export function relationshipGraph(graph, opts = {}) {
  const masked = opts.masked instanceof Set ? opts.masked : new Set();
  const showMasked = !!opts.showMasked;
  const onPick = typeof opts.onPick === "function" ? opts.onPick : () => {};
  const nodes = Array.isArray(graph && graph.nodes) ? graph.nodes : [];
  const root = nodes.find((n) => srcCount(n) === 0) || null;
  const others = nodes.filter((n) => n !== root).sort((a, b) => srcCount(b) - srcCount(a) || (b.confidence || 0) - (a.confidence || 0));
  const drawn = others.slice(0, MAX_DRAWN);
  const notDrawn = others.length - drawn.length;
  const isMasked = (n) => !showMasked && masked.has(n.type + "|" + n.value);
  const labelFor = (n) => (isMasked(n) ? "hidden" : String(n.value));
  const quiet = drawn.length > 24;

  // one sector per entity type, sized by how many entities of that type are drawn
  const groups = new Map();
  for (const n of drawn) {
    if (!groups.has(n.type)) groups.set(n.type, []);
    groups.get(n.type).push(n);
  }
  const order = [...groups.entries()].sort((x, y) => y[1].length - x[1].length || String(x[0]).localeCompare(String(y[0])));
  const free = TAU - GAP * Math.max(order.length, 1);
  const pos = new Map();
  const sectors = [];
  let a = -Math.PI / 2 + GAP / 2;
  for (const [type, list] of order) {
    const span = drawn.length ? free * (list.length / drawn.length) : 0;
    list.forEach((n, i) => pos.set(n.id, { ang: a + span * ((i + 0.5) / list.length), r: RING[i % 2] }));
    sectors.push({ type, a0: a, a1: a + span, count: list.length });
    a += span + GAP;
  }

  const guides = RING.map((r) => svg("circle", { r: String(r), cx: "0", cy: "0", class: "g-ring" }));
  const arcs = [];
  for (const s of sectors) {
    arcs.push(svg("path", { d: arcPath(ARC_R, s.a0, s.a1), class: "g-sector-arc" }));
    const mid = (s.a0 + s.a1) / 2;
    const [x, y] = pt(SECTOR_R, mid);
    const c = Math.cos(mid);
    arcs.push(svg("text", { x: f1(x), y: f1(y), "text-anchor": c > 0.2 ? "start" : c < -0.2 ? "end" : "middle", class: "g-sector" },
      `${typeName(s.type).toUpperCase()} · ${s.count}`));
  }
  const edges = drawn.map((n) => {
    const p = pos.get(n.id);
    const [x, y] = pt(p.r, p.ang);
    return svg("line", { x1: "0", y1: "0", x2: f1(x), y2: f1(y), class: "g-edge" + (srcCount(n) >= 2 ? " hot" : "") });
  });

  let current = null;
  const pick = (n, el) => {
    if (current) current.classList.remove("sel");
    current = el;
    el.classList.add("sel");
    onPick(n, isMasked(n));
  };
  const bind = (g, n) => {
    g.addEventListener("click", () => pick(n, g));
    g.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        pick(n, g);
      }
    });
    return g;
  };

  const nodeEls = [];
  if (root) {
    const label = `Searched item: ${root.value}`;
    const g = svg("g", { class: "g-node root", tabindex: "0", role: "button", "aria-label": label },
      svg("title", {}, label),
      svg("circle", { r: "30", class: "g-root-halo" }),
      svg("circle", { r: "13", class: "g-hit" }),
      svg("circle", { r: "16" }),
      svg("text", { x: "0", y: "48", "text-anchor": "middle", class: "g-root-label" }, shorten(root.value, 26)));
    nodeEls.push(bind(g, { id: root.id, type: root.type, value: root.value, sources: [], relations: [], confidence: 1 }));
  }
  for (const n of drawn) {
    const p = pos.get(n.id);
    const multi = srcCount(n) >= 2;
    const hidden = isMasked(n);
    const [x, y] = pt(p.r, p.ang);
    const c = Math.cos(p.ang);
    const s = Math.sin(p.ang);
    const lx = f1(13 * c);
    const ly = f1(13 * s + (s > 0.5 ? 10 : s < -0.5 ? -4 : 4));
    const anchor = c > 0.2 ? "start" : c < -0.2 ? "end" : "middle";
    const label = `${typeName(n.type)}: ${labelFor(n)}. Seen by ${srcCount(n)} tool${srcCount(n) === 1 ? "" : "s"}.`;
    const g = svg("g", {
      class: "g-node" + (multi ? " multi" : "") + (quiet ? " quiet" : "") + (hidden ? " masked" : ""),
      transform: `translate(${f1(x)} ${f1(y)})`, tabindex: "0", role: "button", "aria-label": label, "data-id": String(n.id),
    }, svg("title", {}, label), svg("circle", { r: "13", class: "g-hit" }), svg("circle", { r: multi ? "7" : "5" }),
      svg("text", { x: lx, y: ly, "text-anchor": anchor }, shorten(labelFor(n), 18)));
    nodeEls.push(bind(g, n));
  }

  const svgEl = svg("svg", { viewBox: "-440 -440 880 880", class: "graph-svg", role: "group", "aria-label": "Relationship graph", focusable: "false" },
    ...guides, ...arcs, ...edges, ...nodeEls);
  const legend = h("div", { class: "legend graph-legend" },
    h("span", { class: "legend-item" }, legendDot("root"), "Searched item"),
    h("span", { class: "legend-item" }, legendDot("multi"), "Seen by two or more tools"),
    h("span", { class: "legend-item" }, legendDot("one"), "Seen by one tool"));
  const el = h("div", { class: "graph-wrap" }, legend, svgEl,
    h("p", { class: "graph-mobile-note small muted" }, "The drawing is for wider screens. The table below lists every relationship."),
    notDrawn > 0 ? h("p", { class: "small muted" }, `${plural(notDrawn, "more entity", "more entities")} not drawn here. The table lists all of them.`) : null);
  return { el, drawn: drawn.length, notDrawn };
}
