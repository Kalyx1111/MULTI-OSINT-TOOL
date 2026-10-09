// MULTI-OSINT-TOOL :: guilloche rosette and the 20-position dial (pure SVG, no external resources).
// The rosette is drawn once as an SVG <symbol> and re-used with <use>, so a page full of them costs one set of paths.
import { h, svg } from "./mot_dom.js";

const TAU = Math.PI * 2;
const f1 = (n) => (Math.round(n * 10) / 10).toString();

/** Closed curve r(phi) = rho + amp * sin(m * phi + shift), rotated by `rot`; engraved "wave" line. */
function waveCurve(rho, amp, m, shift, rot, steps) {
  let d = "";
  for (let i = 0; i <= steps; i++) {
    const phi = (i / steps) * TAU;
    const r = rho + amp * Math.sin(m * phi + shift);
    const a = phi + rot;
    d += (i === 0 ? "M" : "L") + f1(r * Math.cos(a)) + " " + f1(r * Math.sin(a));
  }
  return d + "Z";
}

/**
 * Engine-turned rosette, built the way a rose engine cuts it: a family of circles whose centres walk around a small ring
 * (the woven "basket" at the heart of a banknote medallion), edged by a fine wave ribbon. Radii are in a 0..R space.
 * Returns plain descriptions; ensureRosetteSymbol() turns them into SVG once.
 */
export function rosetteShapes(R = 250) {
  const out = [];
  const N = 48;
  for (let k = 0; k < N; k++) {
    const a = (k / N) * TAU;
    out.push({ circle: [f1(R * 0.3 * Math.cos(a)), f1(R * 0.3 * Math.sin(a)), f1(R * 0.6)], cls: "ro-a" });
  }
  for (let k = 0; k < 18; k++) out.push({ d: waveCurve(R * 0.78, R * 0.05, 36, 0, (k / 18) * (TAU / 36), 360), cls: "ro-b" });
  for (let k = 0; k < 10; k++) out.push({ d: waveCurve(R * 0.955, R * 0.03, 90, 0, (k / 10) * (TAU / 90), 450), cls: "ro-c" });
  return out;
}

let symbolMade = false;

/** Adds the shared <symbol id="mot-rosette"> to a hidden <svg> once per document. */
export function ensureRosetteSymbol() {
  if (symbolMade || document.getElementById("mot-rosette")) return;
  const R = 250;
  const sym = svg("symbol", { id: "mot-rosette", viewBox: `${-R - 4} ${-R - 4} ${2 * R + 8} ${2 * R + 8}` },
    ...rosetteShapes(R).map((p) => (p.circle ? svg("circle", { cx: p.circle[0], cy: p.circle[1], r: p.circle[2], class: p.cls }) : svg("path", { d: p.d, class: p.cls }))));
  const holder = svg("svg", { width: "0", height: "0", "aria-hidden": "true", focusable: "false", class: "mot-defs" }, svg("defs", {}, sym));
  document.body.prepend(holder);
  symbolMade = true;
}

/** A free-standing rosette (watermark, brand mark, vault door). */
export function rosette(className = "") {
  ensureRosetteSymbol();
  return svg("svg", { viewBox: "-254 -254 508 508", class: "rosette " + className, "aria-hidden": "true", focusable: "false" },
    svg("use", { href: "#mot-rosette", x: "-254", y: "-254", width: "508", height: "508" }));
}

/** Small brand mark: five engraved loops inside a ring. Drawn directly (it is tiny). */
export function brandMark() {
  const paths = [];
  for (let k = 0; k < 9; k++) paths.push(svg("path", { d: waveCurve(8.2, 2.6, 5, 0, (k / 9) * (TAU / 5), 120), class: "bm-line" }));
  return svg("svg", { viewBox: "-13 -13 26 26", class: "brand-mark", "aria-hidden": "true", focusable: "false" },
    svg("circle", { r: "11.6", class: "bm-ring" }), ...paths);
}

// -------------------------------------------------------------------------------------------- the dial
export const JEWEL_ORDER = ["sherlock", "maltego", "shodan", "spiderfoot", "dehashed", "hibp", "pimeyes", "epieos", "hunter",
  "intelx", "virustotal", "urlscan", "github", "hudsonrock", "wayback", "maigret", "holehe", "theharvester", "phoneinfoga", "ahmia"];

const STATUS_LOOK = {
  ok: "found", empty: "none",
  no_key: "attn", key_invalid: "attn", plan_limit: "attn", rate_limited: "attn", missing_tool: "attn", skipped: "attn", offline: "attn", unsupported: "attn",
  error: "fail", timeout: "fail", blocked: "fail",
  handoff: "manual", export: "manual", cancelled: "cancel",
};

export function jewelLook(entry) {
  if (!entry || entry.na) return "na";
  if (entry.state === "running") return "running";
  if (entry.state !== "done") return "queued";
  return STATUS_LOOK[entry.status] || "none";
}

/**
 * The dial: 20 fixed positions around an engraved rosette. `names` maps connector id -> display name.
 * The rosette turns slowly (a separate layer, so only that layer is animated) while a search runs; the jewels never move.
 * dial.update({id: {na, state, status, label}}) at any time; dial.setCentre(big, small, smaller) sets the text in the middle.
 */
export function createDial(names, order = JEWEL_ORDER) {
  const RJ = 292; // radius of the jewel ring
  const ticks = [];
  for (let i = 0; i < 100; i++) {
    const a = (i / 100) * TAU - Math.PI / 2;
    const major = i % 5 === 0;
    const r1 = major ? 313 : 316, r2 = 322;
    ticks.push(svg("line", { x1: f1(r1 * Math.cos(a)), y1: f1(r1 * Math.sin(a)), x2: f1(r2 * Math.cos(a)), y2: f1(r2 * Math.sin(a)), class: major ? "tick major" : "tick" }));
  }
  const jewels = new Map();
  const ring = order.map((id, i) => {
    const a = (i / order.length) * TAU - Math.PI / 2;
    const cx = RJ * Math.cos(a), cy = RJ * Math.sin(a);
    const g = svg("g", { class: "jewel look-na", transform: `translate(${f1(cx)} ${f1(cy)})`, "data-tool": id },
      svg("title", {}, names[id] || id),
      svg("circle", { r: "18", class: "j-hit" }),
      svg("circle", { r: "10", class: "j-ring" }),
      svg("path", { d: "M-10 0 A10 10 0 0 1 0 -10", class: "j-arc" }),
      svg("circle", { r: "5.5", class: "j-core" }),
      svg("circle", { r: "2.6", class: "j-dot" }),
      svg("rect", { x: "-6.5", y: "-6.5", width: "13", height: "13", class: "j-diamond", transform: "rotate(45)" }),
      svg("path", { d: "M-6 6 L6 -6", class: "j-slash" }),
      svg("path", { d: "M-4.5 -4.5 L4.5 4.5 M4.5 -4.5 L-4.5 4.5", class: "j-cross" }));
    jewels.set(id, g);
    return g;
  });
  const big = svg("text", { class: "dc-big", x: "0", y: "16", "text-anchor": "middle" }, "–");
  const sub = svg("text", { class: "dc-sub", x: "0", y: "58", "text-anchor": "middle" }, "");
  const sub2 = svg("text", { class: "dc-sub2", x: "0", y: "86", "text-anchor": "middle" }, "");
  const face = svg("svg", { viewBox: "-340 -340 680 680", class: "dial", role: "img", "aria-label": "Status of the twenty tools" },
    svg("circle", { r: "326", class: "dial-bezel" }), svg("circle", { r: "264", class: "dial-inner" }), ...ticks,
    svg("circle", { r: "118", class: "dial-hub" }), ...ring, svg("g", { class: "dial-centre" }, big, sub, sub2));
  ensureRosetteSymbol();
  const rose = svg("svg", { viewBox: "-254 -254 508 508", class: "dial-rosette", "aria-hidden": "true", focusable: "false" },
    svg("use", { href: "#mot-rosette", x: "-254", y: "-254", width: "508", height: "508" }));
  const wrap = h("div", { class: "dial-wrap" }, rose, face);
  return {
    el: wrap,
    face,
    jewels,
    update(map) {
      for (const [id, g] of jewels) {
        const e = map[id];
        g.setAttribute("class", "jewel look-" + jewelLook(e));
        const name = names[id] || id;
        g.querySelector("title").textContent = e && e.label ? `${name}: ${e.label}` : e && !e.na ? `${name}: ${e.state === "done" ? e.status : e.state}` : `${name}: not used for this search`;
      }
    },
    setCentre(a, b = "", c = "") {
      big.textContent = a;
      sub.textContent = b;
      sub2.textContent = c;
    },
    setBusy(on) {
      wrap.classList.toggle("is-busy", !!on);
    },
    wake() {
      let n = 0;
      for (const g of jewels.values()) {
        g.style.setProperty("--wake", `${n++ * 38}ms`);
        g.classList.remove("waking");
        void g.getBoundingClientRect();
        g.classList.add("waking");
      }
    },
  };
}
