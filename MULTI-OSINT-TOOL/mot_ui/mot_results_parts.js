// MULTI-OSINT-TOOL :: parts of the results screen (findings, tools, relationships, notes).
// Every string from a tool is shown as a text node. URLs are shown as inert text with a copy button, never as links.
// Sensitive records stay hidden until the person asks for them; secret values exist only while they are on screen.
import { h, icon, shorten, plural, fmtNum, secs } from "./mot_dom.js";
import * as api from "./mot_api.js";
import { statusChip, statusInfo, modeChip, chip, confidenceMeter, copyButton, button, emptyState, switchEl, textInput, field, confirmBox, toast, reportError, banner, uid, withBusy } from "./mot_ui.js";
import { relationshipGraph, typeName } from "./mot_graph.js";

export const LEVEL = { low: "Low", moderate: "Moderate", high: "High", critical: "Critical" };
export const CAP = 120; // rows per group before "Show more", so a huge result set stays responsive

// Finding kinds the connectors produce, grouped for reading. Anything unknown lands in "Other".
export const GROUPS = [
  { id: "breach", label: "Breaches, leaks and credentials", ic: "database", kinds: ["breach", "leak", "credential", "password_exposure", "paste", "infostealer", "darkweb"] },
  { id: "identity", label: "Accounts and identities", ic: "user", kinds: ["account", "email", "email_check", "phone", "org", "osint", "recon", "person"] },
  { id: "infra", label: "Domains, hosts and services", ic: "network", kinds: ["domain", "subdomain", "subdomains", "host", "ip", "ips", "asn", "service", "scan", "vuln", "cve", "archive", "url", "risk"] },
  { id: "reputation", label: "Reputation and code", ic: "shield", kinds: ["reputation", "commit", "hash"] },
];
const KIND_GROUP = new Map(GROUPS.flatMap((g) => g.kinds.map((k) => [k, g.id])));
export const groupOf = (kind) => KIND_GROUP.get(kind) || "other";
const KIND_LABEL = { breach: "Breach", leak: "Leak", credential: "Credential", password_exposure: "Password exposure", paste: "Paste", infostealer: "Infostealer", darkweb: "Dark web",
  account: "Account", email: "Email", email_check: "Email check", phone: "Phone", org: "Organisation", osint: "Open source", recon: "Recon", domain: "Domain", subdomain: "Subdomain",
  subdomains: "Subdomains", host: "Host", ip: "IP address", ips: "IP addresses", asn: "Network (ASN)", service: "Service", scan: "Scan", vuln: "Vulnerability", cve: "CVE",
  archive: "Archived page", url: "Web address", risk: "Risk", reputation: "Reputation", commit: "Commit", hash: "Hash" };
export const kindLabel = (k) => KIND_LABEL[k] || String(k || "finding").replace(/_/g, " ");

// Mirrors the server's normalisation (mot_correlate.norm_entity) so a masked entity is recognised in the graph.
const CASEFOLD = new Set(["email", "domain", "hostname", "ip", "onion", "hash", "url_host"]);
export function normEntity(type, value) {
  const v = String(value ?? "").trim().slice(0, 300);
  return CASEFOLD.has(type) ? v.toLowerCase().replace(/\.+$/, "") : v;
}

/** Entities that appear only in sensitive findings the person has not opened. Shared with the graph. */
export function maskedKeys(results, maskOn, shown) {
  const visible = new Set();
  const hidden = new Set();
  for (const r of results.values()) {
    for (const f of r.findings || []) {
      const isHidden = maskOn && f.sensitive && !shown.has(f.fid);
      for (const e of f.ents || []) {
        const key = e[0] + "|" + normEntity(e[0], e[1]);
        if (isHidden) hidden.add(key);
        else visible.add(key);
      }
    }
  }
  for (const k of visible) hidden.delete(k);
  return hidden;
}

/** Key/value pairs from a finding's data. Nested values become short readable text; secrets never reach this point. */
export function dataPairs(data) {
  const out = [];
  for (const [k, v] of Object.entries(data || {})) {
    if (String(k).startsWith("_") || v === null || v === undefined || v === "") continue;
    let text;
    if (Array.isArray(v)) text = v.slice(0, 12).map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(", ");
    else if (typeof v === "object") text = JSON.stringify(v);
    else text = String(v);
    out.push([String(k).replace(/_/g, " "), shorten(text, 400)]);
  }
  return out;
}

const relLabel = (r) => String(r || "related").replace(/_/g, " ");

function kvBlock(pairs) {
  const dl = h("dl", { class: "kv" });
  for (const [k, v] of pairs) {
    if (v === null || v === undefined || v === "") continue;
    dl.appendChild(h("dt", {}, k));
    dl.appendChild(h("dd", { class: "wrap-any" }, v));
  }
  return dl;
}

/** One finding row. `c` supplies the state and the actions; the row itself holds no state. */
function findingRow(f, r, c) {
  const isHidden = c.U.maskOn && f.sensitive && !c.U.shown.has(f.fid);
  const hasSecret = !!f.has_secret;
  const secret = c.U.secrets.get(f.fid);
  const meta = [h("span", { class: "chip tone-mute" }, kindLabel(f.kind)), h("span", { class: "src", title: "Tool that returned this" }, c.names[r.connector] || r.connector)];
  if (f.mode) meta.push(modeChip(f.mode));
  if (f.sensitive) meta.push(chip(isHidden ? "Sensitive, hidden" : "Sensitive", "warn", "shieldWarn"));
  if (hasSecret) meta.push(chip("Holds a secret", "bad", "key"));
  const head = isHidden
    ? h("div", { class: "finding-title muted" }, "Sensitive record hidden")
    : h("div", { class: "finding-title" }, shorten(f.title || f.value || kindLabel(f.kind), 220));
  const sub = !isHidden && f.value ? h("div", { class: "finding-sub mono" }, shorten(f.value, 200)) : null;
  const actions = h("div", { class: "cluster-s" });
  if (f.sensitive) {
    actions.appendChild(button({ label: isHidden ? "Show record" : "Hide record", kind: "quiet", small: true, ic: isHidden ? "eye" : "eyeOff",
      onClick: () => c.toggleShown(f.fid) }));
  }
  if (hasSecret && c.canReveal) {
    actions.appendChild(button({ label: secret ? "Hide secret" : "Reveal secret", kind: "quiet", small: true, ic: "key",
      onClick: () => (secret ? c.hideSecret(f.fid) : c.reveal(f)) }));
  }
  const body = [];
  if (hasSecret && !c.canReveal) body.push(h("p", { class: "small muted" }, "Passwords and tokens are not stored with a case. Run the search again to reveal them."));
  if (secret) {
    const left = Math.max(0, Math.ceil((secret.expires - Date.now()) / 1000));
    body.push(h("div", { class: "secret-box", role: "status" },
      h("span", { class: "tiny muted" }, `Shown for one minute (${left} s left), then removed. Never saved.`),
      kvBlock(Object.entries(secret.data).map(([k, v]) => [k, String(v)]))));
  }
  if (!isHidden && f.url) body.push(h("div", { class: "finding-url" }, icon("link", "s"), h("span", { class: "mono wrap-any" }, shorten(f.url, 300)), copyButton(f.url, "Copy address")));
  if (!isHidden) {
    const pairs = dataPairs(f.data);
    if (pairs.length) body.push(h("details", { class: "disclose" }, h("summary", {}, icon("chevronRight", "s"), `Details (${pairs.length})`), h("div", { class: "disclose-body" }, kvBlock(pairs))));
  }
  return h("article", { class: "finding", "data-fid": f.fid },
    h("div", { class: "stack-s" }, head, sub),
    h("div", { class: "cluster-s", title: "How many tools agree" }, f.confidence !== undefined ? confidenceMeter(f.confidence) : null),
    h("div", { class: "finding-meta" }, meta),
    actions.childNodes.length ? h("div", { class: "finding-meta" }, actions) : null,
    body.length ? h("div", { class: "finding-data stack-s" }, body) : null);
}

// ------------------------------------------------------------------------------------------------ findings tab
/**
 * findingsView(c) -> {el, paint}. The filter box and source buttons live outside the list, so typing never loses focus
 * when the list is repainted during a search. `c` = {M, U, names, canReveal, toggleShown(fid), reveal(f), hideSecret(fid), repaint()}.
 */
export function findingsView(c) {
  const filter = textInput({ id: uid("filter"), placeholder: "Name, address, source or detail…", maxlength: 200, onInput: (v) => {
    c.U.q = v.trim().toLowerCase();
    paintList();
  } });
  filter.value = c.U.q;
  const sources = h("div", { class: "srcfilter", role: "group", "aria-label": "Filter by tool" });
  const list = h("div", { class: "stack-l" });
  const note = h("p", { class: "small muted" }, "Sensitive records stay hidden until you open them. The default is set in ",
    h("a", { href: "#/settings" }, "Settings"), ".");
  const el = h("div", { class: "stack" },
    h("div", { class: "filterbar" }, h("label", { class: "sr-only", for: filter.id }, "Filter findings"), filter, h("span", { class: "small muted", "aria-live": "polite", id: "fcount" })),
    sources, note, list);

  function matches(f, r) {
    if (!c.U.q) return true;
    const hay = [f.title, f.value, f.url, kindLabel(f.kind), c.names[r.connector] || r.connector, ...dataPairs(f.data).map((p) => p[1])].join(" ").toLowerCase();
    return hay.includes(c.U.q);
  }

  function paintSources(all) {
    sources.replaceChildren();
    const per = new Map();
    for (const r of c.M.results.values()) per.set(r.connector, (r.findings || []).length);
    const btn = (label, value, n) => h("button", { type: "button", "aria-pressed": String(c.U.src === value), on: { click: () => {
      c.U.src = value;
      c.repaint();
    } } }, label, " ", h("span", { class: "muted" }, fmtNum(n)));
    sources.appendChild(btn("All tools", "", all));
    for (const [id, n] of per) if (n > 0) sources.appendChild(btn(c.names[id] || id, id, n));
  }

  function paintList() {
    const all = [];
    for (const r of c.M.results.values()) for (const f of r.findings || []) all.push({ f, r });
    paintSources(all.length);
    const count = el.querySelector("#fcount");
    const pool = all.filter((x) => (!c.U.src || x.r.connector === c.U.src) && matches(x.f, x.r));
    if (count) count.textContent = pool.length === all.length ? "" : `${fmtNum(pool.length)} of ${fmtNum(all.length)} shown`;
    list.replaceChildren();
    if (!all.length) {
      const busy = c.M.status === "running" || c.M.status === "loading";
      list.appendChild(emptyState({ ic: busy ? "refresh" : "search", title: busy ? "Searching…" : "No findings", text: busy ? "Results appear here as each tool finishes." : "None of the tools that ran returned a record for this item." }));
      return;
    }
    if (!pool.length) {
      list.appendChild(emptyState({ ic: "search", title: "Nothing matches this filter", text: "Clear the filter to see every finding." }));
      return;
    }
    const groups = [...GROUPS, { id: "other", label: "Other", ic: "file", kinds: [] }];
    for (const g of groups) {
      const items = pool.filter((x) => groupOf(x.f.kind) === g.id).sort((a, b) => (b.f.confidence || 0) - (a.f.confidence || 0) || String(a.f.title).localeCompare(String(b.f.title)));
      if (!items.length) continue;
      const open = c.U.expanded.has(g.id) || items.length <= CAP;
      const shown = open ? items : items.slice(0, CAP);
      const more = open ? null : button({ label: `Show ${plural(items.length - CAP, "more finding", "more findings")}`, kind: "quiet", ic: "chevronDown", onClick: () => {
        c.U.expanded.add(g.id);
        paintList();
      } });
      list.appendChild(h("section", { class: "fgroup", "aria-label": g.label },
        h("div", { class: "fgroup-head" }, icon(g.ic, "s"), h("h3", {}, g.label), h("span", { class: "push muted small" }, fmtNum(items.length))),
        ...shown.map((x) => findingRow(x.f, x.r, c)),
        more ? h("div", { class: "cluster" }, more) : null));
    }
  }

  return { el, paint: paintList };
}

// ------------------------------------------------------------------------------------------------ tools tab
function nextStep(r) {
  if (!r) return h("span", { class: "muted small" }, "Waiting for the search to finish.");
  const notes = (r.notes || []).map(String).join(" ");
  switch (r.status) {
    case "no_key":
      return h("span", { class: "small" }, "Needs a key. ", h("a", { href: "#/connections" }, "Add one in Connections"), ". Until then the free tier is used where one exists.");
    case "missing_tool":
      return h("span", { class: "small" }, "Not installed. ", h("a", { href: "#/connections" }, "Install it in Connections"), ".");
    case "handoff":
    case "export":
      return h("div", { class: "stack-s small" },
        h("span", {}, "A manual step. Open the address in Tor Browser, or with your VPN on, not in your everyday browser."),
        r.handoff_url ? h("div", { class: "finding-url" }, icon("link", "s"), h("span", { class: "mono wrap-any" }, shorten(r.handoff_url, 240)), copyButton(r.handoff_url, "Copy address")) : null);
    case "error": case "timeout": case "blocked": case "offline": case "rate_limited": case "plan_limit": case "key_invalid": case "unsupported": case "skipped": case "cancelled":
      return h("span", { class: "small muted" }, shorten(r.error || notes || statusInfo(r.status).label, 240));
    default:
      return h("span", { class: "muted small" }, notes ? shorten(notes, 240) : "Nothing to do.");
  }
}

/** toolsView(c) -> {el, paint}. `c` = {M, names, cats, ids(): string[]}. */
export function toolsView(c) {
  const el = h("div", { class: "tbl-wrap" });
  function paint() {
    const rows = c.ids().map((id) => {
      const r = c.M.results.get(id);
      const st = c.M.state ? c.M.state[id] : "";
      const statusCell = r ? statusChip(r.status)
        : st === "running" ? chip("Running", "accent", "refresh") : chip("Queued", "mute", "clock");
      return h("tr", { "data-tool": id },
        h("td", {}, h("div", { class: "strong" }, c.names[id] || id), h("div", { class: "tiny muted" }, (c.cats && c.cats[id]) || ""),
          h("div", { class: "small muted conn-use" }, (r && r.use) || (c.uses && c.uses[id]) || "")),
        h("td", {}, statusCell),
        h("td", {}, r ? modeChip(r.mode) : null),
        h("td", { class: "r" }, r ? fmtNum((r.findings || []).length) : "–"),
        h("td", { class: "r" }, r && r.elapsed ? secs(r.elapsed) : "–"),
        h("td", {}, nextStep(r)));
    });
    el.replaceChildren(h("table", { class: "tbl" },
      h("thead", {}, h("tr", {}, ...["Tool", "Result", "Access", "Findings", "Time", "Next step"].map((t, i) => h("th", { scope: "col", class: i >= 3 && i <= 4 ? "r" : "" }, t)))),
      h("tbody", {}, ...rows)));
  }
  return { el, paint };
}

// ------------------------------------------------------------------------------------------------ relationships tab
const EDGE_CAP = 200;

/** relationsView(c) -> {el, paint}. `c` = {M, U, names, masked(): Set, repaintAll()}. The drawing and the table show the same data. */
export function relationsView(c) {
  const toggle = switchEl({ checked: !!c.U.showMasked, label: "Show sensitive entities", onChange: (v) => {
    c.U.showMasked = v;
    paint();
  } });
  const head = h("div", { class: "cluster-s" }, toggle.el,
    h("span", { class: "small muted" }, "Entities that come only from sensitive records stay hidden unless you show them."));
  const body = h("div", { class: "stack-l" });
  const el = h("div", { class: "stack-l" }, head, body);

  function describe(n, hidden) {
    const pairs = [
      ["Type", typeName(n.type)],
      ["Entity", hidden ? "Hidden (sensitive record)" : n.value],
      ["Seen by", (n.sources || []).length ? n.sources.map((s) => c.names[s] || s).join(", ") : "The searched item"],
      ["Relation", (n.relations || []).map(relLabel).join(", ") || null],
      ["Confidence", n.confidence !== undefined ? (n.confidence >= 0.85 ? "Strongly corroborated" : n.confidence >= 0.6 ? "Corroborated" : n.confidence >= 0.35 ? "Single source" : "Weak") : null],
    ];
    return kvBlock(pairs);
  }

  function paint() {
    body.replaceChildren();
    const g = c.M.graph;
    if (!g) {
      const busy = c.M.status === "running" || c.M.status === "loading";
      body.appendChild(emptyState({ ic: busy ? "refresh" : "network", title: busy ? "Relationships come later" : "No relationships",
        text: busy ? "The graph is drawn when every tool has finished, so the links are complete." : "None of the tools linked this item to another entity." }));
      return;
    }
    const masked = c.masked();
    const detail = h("div", { class: "plate stack-s", "aria-live": "polite" }, h("p", { class: "muted small" }, "Select an entity in the drawing or the table to see where it came from."));
    const gr = relationshipGraph(g, { masked, showMasked: !!c.U.showMasked, onPick: (n, hidden) => detail.replaceChildren(h("h3", { class: "h3" }, hidden ? "Sensitive entity" : shorten(n.value, 120)), describe(n, hidden)) });
    const byId = new Map((g.nodes || []).map((n) => [n.id, n]));
    const isHidden = (n) => !c.U.showMasked && masked.has(n.type + "|" + n.value);
    const corro = (g.corroborated || []).slice(0, 10).map((n) => h("li", { class: "cluster-s" },
      h("span", { class: "tiny muted" }, typeName(n.type)), h("span", { class: "wrap-any" }, isHidden(n) ? "Hidden" : shorten(n.value, 120)),
      confidenceMeter(n.confidence), h("span", { class: "push small muted" }, plural(n.sources.length, "tool"))));
    const edges = (g.edges || []).slice(0, EDGE_CAP).map((e) => {
      const n = byId.get(e.target);
      if (!n) return null;
      return h("tr", {},
        h("td", {}, relLabel(e.label)),
        h("td", {}, typeName(n.type)),
        h("td", { class: "wrap-any" }, isHidden(n) ? "Hidden" : shorten(n.value, 160)),
        h("td", {}, (e.sources || []).map((s) => c.names[s] || s).join(", ")));
    }).filter(Boolean);
    body.append(
      gr.el,
      detail,
      corro.length ? h("section", { class: "stack-s", "aria-label": "Most corroborated" }, h("h3", { class: "h3" }, "Seen by several tools"), h("ul", { class: "stack-s" }, ...corro)) : null,
      edges.length ? h("section", { class: "stack-s", "aria-label": "Every relationship" },
        h("h3", { class: "h3" }, "Every relationship"),
        h("div", { class: "tbl-wrap" }, h("table", { class: "tbl" },
          h("thead", {}, h("tr", {}, ...["Relation", "Type", "Entity", "Seen by"].map((t) => h("th", { scope: "col" }, t)))),
          h("tbody", {}, ...edges))),
        (g.edges || []).length > EDGE_CAP ? h("p", { class: "small muted" }, `Showing the first ${EDGE_CAP} of ${fmtNum(g.edges.length)} relationships.`) : null) : null);
  }
  return { el, paint };
}

// ------------------------------------------------------------------------------------------------ notes tab (saved cases only)
/** notesView(c) -> {el, paint}. `c` = {M, caseId, systemNotes, onSaved({title, notes}), onDeleted()}. Typing never repaints the screen. */
export function notesView(c) {
  const el = h("div", { class: "stack-l" });
  function paint() {
    el.replaceChildren();
    if (!c.caseId) {
      el.appendChild(emptyState({ ic: "file", title: "Notes need a saved case", text: "Turn on 'Save as a case' in Search options and run the search again. Then notes and the case title can be kept with the results." }));
      return;
    }
    const title = textInput({ id: uid("ctitle"), value: c.M.title || "", maxlength: 120, placeholder: "Case title" });
    const notes = h("textarea", { class: "textarea", id: uid("cnotes"), maxlength: "20000", rows: "8", placeholder: "Findings, leads to check, decisions…", spellcheck: "false" });
    notes.value = c.M.notes || "";
    const save = async () => {
      const t = title.value.trim();
      if (!t) {
        toast("Give the case a title.", "warn");
        return;
      }
      try {
        const r = await api.post(`/api/cases/${c.caseId}/update`, { title: t, notes: notes.value });
        c.onSaved({ title: r.title || t, notes: notes.value });
        toast("Case saved.", "ok", 2400);
      } catch (e) {
        reportError(e, "Could not save the case.");
      }
    };
    const saveBtn = button({ label: "Save", kind: "primary", ic: "check", onClick: () => withBusy(saveBtn, save) });
    const delBtn = button({ label: "Delete this case", kind: "danger", ic: "trash", onClick: async () => {
      const ok = await confirmBox({ title: "Delete this case?", body: "The case, its notes and its results are removed from this computer. This cannot be undone.", confirmLabel: "Delete case", danger: true });
      if (!ok) return;
      try {
        await api.post(`/api/cases/${c.caseId}/delete`, {});
        toast("Case deleted.", "ok", 3000);
        c.onDeleted();
      } catch (e) {
        reportError(e, "Could not delete the case.");
      }
    } });
    el.append(
      c.systemNotes && c.systemNotes.length ? banner({ tone: "info", title: "Notes from MULTI-OSINT-TOOL", body: h("ul", { class: "small" }, ...c.systemNotes.map((n) => h("li", {}, String(n)))) }) : null,
      field({ label: "Case title", hint: "Shown in Cases. Plain text only.", control: title }).el,
      field({ label: "Your notes", hint: "Stored encrypted in this case. Passwords and tokens are never stored.", control: notes }).el,
      h("div", { class: "cluster" }, saveBtn, h("span", { class: "push" }), delBtn));
  }
  return { el, paint };
}
