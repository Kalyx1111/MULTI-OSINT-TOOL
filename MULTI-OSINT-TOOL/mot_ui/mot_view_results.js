// MULTI-OSINT-TOOL :: results screen. A search in progress or finished (#/run/<id>) and a saved case (#/case/<id>).
// A running search is polled every 1.2 s, asking only for the tools whose full results are not yet held. Sensitive records
// stay hidden, secret values are shown for one minute only and never saved, and nothing here is written to browser storage.
import { h, icon, mount, fmtTime, ago, TYPE_ICON } from "./mot_dom.js";
import * as api from "./mot_api.js";
import { state, loadConns } from "./mot_state.js";
import { createDial, JEWEL_ORDER } from "./mot_rosette.js";
import { TYPE_LABEL, scope, banner, chip, statusInfo, emptyState, errorPlate, popMenu, button, askPassword, toast, reportError, tabs, loadingPlate } from "./mot_ui.js";
import { LEVEL, maskedKeys, findingsView, toolsView, relationsView, notesView } from "./mot_results_parts.js";

const POLL_MS = 1200;
const SECRET_MS = 60000;
const EXPORTS = [
  { value: "json", label: "JSON, complete data", ic: "file", ext: "json" },
  { value: "csv", label: "CSV, for spreadsheets", ic: "file", ext: "csv" },
  { value: "md", label: "Markdown report", ic: "book", ext: "md" },
  { value: "maltego", label: "Maltego import (ZIP)", ic: "network", ext: "zip" },
];
const TONE = { low: "ok", moderate: "warn", high: "bad", critical: "bad" };

export async function mountRun(root, p, ctx) {
  return mountScreen(root, p, ctx, "run");
}
export async function mountCase(root, p, ctx) {
  return mountScreen(root, p, ctx, "case");
}

async function mountScreen(root, p, ctx, mode) {
  const S = scope();
  const id = p.arg || "";
  if (!id) {
    mount(root, h("div", { class: "page" }, emptyState({ ic: "search", title: "No search selected", text: "Start a search, or open a case from Cases.", action: h("a", { class: "btn", href: "#/" }, "Search") })));
    return () => S.dispose();
  }
  // ---- model (what the search or case holds) and UI state (what the person has done on this screen)
  const M = { mode, id, status: "loading", error: "", loadError: "", target: "", ttype: "", purpose: "", title: "", notes: "", systemNotes: [],
    created: 0, caseId: mode === "case" ? id : "", plan: [], state: {}, results: new Map(), graph: null, score: null, summary: "", rev: 0, fails: 0 };
  const U = { tab: "findings", src: "", q: "", maskOn: true, shown: new Set(), secrets: new Map(), expanded: new Set(), showMasked: false };
  let caseSeen = null;
  let timer = 0;

  // ---- static DOM
  const names = Object.fromEntries(state.connList.map((c) => [c.id, c.name]));
  const cats = Object.fromEntries(state.connList.map((c) => [c.id, c.category]));
  const uses = Object.fromEntries(state.connList.map((c) => [c.id, c.use || ""]));
  const dial = createDial(names);
  const bannerHost = h("div", { class: "stack-s" });
  const headHost = h("div", { class: "target-id" });
  const exportBtn = button({ label: "Export", ic: "download", onClick: () => openExport() });
  const cancelBtn = button({ label: "Stop search", kind: "quiet", ic: "stop", onClick: () => cancelJob() });
  cancelBtn.hidden = true;
  const actions = h("div", { class: "cluster" }, h("div", { class: "menu-anchor" }, exportBtn), cancelBtn,
    h("a", { class: "btn btn-quiet", href: "#/" }, icon("search", "s"), "New search"));
  const progress = h("div", { class: "progress", role: "progressbar", "aria-label": "Tools finished", "aria-valuemin": "0", "aria-valuemax": "100" }, h("i"));
  const summaryP = h("p", { class: "muted small" });
  const scoreHost = h("div", { class: "stack-s" });
  const side = h("aside", { class: "res-side" }, h("div", { class: "plate stack-s" }, dial.el, progress), summaryP, scoreHost);
  const panel = h("div", { class: "stack-l", role: "tabpanel" });
  const tabBar = tabs({ items: [{ id: "findings", label: "Findings", count: 0 }, { id: "tools", label: "Tools", count: 0 }, { id: "relations", label: "Relationships" }, { id: "notes", label: "Notes" }],
    value: U.tab, label: "Result sections", onChange: (t) => {
      U.tab = t;
      showTab(true);
    } });
  const main = h("div", { class: "res-main" }, tabBar.el, panel);
  mount(root, h("div", { class: "page stack-l" }, h("header", { class: "target-head" }, headHost, actions), bannerHost, h("div", { class: "res-grid" }, side, main)));

  // ---- shared context for the four tab views (getters keep values current without copying)
  const C = {
    M, U, names, cats, uses,
    get canReveal() { return M.mode === "run"; },
    get caseId() { return M.caseId; },
    get systemNotes() { return M.systemNotes; },
    ids: () => (M.plan.length ? M.plan : [...M.results.keys()]),
    masked: () => maskedKeys(M.results, U.maskOn, U.shown),
    toggleShown(fid) {
      if (U.shown.has(fid)) U.shown.delete(fid);
      else U.shown.add(fid);
      M.rev++;
      showTab(true);
    },
    hideSecret(fid) {
      U.secrets.delete(fid);
      showTab(true);
    },
    reveal,
    repaint: () => showTab(true),
    onSaved({ title, notes }) {
      M.title = title;
      M.notes = notes;
      paintHead();
    },
    onDeleted: () => ctx.go("#/cases"),
  };
  const views = { findings: findingsView(C), tools: toolsView(C), relations: relationsView(C), notes: notesView(C) };
  const painted = {};

  function showTab(force) {
    if (!S.alive) return;
    const v = views[U.tab];
    if (!v) return;
    if (panel.firstChild !== v.el) mount(panel, v.el);
    if (force || painted[U.tab] !== M.rev) {
      v.paint();
      painted[U.tab] = M.rev;
    }
  }

  // ---- painting
  function dialMap() {
    const inPlan = new Set(M.plan);
    const map = {};
    for (const cid of JEWEL_ORDER) {
      if (!inPlan.has(cid)) {
        map[cid] = { na: true, label: "Not used for this search" };
        continue;
      }
      const r = M.results.get(cid);
      if (r) map[cid] = { state: "done", status: r.status, label: statusInfo(r.status).label };
      else if (M.state[cid] === "running") map[cid] = { state: "running", label: "Searching" };
      else map[cid] = { state: "queued", label: "Waiting" };
    }
    return map;
  }

  function paintHead() {
    const t = M.ttype;
    const status = M.mode === "case" ? chip("Saved case", "accent", "folder")
      : M.status === "running" ? chip("Searching", "accent", "refresh")
      : M.status === "done" ? chip("Finished", "ok", "check")
      : M.status === "cancelled" ? chip("Stopped", "mute", "stop")
      : M.status === "error" ? chip("Stopped with an error", "bad", "warn")
      : M.status === "gone" ? chip("Not in memory", "mute", "clock") : chip("Loading", "mute", "clock");
    const saved = M.caseId ? chip("Saved as a case", "info", "folder") : M.mode === "run" && M.status !== "running" && M.status !== "loading" ? chip("Not saved", "mute", "lock") : null;
    exportBtn.disabled = !M.caseId;
    exportBtn.title = M.caseId ? "Export this case" : "Save this search as a case to export it";
    cancelBtn.hidden = !(M.mode === "run" && M.status === "running");
    mount(headHost, h("div", { class: "target-ring" }, icon(TYPE_ICON[t] || "tag")),
      h("div", { class: "stack-s" },
        h("h1", { class: "target-name", tabIndex: -1, "data-page-title": "" }, M.mode === "case" ? M.title || M.target || "Case" : M.target || "Search"),
        h("div", { class: "cluster-s" }, chip(TYPE_LABEL[t] || t || "Target", "mute", TYPE_ICON[t]), status, saved),
        h("span", { class: "tiny muted" }, [M.purpose ? "Purpose: " + M.purpose : "", M.created ? `Started ${fmtTime(M.created)} · ${ago(M.created)}` : ""].filter(Boolean).join(" · "))));
  }

  function scoreBlock() {
    const sc = M.score;
    if (!sc) return [];
    return [
      h("div", { class: "score-line lvl-" + sc.level }, h("span", { class: "score-num" }, String(sc.score)), h("span", { class: "muted small" }, "exposure, out of 100"),
        chip(LEVEL[sc.level] || sc.level, TONE[sc.level] || "mute")),
      sc.factors && sc.factors.length
        ? h("ol", { class: "factors" }, ...sc.factors.slice(0, 12).map((f) => h("li", {}, h("span", { class: "pts" }, "+" + Math.round(f.points)), h("span", {}, f.reason))))
        : h("p", { class: "small muted" }, "No exposure factors were found."),
      h("p", { class: "tiny faint" }, sc.disclaimer || ""),
    ];
  }

  function paintSide() {
    const total = M.plan.length || M.results.size;
    const doneN = M.mode === "case" ? M.results.size : Object.values(M.state).filter((s) => s === "done").length;
    const withFind = [...M.results.values()].filter((r) => (r.findings || []).length > 0).length;
    const okN = [...M.results.values()].filter((r) => r.status === "ok").length;
    progress.style.setProperty("--p", String(total ? Math.round((doneN / total) * 100) : 0));
    dial.update(dialMap());
    dial.setBusy(M.status === "running");
    if (M.status === "done" && M.score) dial.setCentre(String(M.score.score), "exposure, out of 100", `${LEVEL[M.score.level] || ""} · ${okN} tools with data`);
    else if (M.status === "running") dial.setCentre(String(doneN), `of ${total} tools finished`, `${withFind} with findings so far`);
    else if (M.status === "loading") dial.setCentre("…", "loading", "");
    else dial.setCentre("–", M.status === "cancelled" ? "search stopped" : "no score", `${doneN} of ${total} tools finished`);
    summaryP.textContent = M.summary || (M.status === "running" ? "Results appear as each tool finishes. The exposure score and the relationship graph are drawn when the search ends." : "");
    mount(scoreHost, ...scoreBlock());
    tabBar.setCount("findings", [...M.results.values()].reduce((n, r) => n + (r.findings || []).length, 0));
    tabBar.setCount("tools", total);
  }

  function paintBanners() {
    const list = [];
    if (M.loadError) list.push(banner({ tone: "bad", title: "Lost contact with the search.", body: M.loadError, actions: button({ label: "Try again", small: true, ic: "refresh", onClick: () => { M.loadError = ""; M.fails = 0; schedule(0); paintBanners(); } }) }));
    if (M.status === "error") list.push(banner({ tone: "bad", title: "The search stopped unexpectedly.", body: `Finished tools are still shown. Open Health for details${M.error ? " (" + M.error + ")" : ""}.` }));
    if (M.status === "cancelled") list.push(banner({ tone: "info", title: "This search was stopped.", body: "Tools that had already finished keep their results." }));
    if (M.status === "gone") list.push(banner({ tone: "warn", title: "This search is no longer in memory.", body: "Open it from Cases.", actions: h("a", { class: "btn btn-s", href: "#/cases" }, "Cases") }));
    if (M.systemNotes.length) list.push(banner({ tone: "info", title: "Notes from MULTI-OSINT-TOOL", body: M.systemNotes.join(" ") }));
    mount(bannerHost, ...list);
  }

  function refresh() {
    if (!S.alive) return;
    paintHead();
    paintSide();
    paintBanners();
    if (U.tab === "notes") {
      if (caseSeen !== M.caseId) {
        caseSeen = M.caseId;
        showTab(true);
      }
    } else showTab(false);
  }

  // ---- actions
  function openExport() {
    if (!M.caseId) return toast("Save this search as a case to export it.", "warn", 4200);
    popMenu({ anchor: exportBtn, label: "Export format", items: EXPORTS.map((x) => ({ label: x.label, ic: x.ic, value: x.value })), onPick: async (fmt) => {
      const ex = EXPORTS.find((x) => x.value === fmt) || EXPORTS[0];
      try {
        await api.download(`/api/cases/${M.caseId}/export?fmt=${ex.value}`, `mot-case-${M.caseId}.${ex.ext}`);
        toast("Export ready. Your browser saves it to your downloads.", "ok", 3600);
      } catch (e) {
        reportError(e, "Export failed.");
      }
    } });
  }

  async function cancelJob() {
    try {
      await api.post(`/api/jobs/${M.id}/cancel`, {});
      toast("Stopping. Tools that already finished keep their results.", "info", 4200);
    } catch (e) {
      reportError(e, "Could not stop the search.");
    }
  }

  async function reveal(f) {
    const out = await askPassword({ title: "Reveal the secret", confirmLabel: "Reveal",
      lead: "Enter your master password. The value is shown for one minute, is never saved, and the reveal is recorded in your audit log.",
      action: (pw) => api.post("/api/reveal", { job: M.id, finding: f.fid, password: pw }) });
    if (!out || !S.alive) return;
    U.secrets.set(f.fid, { data: out, expires: Date.now() + SECRET_MS });
    showTab(true);
  }

  // secret values leave the screen on time, and on lock or navigation (S.add runs at teardown)
  S.interval(() => {
    const now = Date.now();
    let gone = false;
    for (const [fid, s] of U.secrets) {
      if (s.expires <= now) {
        U.secrets.delete(fid);
        gone = true;
      }
    }
    if (gone) showTab(true);
  }, 1000);
  S.add(() => U.secrets.clear());

  // ---- data
  // A signature of what the screen shows, so an unchanged poll does not repaint the findings list.
  const sigOf = () => [M.status, M.caseId, M.error, Object.values(M.state).join(""),
    [...M.results.values()].map((r) => r.connector + ":" + r.status + ":" + (r.findings || []).length).join(",")].join("|");

  function merge(d) {
    if (!d || typeof d !== "object") return;
    const before = sigOf();
    M.status = d.status || M.status;
    M.error = d.error || "";
    M.target = d.target || M.target;
    M.ttype = d.ttype || M.ttype;
    M.created = d.created || M.created;
    if (Array.isArray(d.plan)) M.plan = d.plan;
    for (const [cid, st] of Object.entries(d.state || {})) M.state[cid] = st;
    for (const [cid, r] of Object.entries(d.results || {})) {
      if (r.delivered && M.results.has(cid)) continue; // the server confirmed we already hold the full result
      M.results.set(cid, r);
    }
    if (d.case) {
      M.caseId = d.saved ? d.case.id : "";
      M.summary = d.case.summary || M.summary;
      M.score = d.case.score || M.score;
      M.graph = d.case.graph || M.graph;
    }
    if (sigOf() !== before) M.rev++;
  }

  async function poll() {
    if (!S.alive) return;
    const have = [...M.results.keys()].filter((cid) => M.state[cid] === "done").join(",");
    let d;
    try {
      d = await api.get(`/api/jobs/${M.id}` + api.q({ have }));
    } catch (e) {
      if (!S.alive) return;
      if (e instanceof api.ApiError && (e.code === "locked" || e.code === "no_session")) return;
      if (e instanceof api.ApiError && e.status === 404) {
        M.status = "gone";
        refresh();
        return;
      }
      M.fails += 1;
      if (M.fails >= 5) {
        M.loadError = (e && e.message) || "The search did not answer.";
        paintBanners();
        return;
      }
      schedule(Math.min(8000, POLL_MS * 2 ** M.fails));
      return;
    }
    if (!S.alive) return;
    M.fails = 0;
    M.loadError = "";
    merge(d);
    try {
      refresh();
    } catch (e) {
      console.error("results could not be drawn", e); // a drawing fault must never look like a lost connection
    }
    if (d.status === "running") schedule(POLL_MS);
  }
  function schedule(ms) {
    clearTimeout(timer);
    if (S.alive) timer = setTimeout(poll, ms);
  }
  S.add(() => clearTimeout(timer));

  async function loadCase() {
    const c = await api.get(`/api/cases/${id}`);
    if (!S.alive) return;
    M.target = c.target || "";
    M.ttype = c.ttype || "";
    M.title = c.title || "";
    M.notes = c.notes_user || "";
    M.purpose = c.purpose || "";
    M.created = c.created || 0;
    M.summary = c.summary || "";
    M.score = c.score || null;
    M.graph = c.graph || null;
    M.systemNotes = Array.isArray(c.notes) ? c.notes.map(String) : [];
    M.results = new Map((c.results || []).map((r) => [r.connector, r]));
    M.plan = [...M.results.keys()];
    M.state = Object.fromEntries(M.plan.map((k) => [k, "done"]));
    M.caseId = c.id || id;
    M.status = "done";
    ctx.setTitle(M.title || "Case");
    M.rev++;
  }

  // ---- start
  try {
    await loadConns().catch(() => {});
    const cfg = await api.get("/api/settings").catch(() => null);
    if (cfg && cfg.mask_sensitive === false) U.maskOn = false;
    if (!S.alive) return () => S.dispose();
    if (mode === "case") await loadCase();
    refresh();
    showTab(true);
    if (mode === "run") poll();
  } catch (e) {
    if (S.alive) mount(panel, errorPlate(e, null));
  }
  return () => S.dispose();
}
