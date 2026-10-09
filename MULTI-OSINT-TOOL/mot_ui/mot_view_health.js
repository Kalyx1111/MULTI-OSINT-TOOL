// MULTI-OSINT-TOOL :: Health. Checks the program, its files, vault, tools and audit log; repairs only what is safe to repair.
// Recovery of an interrupted search is offered here, and a crash marker is explained rather than hidden.
import { h, icon, mount, fmtTime, fmtNum, ago } from "./mot_dom.js";
import * as api from "./mot_api.js";
import { state, emit } from "./mot_state.js";
import { scope, banner, chip, button, pageHead, sectionHead, loadingPlate, kvList, toast, reportError, confirmBox } from "./mot_ui.js";

const TONE = { ok: "ok", warn: "warn", fail: "bad" };
const ICON = { ok: "check", warn: "warn", fail: "cross" };
const short = (v) => (v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v).slice(0, 160) : String(v).slice(0, 160));

export async function mountHealth(root, p, ctx) {
  const S = scope();
  const body = h("div", { class: "stack-l" });
  mount(root, h("div", { class: "page stack-l" },
    pageHead({ eyebrow: "Diagnostics", title: "Health",
      lead: "Checks the program, its files, the vault, the tools and the audit log. It repairs only what is safe to repair on its own, and explains the rest." }),
    body));
  mount(body, loadingPlate("Running the checks…"));

  async function build() {
    const [health, rec, tools, audit] = await Promise.all([api.get("/api/health"), api.get("/api/recovery"), api.get("/api/tools"), api.get("/api/audit?limit=60")]);
    if (!S.alive) return;
    state.pending = (rec.pending || []).length;
    state.crash = !!rec.crash;
    emit("recovery", rec);
    ctx.refreshRecovery();
    mount(body,
      overall(health),
      recoveryBlock(rec),
      checksBlock(health),
      hardwareBlock(health),
      toolsBlock(tools),
      auditBlock(audit));
  }

  function overall(health) {
    const fixable = (health.checks || []).filter((c) => c.status !== "ok" && c.fixable).length;
    const fixBtn = fixable ? button({ label: `Run diagnostic repair (${fixable})`, kind: "primary", ic: "wrench", onClick: () => repairAll() }) : null;
    if (health.overall === "ok") return banner({ tone: "ok", title: "Everything checks out.", body: "Nothing needs your attention." });
    return banner({ tone: health.overall === "fail" ? "bad" : "warn", title: health.overall === "fail" ? "Something needs attention." : "Some optional items are not ready.",
      body: "Failing items are listed below with what to do about each one.", actions: fixBtn });
  }

  function recoveryBlock(rec) {
    const pend = rec.pending || [];
    if (!rec.crash && !pend.length) return null;
    const items = pend.map((s) => h("div", { class: "case-row" },
      h("div", { class: "stack-s" }, h("span", { class: "strong wrap-any" }, short(s.target) || "Search"),
        h("span", { class: "small muted" }, `${s.done.length} of ${s.done.length + s.todo.length} tools finished · started ${s.created ? ago(s.created) : "earlier"}`)),
      h("span", {}, button({ label: "Recover from last state", kind: "primary", small: true, ic: "refresh", onClick: () => recover(s.id, "resume") })),
      h("span", {}, button({ label: "Save finished results as a case", small: true, ic: "folder", onClick: () => recover(s.id, "case") })),
      h("span", {}, button({ label: "Discard", kind: "quiet", small: true, ic: "trash", onClick: () => discard(s.id) }))));
    return h("section", { class: "section stack-s", "aria-label": "Recovery" }, sectionHead("Unfinished work"),
      banner({ tone: "warn", title: rec.crash ? "MULTI-OSINT-TOOL did not close cleanly last time." : "Unfinished searches were found.",
        body: "Nothing was lost. You can recover from the last saved state, keep what finished as a case, or discard it." }),
      pend.length ? h("div", { class: "stack-s" }, ...items) : null,
      pend.length ? null : h("p", { class: "small muted" }, "No unfinished searches are waiting."));
  }

  async function recover(jid, action) {
    try {
      const out = await api.post(`/api/recovery/${jid}`, { action });
      if (action === "resume" && out.job) return ctx.go("#/run/" + out.job.id);
      if (action === "case" && out.case) return ctx.go("#/case/" + out.case);
      toast("Done.", "ok", 2400);
      await build();
    } catch (e) {
      reportError(e, "Recovery did not finish.");
    }
  }

  async function discard(jid) {
    const ok = await confirmBox({ title: "Discard this unfinished search?", body: "Its partial results are deleted. This cannot be undone.", confirmLabel: "Discard", danger: true });
    if (!ok) return;
    try {
      await api.post(`/api/recovery/${jid}`, { action: "discard" });
      toast("Discarded.", "ok", 2200);
      await build();
    } catch (e) {
      reportError(e, "Could not discard it.");
    }
  }

  function checksBlock(health) {
    const rows = (health.checks || []).map((c) => h("div", { class: "check-row", vars: { "--tone": `var(--${TONE[c.status] || "ink-3"})` } },
      icon(ICON[c.status] || "info"),
      h("div", { class: "stack-s" }, h("span", { class: "strong" }, c.title), h("span", { class: "small muted wrap-any" }, short(c.detail))),
      c.fixable && c.status !== "ok" ? button({ label: "Repair", small: true, ic: "wrench", onClick: () => repairOne(c) }) : h("span", { class: "tiny muted" }, c.status === "ok" ? "OK" : c.status === "warn" ? "Optional" : "Needs you")));
    return h("section", { class: "section stack-s", "aria-label": "Checks" }, sectionHead("Checks"), h("div", { class: "rows" }, ...rows));
  }

  async function repairOne(c) {
    try {
      const r = await api.post("/api/health/fix", { id: c.id });
      toast(r.ok ? (r.msg || "Repaired.") : (r.msg || "Not repaired."), r.ok ? "ok" : "warn", 5200);
    } catch (e) {
      reportError(e, "Repair did not run.");
    }
    await build();
  }

  async function repairAll() {
    const h0 = await api.get("/api/health");
    const todo = (h0.checks || []).filter((c) => c.status !== "ok" && c.fixable);
    let fixed = 0;
    for (const c of todo) {
      try {
        const r = await api.post("/api/health/fix", { id: c.id });
        if (r.ok) fixed += 1;
      } catch (_) {
        /* the item stays listed as it is */
      }
    }
    toast(`Diagnostic repair finished: ${fixed} of ${todo.length} fixed.`, fixed === todo.length ? "ok" : "warn", 5200);
    await build();
  }

  function hardwareBlock(health) {
    const hw = Object.entries(health.hardware || {}).filter(([, v]) => typeof v !== "object" || v === null).slice(0, 12);
    const tune = Object.entries(health.tuning || {}).filter(([, v]) => typeof v !== "object" || v === null).slice(0, 8);
    return h("section", { class: "section stack-s", "aria-label": "This computer" }, sectionHead("This computer"),
      h("div", { class: "form-grid" }, kvList(hw.map(([k, v]) => [k.replace(/_/g, " "), String(v)])), kvList(tune.map(([k, v]) => [k.replace(/_/g, " "), String(v)]))));
  }

  function toolsBlock(t) {
    const tor = t.tor || {};
    const rows = (t.tools || []).map((r) => h("div", { class: "check-row", vars: { "--tone": r.installed ? "var(--ok)" : "var(--warn)" } },
      icon(r.installed ? "check" : "wrench"),
      h("div", { class: "stack-s" }, h("span", { class: "strong" }, r.name),
        h("span", { class: "small muted wrap-any" }, r.installed ? "Installed on this computer." : (r.manual || "Not installed yet.")),
        r.state && r.state.msg ? h("span", { class: "tiny muted" }, short(r.state.msg)) : null,
        r.needs_python ? h("span", { class: "tiny muted" }, `Needs Python ${r.needs_python} or newer.`) : null),
      r.installed ? chip("Installed", "ok") : r.manual ? chip("Manual", "info") : button({ label: "Install", small: true, ic: "download", onClick: () => installTool(r.id) })));
    return h("section", { class: "section stack-s", "aria-label": "Tools on this computer" }, sectionHead("Tools on this computer"),
      h("p", { class: "small muted" }, tor.binary ? "Tor is installed." : "Tor is not installed. Optional, but needed for dark-web lookups.", (tor.detected || []).length ? ` Running on ${tor.detected.join(", ")}.` : ""),
      h("div", { class: "rows" }, ...rows));
  }

  async function installTool(cid) {
    try {
      await api.post(`/api/tools/${cid}/install`, {});
      toast("Installing. This can take a few minutes.", "info", 4200);
      setTimeout(() => S.alive && build(), 4000);
    } catch (e) {
      reportError(e, "Install did not start.");
    }
  }

  function auditBlock(a) {
    const v = a.verify || {};
    const ok = !!v.ok;
    const rows = (a.rows || []).slice(-40).reverse().map((r) => h("tr", {},
      h("td", { class: "tiny muted nowrap" }, fmtTime(r.ts)),
      h("td", {}, h("span", { class: "mono" }, String(r.event))),
      h("td", { class: "small muted wrap-any" }, Object.entries(r.d || {}).slice(0, 4).map(([k, val]) => `${k}: ${short(val)}`).join(" · "))));
    return h("section", { class: "section stack-s", "aria-label": "Audit log" }, sectionHead("Audit log"),
      banner({ tone: ok ? "ok" : "bad", title: ok ? `The audit log is intact (${fmtNum(v.records || 0)} records).` : "The audit log does not verify.",
        body: ok ? "Every entry is chained, so an edited or removed line would be detected." : `First bad record: ${v.first_bad_seq ?? "unknown"}. Keep this computer's state and report it.` }),
      rows.length ? h("div", { class: "tbl-wrap" }, h("table", { class: "tbl" },
        h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Time"), h("th", { scope: "col" }, "Event"), h("th", { scope: "col" }, "Details"))),
        h("tbody", {}, ...rows))) : h("p", { class: "small muted" }, "No events yet."));
  }

  try {
    await build();
  } catch (e) {
    if (S.alive) mount(body, banner({ tone: "bad", title: "The checks could not run.", body: e.message || "Try again." }));
  }
  return () => S.dispose();
}
