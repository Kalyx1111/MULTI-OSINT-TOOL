// MULTI-OSINT-TOOL :: Connections. The twenty tools, their keys, routes and installs.
// Keys go to the encrypted vault and are never shown again except through the password-confirmed reveal (60 s, audited).
// Only non-empty fields are sent when a key is saved: the server treats a blank optional field as "remove it".
import { h, icon, mount, TYPE_ICON } from "./mot_dom.js";
import * as api from "./mot_api.js";
import { state, loadConns } from "./mot_state.js";
import { TYPE_LABEL, scope, banner, chip, connModeChip, emptyState, errorPlate, loadingPlate, pageHead, switchEl, segmented, pwInput,
  externalLink, askPassword, confirmBox, modal, toast, reportError } from "./mot_ui.js";

const FILTERS = [
  { value: "all", label: "All" },
  { value: "attention", label: "Needs a key or install" },
  { value: "paid", label: "On my key" },
  { value: "free", label: "Free tier" },
  { value: "catalog", label: "Catalogue only" },
  { value: "manual", label: "Manual or file" },
];
const VERDICT_TONE = { connected: "ok", connected_limited: "warn", rate_limited: "warn", shield_down: "bad", rejected: "bad", error: "bad" };
const FIELD_LABEL = { api_key: "API key", key: "API key", token: "Token", username: "Username", password: "Password", secret: "Secret", email: "Email", user: "Username" };
const fieldLabel = (f) => FIELD_LABEL[f] || String(f).replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
const needsAttention = (r) => r.mode === "needs_key" || r.installed === false;

export async function mountConnections(root, p, ctx) {
  const S = scope();
  const U = { filter: "all", open: new Set() };
  let rows = [];
  let summary = { paid: 0, free_ready: 0, needs_key: 0 };
  const sumHost = h("div", {});
  const filterHost = h("div", {});
  const list = h("div", { class: "stack-s" });
  mount(root, h("div", { class: "page stack-l" },
    pageHead({ eyebrow: "Your tools", title: "Connections",
      lead: "Every source the program knows, with what it is used for. A connected tool runs on your own key when you add one, and on its free tier otherwise. Catalogue-only sources are never sent your searches. Keys are encrypted in your vault." }),
    sumHost, filterHost, list));
  mount(list, loadingPlate("Opening your tools…"));

  async function load() {
    await loadConns(true);
    if (!S.alive) return;
    rows = state.connList || [];
    summary = state.connSummary || summary;
    paint();
  }

  function paintSummary() {
    const manual = rows.filter((r) => r.mode === "handoff" || r.mode === "export").length;
    mount(sumHost, h("div", { class: "summary-bar" },
      h("span", {}, h("b", {}, String(summary.paid || 0)), "on your own keys"),
      h("span", {}, h("b", {}, String(summary.free_ready || 0)), "on the free tier"),
      h("span", {}, h("b", {}, String(summary.needs_key || 0)), "waiting for a key"),
      h("span", {}, h("b", {}, String(manual)), "manual or file")));
  }

  const seg = segmented({ options: FILTERS, value: U.filter, label: "Show tools", onChange: (v) => {
    U.filter = v;
    paint();
  } });
  mount(filterHost, seg.el);

  function paint() {
    if (!S.alive) return;
    paintSummary();
    const shown = rows.filter((r) => U.filter === "all" || (U.filter === "attention" ? needsAttention(r) : U.filter === "manual" ? (r.mode === "handoff" || r.mode === "export") : U.filter === "catalog" ? r.tier === "catalog" : r.mode === U.filter));
    list.replaceChildren();
    if (!shown.length) {
      list.appendChild(emptyState({ ic: "plug", title: "No tools here", text: "Choose another filter to see the rest." }));
      return;
    }
    for (const r of shown) list.appendChild(connRow(r));
  }

  function connRow(r) {
    if (r.tier === "catalog") return catalogRow(r);
    const body = h("div", { class: "conn-body" });
    const open = U.open.has(r.id);
    const sw = switchEl({ checked: !!r.enabled, label: `Use ${r.name} in searches`, onChange: async (v) => {
      try {
        await api.post(`/api/connections/${r.id}/config`, { enabled: v });
        r.enabled = v;
        toast(v ? `${r.name} is on.` : `${r.name} is off. It will not run.`, "ok", 2800);
        paint();
      } catch (e) {
        sw.set(!v);
        reportError(e);
      }
    } });
    const toggle = h("button", { class: "btn btn-quiet btn-s", type: "button", "aria-expanded": String(open), on: { click: () => {
      if (U.open.has(r.id)) U.open.delete(r.id);
      else U.open.add(r.id);
      paint();
    } } }, icon(open ? "chevronDown" : "chevronRight", "s"), open ? "Close" : "Manage");
    const tier = r.tier === "requested" ? "Your list" : "Added to make 20";
    const head = h("div", { class: "conn-head" },
      h("span", { class: "mono-badge", "aria-hidden": "true" }, String(r.name || r.id).slice(0, 2).toUpperCase()),
      h("div", { class: "stack-s" },
        h("div", { class: "conn-name" }, h("h3", {}, r.name), h("span", { class: "tiny muted" }, r.category || ""), connModeChip(r.mode),
          r.enabled ? null : chip("Off", "mute", "minus")),
        h("div", { class: "tiny muted cluster-s" }, ...(r.targets || []).slice(0, 6).map((t) => chip(TYPE_LABEL[t] || t, "mute", TYPE_ICON[t] || null)), h("span", {}, tier)),
        r.use ? h("p", { class: "small conn-use" }, r.use) : null),
      h("div", { class: "cluster-s", title: r.enabled ? "On" : "Off" }, sw.el),
      toggle);
    const art = h("article", { class: "conn", "data-tool": r.id }, head, open ? body : null);
    if (open) fillBody(r, body);
    return art;
  }

  // A source with no connector: what it is used for, what it searches, and why the program does not run it.
  function catalogRow(r) {
    const types = (r.search_types || []).map((t) => chip(TYPE_LABEL[t] || t, "mute", TYPE_ICON[t] || null));
    return h("article", { class: "conn", "data-tool": r.id },
      h("div", { class: "conn-head" },
        h("span", { class: "mono-badge", "aria-hidden": "true" }, String(r.name || r.id).slice(0, 2).toUpperCase()),
        h("div", { class: "stack-s" },
          h("div", { class: "conn-name" }, h("h3", {}, r.name), h("span", { class: "tiny muted" }, r.category || ""), connModeChip(r.mode)),
          r.use ? h("p", { class: "small conn-use" }, r.use) : null,
          h("div", { class: "tiny muted cluster-s" }, ...types, h("span", {}, r.access_label || ""))),
        h("span", { class: "tiny muted" }, "Not searched by the program")),
      r.note ? h("p", { class: "small muted" }, String(r.note)) : null,
      h("p", { class: "tiny faint" }, r.site ? `Website: ${r.site}` : "Website: not verified yet."));
  }

  function fillBody(r, body) {
    const kids = [];
    if (r.note) kids.push(h("p", { class: "small muted" }, String(r.note)));
    if (r.free_mode) kids.push(h("p", { class: "small" }, "Free tier: ", String(r.free_mode)));
    if (r.needs_tor) kids.push(banner({ tone: "info", body: "This tool is reached through Tor only." }));
    if (r.canary_cost) kids.push(banner({ tone: "warn", body: "Testing this key uses one credit of your plan. You are asked before each test." }));
    if (r.kind === "cli" || r.kind === "local") kids.push(installLine(r));
    if ((r.key_fields || []).length || (r.optional_fields || []).length) kids.push(keyForm(r));
    if (r.kind === "api" || r.kind === "cli") kids.push(routeLine(r));
    const links = [];
    if (r.key_url) links.push(externalLink("Get a key", "vendor", r.id, "key", r.name + " key page"));
    if (r.site) links.push(externalLink("Website", "vendor", r.id, "site", r.name + " website"));
    if (r.docs_url) links.push(externalLink("Documentation", "vendor", r.id, "docs", r.name + " documentation"));
    if (links.length) kids.push(h("div", { class: "cluster-s" }, ...links));
    kids.push(h("p", { class: "tiny faint" }, "Links open in your ordinary browser, after a warning. Copy them into Tor Browser if you prefer."));
    mount(body, ...kids);
  }

  function installLine(r) {
    if (r.installed) return h("div", { class: "cluster-s small" }, chip("Installed on this computer", "ok", "check"));
    if (!r.installable) return h("p", { class: "small muted" }, "Not installed. See Health for how to add it.");
    return h("div", { class: "cluster-s small" }, chip("Not installed", "warn", "wrench"),
      h("button", { class: "btn btn-s", type: "button", on: { click: async () => {
        try {
          await api.post(`/api/tools/${r.id}/install`, {});
          toast("Installing. Progress is shown in Health.", "info", 4200);
        } catch (e) {
          reportError(e, "Install did not start.");
        }
      } } }, icon("wrench", "s"), "Install"));
  }

  function routeLine(r) {
    return h("div", { class: "stack-s" }, h("span", { class: "label" }, "Route"),
      segmented({ options: [{ value: "auto", label: "Automatic" }, { value: "tor", label: "Tor" }, { value: "vpn", label: "VPN" }], value: r.route || "auto", label: "Route for this tool", onChange: async (v) => {
        try {
          await api.post(`/api/connections/${r.id}/config`, { route: v });
          r.route = v;
          toast("Route saved.", "ok", 2000);
        } catch (e) {
          reportError(e);
        }
      } }).el,
      h("p", { class: "hint" }, "Automatic follows the shield mode. Tor and VPN force the route; if the shield does not allow it, nothing is sent."));
  }

  function keyForm(r) {
    const inputs = [];
    const msg = h("p", { class: "hint", "aria-live": "polite" });
    const fields = [...(r.key_fields || []), ...(r.optional_fields || [])];
    const rowsEl = fields.map((f) => {
      const st = (r.keys || {})[f] || { set: false };
      const pw = pwInput({ autocomplete: "off", placeholder: st.set ? "Stored. Type to replace." : "Paste the key" });
      inputs.push([f, pw]);
      const stored = st.set ? (st.source === "environment" ? "From your environment" : "Stored in your vault" + (st.preview ? " · " + st.preview : "")) : "Not set";
      const revealBtn = st.set && st.source === "vault" ? h("button", { class: "btn btn-quiet btn-s", type: "button", on: { click: () => revealField(r, f) } }, icon("eye", "s"), "Show") : null;
      return h("div", { class: "keyrow" },
        h("div", { class: "stack-s" }, h("label", { class: "label", for: pw.input.id }, fieldLabel(f) + (st.required ? "" : " (optional)")), h("span", { class: "state" }, icon(st.set ? "check" : "minus", "s"), stored)),
        pw.el, revealBtn);
    });
    const save = h("button", { class: "btn btn-primary btn-s", type: "button", on: { click: async () => {
      const out = {};
      for (const [f, pw] of inputs) if (pw.value.trim()) out[f] = pw.value.trim();
      if (!Object.keys(out).length) {
        msg.textContent = "Paste a key first. Stored keys are never shown again.";
        return;
      }
      try {
        const res = await api.post(`/api/connections/${r.id}/key`, { fields: out });
        for (const [, pw] of inputs) pw.wipe();
        toast(res.complete ? "Key saved. This tool now uses it." : `Saved. Still missing: ${(res.missing || []).map(fieldLabel).join(", ")}.`, res.complete ? "ok" : "warn", 5200);
        await load();
      } catch (e) {
        reportError(e, "The key was not saved.");
      }
    } } }, icon("key", "s"), "Save key");
    const remove = (r.keys && Object.values(r.keys).some((s) => s.set && s.source === "vault")) ? h("button", { class: "btn btn-quiet btn-s", type: "button", on: { click: () => removeKey(r) } }, icon("trash", "s"), "Remove stored key") : null;
    const test = r.testable ? h("button", { class: "btn btn-s", type: "button", on: { click: (ev) => testKey(r, msg, ev.currentTarget) } }, icon("pulse", "s"), "Test key") : null;
    return h("div", { class: "stack" }, ...rowsEl, h("div", { class: "cluster" }, save, test, remove), msg);
  }

  async function testKey(r, msg, btn) {
    msg.className = "hint";
    msg.textContent = "Testing…";
    btn.disabled = true;
    try {
      let res;
      try {
        res = await api.post(`/api/connections/${r.id}/test`, { confirm_cost: false });
      } catch (e) {
        if (!(e instanceof api.ApiError && e.code === "confirm_cost")) throw e;
        const ok = await confirmBox({ title: "Test this key?", body: e.message, confirmLabel: "Test anyway" });
        if (!ok) {
          msg.textContent = "";
          return;
        }
        res = await api.post(`/api/connections/${r.id}/test`, { confirm_cost: true });
      }
      msg.className = "hint" + (VERDICT_TONE[res.verdict] === "bad" ? " is-error" : "");
      msg.textContent = res.message || res.verdict;
    } catch (e) {
      msg.className = "hint is-error";
      msg.textContent = e.message || "The test did not complete.";
    } finally {
      btn.disabled = false;
    }
  }

  async function revealField(r, field) {
    const out = await askPassword({ title: `Show the ${fieldLabel(field).toLowerCase()} for ${r.name}`, confirmLabel: "Show",
      lead: "Enter your master password. The value is shown for one minute, is not saved, and the reveal is written to your audit log.",
      action: (pw) => api.post(`/api/connections/${r.id}/reveal`, { field, password: pw }) });
    if (!out || !S.alive) return;
    const ctl = modal({ title: "Stored value", lead: "Closes by itself after one minute.", content: [h("div", { class: "secret-box" }, h("span", { class: "mono wrap-any" }, String(out.value)))],
      actions: [{ label: "Close", kind: "primary", value: true, autofocus: true }] });
    const t = setTimeout(() => ctl.close(true), 60000);
    await ctl.closed;
    clearTimeout(t);
  }

  async function removeKey(r) {
    const ok = await confirmBox({ title: `Remove the ${r.name} key?`, body: "The key is deleted from your vault. Searches with this tool go back to the free tier, if it has one.", confirmLabel: "Remove key", danger: true });
    if (!ok) return;
    try {
      await api.post(`/api/connections/${r.id}/delete_key`, {});
      toast("Key removed.", "ok", 2600);
      await load();
    } catch (e) {
      reportError(e, "The key was not removed.");
    }
  }

  try {
    await load();
  } catch (e) {
    if (S.alive) mount(list, errorPlate(e, null));
  }
  return () => S.dispose();
}
