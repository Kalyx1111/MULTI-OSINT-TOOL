// MULTI-OSINT-TOOL :: shared interface components. No innerHTML anywhere: every string becomes a text node (see mot_dom.js).
import { h, icon, copyText, clear } from "./mot_dom.js";
import * as api from "./mot_api.js";

let seq = 0;
export const uid = (p = "mot") => `${p}-${++seq}`;

export const TYPE_LABEL = { username: "Username", email: "Email address", domain: "Domain", ip: "IP address", phone: "Phone number", url: "Web address", hash: "Hash", keyword: "Name or keyword", password: "Password", image: "Face (photo)" };
export const TYPE_ORDER = ["username", "email", "domain", "ip", "phone", "url", "hash", "keyword", "password", "image"];
export const TYPE_EXAMPLE = {
  username: "e.g. jdoe_42", email: "e.g. name@example.com", domain: "e.g. example.com", ip: "e.g. 203.0.113.7", phone: "e.g. +14155552671 (international format)",
  url: "e.g. https://example.com/page", hash: "MD5, SHA-1 or SHA-256 (hex)", keyword: "e.g. Acme Holdings", password: "A password to check against breach data", image: "A short label for this photo (no file path)",
};

// ------------------------------------------------------------------------------------------------ scope (cleanup for views)
/** Collects timers and listeners so a view can release all of them in one call when the route changes. */
export function scope() {
  const fns = [];
  let dead = false;
  return {
    get alive() {
      return !dead;
    },
    add(fn) {
      fns.push(fn);
      return fn;
    },
    interval(fn, ms) {
      const t = setInterval(fn, ms);
      fns.push(() => clearInterval(t));
      return t;
    },
    timeout(fn, ms) {
      const t = setTimeout(fn, ms);
      fns.push(() => clearTimeout(t));
      return t;
    },
    listen(target, evt, fn, opts) {
      target.addEventListener(evt, fn, opts);
      fns.push(() => target.removeEventListener(evt, fn, opts));
    },
    dispose() {
      dead = true;
      while (fns.length) {
        try {
          fns.pop()();
        } catch (e) {
          console.error("cleanup failed", e);
        }
      }
    },
  };
}

// ------------------------------------------------------------------------------------------------ toasts
let toastHost = null;
export function toast(message, tone = "ok", ms = 5200) {
  if (!toastHost) {
    toastHost = h("div", { class: "toasts", role: "status", "aria-live": "polite" });
    document.body.appendChild(toastHost);
  }
  const ic = { ok: "check", warn: "warn", bad: "cross", info: "info" }[tone] || "info";
  const el = h("div", { class: "toast", vars: { "--tone": `var(--${tone === "accent" ? "accent" : tone})` } }, icon(ic), h("div", {}, String(message)));
  toastHost.appendChild(el);
  while (toastHost.children.length > 4) toastHost.firstChild.remove();
  const t = setTimeout(() => el.remove(), ms);
  el.addEventListener("click", () => {
    clearTimeout(t);
    el.remove();
  });
  return el;
}

/** Shows an API/JS error as a toast. A locked vault or a missing session is handled by the gate screen, so no toast for those. */
export function reportError(err, prefix = "") {
  if (err instanceof api.ApiError && (err.code === "locked" || err.code === "no_session")) return;
  const msg = (err && err.message) || "Something went wrong.";
  toast((prefix ? prefix + " " : "") + msg, "bad", 8000);
}

// ------------------------------------------------------------------------------------------------ small building blocks
export function para(...kids) {
  return h("p", {}, ...kids);
}

export function spinner(label = "Working") {
  return h("span", { class: "spinner", role: "status", "aria-label": label });
}

export function loadingPlate(text = "Loading…") {
  return h("div", { class: "empty" }, spinner(), h("p", {}, text));
}

export function chip(text, tone = "mute", ic = null, title = "") {
  return h("span", { class: "chip tone-" + tone, title: title || null }, ic ? icon(ic) : null, text);
}

export const STATUS = {
  ok: { label: "Findings", tone: "accent", icon: "check" },
  empty: { label: "Nothing found", tone: "mute", icon: "minus" },
  no_key: { label: "Needs a key", tone: "warn", icon: "key" },
  key_invalid: { label: "Key rejected", tone: "bad", icon: "cross" },
  plan_limit: { label: "Not in your plan", tone: "warn", icon: "lock" },
  rate_limited: { label: "Rate limited", tone: "warn", icon: "clock" },
  blocked: { label: "Blocked by shield", tone: "bad", icon: "shieldOff" },
  missing_tool: { label: "Not installed", tone: "warn", icon: "wrench" },
  handoff: { label: "Manual step", tone: "info", icon: "external" },
  skipped: { label: "Skipped", tone: "mute", icon: "minus" },
  error: { label: "Failed", tone: "bad", icon: "warn" },
  timeout: { label: "Timed out", tone: "bad", icon: "clock" },
  cancelled: { label: "Cancelled", tone: "mute", icon: "stop" },
  offline: { label: "Offline", tone: "warn", icon: "globe" },
  export: { label: "Export file", tone: "info", icon: "download" },
  unsupported: { label: "Not supported", tone: "mute", icon: "minus" },
};
export const statusInfo = (s) => STATUS[s] || { label: String(s || "Unknown").replace(/_/g, " "), tone: "mute", icon: "info" };
export const statusChip = (s) => {
  const i = statusInfo(s);
  return chip(i.label, i.tone, i.icon);
};

export const MODE = {
  keyed: { label: "Your key", tone: "accent" },
  free: { label: "Free tier", tone: "ok" },
  local: { label: "On this computer", tone: "mute" },
  handoff: { label: "Manual", tone: "info" },
  export: { label: "File", tone: "info" },
  none: { label: "", tone: "mute" },
};
export const modeChip = (m) => (MODE[m] && MODE[m].label ? chip(MODE[m].label, MODE[m].tone) : null);

/** Connection-row modes from /api/connections. */
export const CONN_MODE = {
  paid: { label: "Paid key active", tone: "accent", icon: "key" },
  free: { label: "Free tier", tone: "ok", icon: "check" },
  needs_key: { label: "Needs a key", tone: "warn", icon: "key" },
  handoff: { label: "Manual hand-off", tone: "info", icon: "external" },
  export: { label: "Export file", tone: "info", icon: "download" },
  catalog: { label: "Catalogue only", tone: "mute", icon: "book" },
  manual: { label: "Kept manual", tone: "mute", icon: "info" },
  research: { label: "Research required", tone: "warn", icon: "info" },
};
export const connModeChip = (m) => {
  const i = CONN_MODE[m] || { label: m, tone: "mute", icon: "info" };
  return chip(i.label, i.tone, i.icon);
};

export function banner({ tone = "info", title = "", body = null, actions = null, live = null }) {
  const ic = { ok: "shieldCheck", warn: "warn", bad: "shieldWarn", info: "info", accent: "info" }[tone] || "info";
  return h("div", { class: "banner tone-" + tone, role: live || (tone === "bad" ? "alert" : "status") }, icon(ic),
    h("div", { class: "banner-body" }, title ? h("strong", {}, title, body ? " " : "") : null, body),
    actions ? h("div", { class: "cluster-s" }, actions) : null);
}

export function emptyState({ ic = "search", title, text = "", action = null }) {
  return h("div", { class: "empty" }, icon(ic, "xl"), h("h3", { class: "h3" }, title), text ? h("p", { class: "measure" }, text) : null, action);
}

export function errorPlate(err, retry) {
  const msg = (err && err.message) || "Something went wrong.";
  return h("div", { class: "plate stack" }, banner({ tone: "bad", title: "This could not be loaded.", body: msg }),
    retry ? h("div", {}, h("button", { class: "btn", type: "button", on: { click: retry } }, icon("refresh", "s"), "Try again")) : null);
}

export function button({ label, kind = "", ic = null, onClick, type = "button", title = "", small = false, iconOnly = false, disabled = false, autofocus = false }) {
  const cls = ["btn", kind ? "btn-" + kind : "", small ? "btn-s" : "", iconOnly ? "btn-icon" : ""].filter(Boolean).join(" ");
  return h("button", { class: cls, type, title: title || null, "aria-label": iconOnly ? label : null, disabled, autofocus, on: onClick ? { click: onClick } : {} }, ic ? icon(ic, "s") : null, iconOnly ? null : label);
}

/** Disables a button and shows a spinner while `fn` runs. */
export async function withBusy(btn, fn) {
  if (!btn || btn.disabled) return undefined;
  const sp = spinner();
  btn.disabled = true;
  btn.setAttribute("aria-busy", "true");
  btn.insertBefore(sp, btn.firstChild);
  try {
    return await fn();
  } finally {
    sp.remove();
    btn.disabled = false;
    btn.removeAttribute("aria-busy");
  }
}

export function copyButton(text, label = "Copy") {
  return h("button", {
    class: "btn btn-quiet btn-s btn-icon", type: "button", title: label, "aria-label": label,
    on: { click: async () => toast((await copyText(text)) ? "Copied to the clipboard." : "Could not copy. Select the text and copy it by hand.", "ok", 2400) },
  }, icon("copy", "s"));
}

export function kvList(pairs) {
  const dl = h("dl", { class: "kv" });
  for (const [k, v] of pairs) {
    if (v === undefined || v === null || v === "") continue;
    dl.appendChild(h("dt", {}, k));
    dl.appendChild(h("dd", {}, v instanceof Node ? v : String(v)));
  }
  return dl;
}

export function pageHead({ eyebrow = "", title, lead = "", actions = null }) {
  return h("header", { class: "page-head" },
    h("div", {}, eyebrow ? h("p", { class: "tiny accent strong" }, eyebrow) : null, h("h1", { class: "display d-3", tabIndex: -1, "data-page-title": "" }, title), lead ? h("p", { class: "lead" }, lead) : null),
    actions ? h("div", { class: "cluster" }, actions) : null);
}

export function sectionHead(title, aside = null, level = "h2") {
  return h("div", { class: "section-head" }, h(level, { class: "display d-1" }, title), aside ? h("div", { class: "muted small" }, aside) : null);
}

/** 1..4 pips + a text label; confidence is 0..1. */
export function confidenceMeter(c) {
  const v = Math.max(0, Math.min(1, Number(c) || 0));
  const pips = v >= 0.85 ? 4 : v >= 0.6 ? 3 : v >= 0.35 ? 2 : 1;
  const label = pips === 4 ? "Strongly corroborated" : pips === 3 ? "Corroborated" : pips === 2 ? "Single source" : "Weak";
  const m = h("span", { class: "meter", role: "img", "aria-label": `Confidence: ${label}`, title: `Confidence: ${label}` });
  for (let i = 1; i <= 4; i++) m.appendChild(h("i", { class: i <= pips ? "on" : "" }));
  return m;
}

// ------------------------------------------------------------------------------------------------ switch / segmented / tabs / fields
export function switchEl({ checked = false, label, onChange, disabled = false, id }) {
  let on = !!checked;
  const el = h("button", { class: "switch", type: "button", role: "switch", id: id || uid("sw"), "aria-checked": String(on), "aria-label": label, disabled,
    on: { click: () => update(!on, true) } });
  function update(v, fire) {
    on = !!v;
    el.setAttribute("aria-checked", String(on));
    if (fire && onChange) onChange(on);
  }
  return { el, get checked() { return on; }, set(v) { update(v, false); } };
}

export function segmented({ options, value, label, onChange }) {
  let cur = value;
  const wrap = h("div", { class: "seg", role: "group", "aria-label": label });
  const btns = options.map((o) => h("button", { type: "button", "aria-pressed": String(o.value === cur), on: { click: () => set(o.value, true) } }, o.label));
  btns.forEach((b) => wrap.appendChild(b));
  function set(v, fire) {
    cur = v;
    options.forEach((o, i) => btns[i].setAttribute("aria-pressed", String(o.value === cur)));
    if (fire && onChange) onChange(cur);
  }
  return { el: wrap, get value() { return cur; }, set: (v) => set(v, false) };
}

export function tabs({ items, value, label = "Sections", onChange }) {
  let cur = value;
  const list = h("div", { class: "tabs", role: "tablist", "aria-label": label });
  const btns = new Map();
  function paint() {
    for (const [id, b] of btns) {
      b.setAttribute("aria-selected", String(id === cur));
      b.tabIndex = id === cur ? 0 : -1;
    }
  }
  for (const it of items) {
    const b = h("button", { class: "tab", type: "button", role: "tab", id: uid("tab"), "data-tab": it.id, on: { click: () => select(it.id) } },
      it.label, it.count !== undefined ? h("span", { class: "count" }, String(it.count)) : null);
    btns.set(it.id, b);
    list.appendChild(b);
  }
  list.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft" && e.key !== "Home" && e.key !== "End") return;
    const ids = items.map((i) => i.id);
    let i = ids.indexOf(cur);
    if (e.key === "ArrowRight") i = (i + 1) % ids.length;
    else if (e.key === "ArrowLeft") i = (i - 1 + ids.length) % ids.length;
    else if (e.key === "Home") i = 0;
    else i = ids.length - 1;
    e.preventDefault();
    select(ids[i]);
    btns.get(ids[i]).focus();
  });
  function select(id) {
    cur = id;
    paint();
    if (onChange) onChange(id);
  }
  paint();
  return {
    el: list,
    get value() { return cur; },
    set(id) { cur = id; paint(); },
    setCount(id, n) { const c = btns.get(id) && btns.get(id).querySelector(".count"); if (c) c.textContent = String(n); },
  };
}

/** A labelled control. `control` is the visible node; `target` is the element that receives the label/hint (defaults to control). */
export function field({ label, hint = "", control, target = null, error = "" }) {
  const t = target || control;
  if (!t.id) t.id = uid("f");
  const hid = hint ? uid("hint") : "";
  const eid = uid("err");
  if (hid) t.setAttribute("aria-describedby", hid);
  const err = h("p", { class: "hint is-error", id: eid, role: "alert" }, error);
  err.hidden = !error;
  const el = h("div", { class: "field" }, label ? h("label", { class: "label", for: t.id }, label) : null, control, hint ? h("p", { class: "hint", id: hid }, hint) : null, err);
  return {
    el,
    setError(msg) {
      err.textContent = msg || "";
      err.hidden = !msg;
      if (msg) t.setAttribute("aria-invalid", "true");
      else t.removeAttribute("aria-invalid");
    },
  };
}

export function textInput({ id, type = "text", value = "", placeholder = "", autocomplete = "off", maxlength = 0, inputmode = "", onInput, small = false, name = "" }) {
  const el = h("input", { class: "input" + (small ? " input-s" : ""), type, id: id || uid("in"), value, placeholder: placeholder || null, autocomplete, spellcheck: "false", autocapitalize: "off",
    maxlength: maxlength ? String(maxlength) : null, inputmode: inputmode || null, name: name || null, on: onInput ? { input: () => onInput(el.value) } : {} });
  return el;
}

export function pwInput({ id, autocomplete = "current-password", placeholder = "", onInput, autofocus = false }) {
  const input = h("input", { class: "input", type: "password", id: id || uid("pw"), autocomplete, placeholder: placeholder || null, spellcheck: "false", autocapitalize: "off", maxlength: "256",
    autofocus, on: onInput ? { input: () => onInput(input.value) } : {} });
  let shown = false;
  const tog = h("button", { class: "pw-toggle", type: "button", "aria-label": "Show password", "aria-pressed": "false", on: { click: () => {
    shown = !shown;
    input.type = shown ? "text" : "password";
    tog.setAttribute("aria-pressed", String(shown));
    tog.setAttribute("aria-label", shown ? "Hide password" : "Show password");
    clear(tog).appendChild(icon(shown ? "eyeOff" : "eye"));
    input.focus();
  } } }, icon("eye"));
  return { el: h("div", { class: "pw" }, input, tog), input, get value() { return input.value; }, wipe() { input.value = ""; } };
}

/** Mirrors the server's master-password rules (mot_vault.check_password_strength); the server stays the authority. */
export function assessPassword(pw) {
  const chars = Array.from(pw);
  const len = chars.length;
  const classes = [/[a-z]/, /[A-Z]/, /\p{Nd}/u, /[^\p{L}\p{N}_\s]/u].filter((r) => r.test(pw)).length;
  const uniq = new Set(chars).size;
  let problem = "";
  if (len === 0) problem = "";
  else if (len < 12) problem = `Use at least 12 characters (${12 - len} more).`;
  else if (len < 20 && classes < 3) problem = "Mix upper and lower case, digits and symbols (3 kinds), or make it a passphrase of 20+ characters.";
  else if (uniq < 6) problem = "That is too repetitive.";
  const ok = len > 0 && !problem;
  let level = 0;
  if (len > 0) level = !ok ? 1 : len >= 24 && classes >= 3 ? 4 : len >= 16 ? 3 : 2;
  return { ok, problem, level, len, classes };
}

export function strengthMeter() {
  const el = h("div", { class: "strength", role: "img", "aria-label": "Password strength", "data-level": "0" }, h("i"), h("i"), h("i"), h("i"));
  return {
    el,
    set(level) {
      el.setAttribute("data-level", String(level));
      el.setAttribute("aria-label", ["Password strength: not entered", "Password strength: too weak", "Password strength: acceptable", "Password strength: good", "Password strength: excellent"][level] || "Password strength");
    },
  };
}

// ------------------------------------------------------------------------------------------------ modal dialogs (native <dialog>: focus trap and Escape come from the browser)
/**
 * modal({title, lead, content[], actions[], wide, dismissible, onSubmit})
 * actions: [{label, kind, ic, value, autofocus, keep, onClick(ctl, btn), submit}]
 *  - no onClick -> closes with `value`;  onClick -> run, then closes unless `keep`;  submit:true -> the Enter key triggers it (needs onSubmit-less usage: it simply is the form's submit button).
 * Returns {el, body, foot, closed (Promise of the close value), close(value), busy(bool), setError(msg)}.
 */
export function modal({ title, lead = "", content = [], actions = [], wide = false, dismissible = true }) {
  const tid = uid("dt");
  let result = null;
  let resolve;
  let isBusy = false;
  const closed = new Promise((r) => (resolve = r));
  const errEl = h("p", { class: "hint is-error", role: "alert" });
  errEl.hidden = true;
  const body = h("div", { class: "modal-body" }, ...content, errEl);
  const foot = h("div", { class: "modal-foot" });
  const head = h("div", { class: "modal-head stack-s" }, h("h2", { class: "display d-1", id: tid }, title), lead ? h("p", { class: "muted small" }, lead) : null);
  const form = h("form", { novalidate: true }, head, body, foot);
  const dlg = h("dialog", { class: "modal" + (wide ? " modal-wide" : ""), "aria-labelledby": tid }, form);
  const ctl = {
    el: dlg, body, foot, closed,
    close(v = null) {
      result = v;
      if (dlg.open) dlg.close();
    },
    busy(on) {
      isBusy = !!on;
      for (const b of foot.querySelectorAll("button")) b.disabled = isBusy;
    },
    setError(msg) {
      errEl.textContent = msg || "";
      errEl.hidden = !msg;
    },
  };
  let submitAction = null;
  for (const a of actions) {
    const btn = h("button", { class: "btn" + (a.kind ? " btn-" + a.kind : ""), type: a.submit ? "submit" : "button", autofocus: !!a.autofocus }, a.ic ? icon(a.ic, "s") : null, a.label);
    const run = async () => {
      if (isBusy) return;
      if (!a.onClick) return ctl.close(a.value === undefined ? null : a.value);
      ctl.setError("");
      ctl.busy(true);
      const sp = spinner();
      btn.insertBefore(sp, btn.firstChild);
      try {
        const keep = await a.onClick(ctl, btn);
        if (!a.keep && keep !== false && dlg.open) ctl.close(a.value === undefined ? null : a.value);
      } catch (e) {
        if (e instanceof api.ApiError && (e.code === "locked" || e.code === "no_session")) ctl.close(null);
        else ctl.setError((e && e.message) || "That did not work.");
      } finally {
        sp.remove();
        ctl.busy(false);
      }
    };
    if (a.submit) submitAction = run;
    btn.addEventListener("click", (ev) => {
      if (a.submit) ev.preventDefault();
      run();
    });
    foot.appendChild(btn);
  }
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (submitAction) submitAction();
  });
  dlg.addEventListener("cancel", (e) => {
    if (!dismissible || isBusy) e.preventDefault();
  });
  dlg.addEventListener("mousedown", (e) => {
    if (e.target === dlg && dismissible && !isBusy) ctl.close(null);
  });
  const opener = document.activeElement;
  dlg.addEventListener("close", () => {
    dlg.remove();
    if (opener && opener.isConnected && typeof opener.focus === "function") opener.focus();
    resolve(result);
  });
  document.body.appendChild(dlg);
  dlg.showModal();
  return ctl;
}

export async function confirmBox({ title, body, confirmLabel = "Continue", cancelLabel = "Cancel", danger = false }) {
  const paras = (Array.isArray(body) ? body : [body]).filter(Boolean).map((b) => (b instanceof Node ? b : h("p", {}, b)));
  const ctl = modal({ title, content: paras, actions: [
    { label: cancelLabel, kind: "quiet", value: false, autofocus: danger },
    { label: confirmLabel, kind: danger ? "danger" : "primary", value: true, autofocus: !danger },
  ] });
  return (await ctl.closed) === true;
}

/**
 * Asks for the master password and runs `action(password)`. Errors from the server are shown inside the dialog and the dialog stays open.
 * Resolves with the action's result, or null when cancelled.
 */
export async function askPassword({ title = "Confirm with your master password", lead = "", confirmLabel = "Confirm", action }) {
  const pw = pwInput({ autocomplete: "current-password", autofocus: true });
  const f = field({ label: "Master password", control: pw.el, target: pw.input });
  let out = null;
  const ctl = modal({ title, lead, content: [f.el], actions: [
    { label: "Cancel", kind: "quiet", value: null },
    { label: confirmLabel, kind: "primary", submit: true, keep: true, onClick: async (c) => {
      if (!pw.value) {
        c.setError("Enter your master password.");
        return false;
      }
      out = await action(pw.value);
      pw.wipe();
      c.close(true);
      return false;
    } },
  ] });
  const closed = await ctl.closed;
  pw.wipe();
  return closed ? out : null;
}

export function notice({ title, body, buttonLabel = "Close" }) {
  const paras = (Array.isArray(body) ? body : [body]).filter(Boolean).map((b) => (b instanceof Node ? b : h("p", {}, b)));
  return modal({ title, content: paras, actions: [{ label: buttonLabel, kind: "primary", value: true, autofocus: true }] }).closed;
}

// ------------------------------------------------------------------------------------------------ links that leave the shield
/**
 * Vendor sign-up / API-key / documentation pages and the safety-guide links. The page never supplies a URL: it names (kind, id, which) and the
 * server resolves it from an allow-list. Opening happens in the person's ordinary browser, which is outside the shield, so we say so first.
 */
export async function openExternal(kind, ident, which, label = "") {
  let info;
  try {
    info = await api.post("/api/external/link", { kind, id: ident, which: String(which) });
  } catch (e) {
    reportError(e);
    return;
  }
  const urlBox = h("div", { class: "secret-box" }, h("span", { class: "tiny muted" }, label || "Address"), h("span", { class: "mono wrap-any" }, info.url));
  const ctl = modal({
    title: "This opens outside the shield",
    content: [
      h("p", {}, "The page opens in your normal browser. That browser is not protected by MULTI-OSINT-TOOL: ", h("strong", {}, info.host), " will see the network your computer is on, and an account you create there can be tied to you."),
      urlBox,
      h("p", { class: "small muted" }, "Safer: copy the link and open it in Tor Browser, or with your VPN on, using an alias e-mail that is not linked to your real identity."),
    ],
    actions: [
      { label: "Cancel", kind: "quiet", value: null, autofocus: true },
      { label: "Copy link", ic: "copy", keep: true, onClick: async () => {
        toast((await copyText(info.url)) ? "Link copied. Paste it into Tor Browser." : "Could not copy. Select the link and copy it by hand.", "ok", 3200);
        return false;
      } },
      { label: "Open in my browser", kind: "primary", ic: "external", keep: true, onClick: async (c) => {
        const r = await api.post("/api/external/open", { kind, id: ident, which: String(which), confirm: true });
        if (r.opened) toast(`Opened ${r.host} in your browser.`, "info", 3600);
        else {
          await copyText(r.url);
          toast("No browser could be opened from here. The link was copied instead.", "warn", 6000);
        }
        c.close(true);
        return false;
      } },
    ],
  });
  await ctl.closed;
}

/** An <a>-looking button that starts the openExternal flow (a real href would bypass the confirmation). */
export function externalLink(text, kind, ident, which, label = "") {
  return h("button", { class: "btn btn-quiet btn-s", type: "button", on: { click: () => openExternal(kind, ident, which, label || text) } }, icon("external", "s"), text);
}

// ------------------------------------------------------------------------------------------------ key file helper (vault gate)
export function readFileBase64(file, maxBytes = 512 * 1024) {
  return new Promise((resolve, reject) => {
    if (!file) return resolve("");
    if (file.size < 1 || file.size > maxBytes) return reject(new Error("A key file must be between 1 byte and 512 KiB."));
    const fr = new FileReader();
    fr.onerror = () => reject(new Error("That file could not be read."));
    fr.onload = () => {
      const bytes = new Uint8Array(fr.result);
      let bin = "";
      for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      resolve(btoa(bin));
    };
    fr.readAsArrayBuffer(file);
  });
}

/** Humanised seconds ("1 min 30 s"). */
export function waitText(s) {
  s = Math.max(0, Math.round(s));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  return `${m} min ${s % 60 ? (s % 60) + " s" : ""}`.trim();
}

// ------------------------------------------------------------------------------------------------ pop-up menu
let openMenu = null;
/**
 * popMenu({anchor, items:[{label, ic, value, selected, danger, sep}], onPick, label})
 * The menu is placed inside the anchor's nearest .menu-anchor. Closes on pick, Escape, Tab or a click elsewhere.
 */
export function popMenu({ anchor, host, items, onPick, label = "Menu" }) {
  if (openMenu) openMenu.close();
  const menu = h("div", { class: "menu menu-down", role: "menu", "aria-label": label });
  const btns = [];
  for (const it of items) {
    if (it.sep) {
      menu.appendChild(h("div", { class: "menu-sep", role: "separator" }));
      continue;
    }
    const b = h("button", { type: "button", role: it.selected !== undefined ? "menuitemradio" : "menuitem", "aria-checked": it.selected !== undefined ? String(!!it.selected) : null, class: it.danger ? "danger" : "",
      on: { click: () => {
        ctl.close(true);
        onPick(it.value);
      } } }, it.ic ? icon(it.ic, "s") : null, h("span", {}, it.label), it.selected ? h("span", { class: "push" }, icon("check", "s")) : null);
    btns.push(b);
    menu.appendChild(b);
  }
  const onKey = (e) => {
    if (e.key === "Escape") {
      e.preventDefault();
      ctl.close(true);
    } else if (e.key === "Tab") ctl.close(false);
    else if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Home" || e.key === "End") {
      e.preventDefault();
      const i = btns.indexOf(document.activeElement);
      const next = e.key === "Home" ? 0 : e.key === "End" ? btns.length - 1 : (i + (e.key === "ArrowDown" ? 1 : -1) + btns.length) % btns.length;
      btns[next].focus();
    }
  };
  const onDown = (e) => {
    if (!menu.contains(e.target) && !anchor.contains(e.target)) ctl.close(false);
  };
  const ctl = {
    close(refocus) {
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("pointerdown", onDown, true);
      menu.remove();
      anchor.setAttribute("aria-expanded", "false");
      if (refocus && anchor.isConnected) anchor.focus();
      if (openMenu === ctl) openMenu = null;
    },
  };
  (host || anchor.closest(".menu-anchor") || anchor.parentElement).appendChild(menu);
  anchor.setAttribute("aria-expanded", "true");
  document.addEventListener("keydown", onKey, true);
  document.addEventListener("pointerdown", onDown, true);
  const first = btns.find((b) => b.getAttribute("aria-checked") === "true") || btns[0];
  if (first) first.focus();
  openMenu = ctl;
  return ctl;
}
