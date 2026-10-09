// MULTI-OSINT-TOOL :: application shell. Boot, session, router, top bar, background checks.
// Screens are loaded on demand (dynamic import), so a fault in one screen can never stop the others from opening.
import { h, icon, clear, mount } from "./mot_dom.js";
import * as api from "./mot_api.js";
import { state, loadConns, loadShield, loadRecovery, applyTheme, rememberedTheme, resetState } from "./mot_state.js";
import { toast, modal, banner, button, scope, errorPlate } from "./mot_ui.js";
import { brandMark, ensureRosetteSymbol } from "./mot_rosette.js";

const root = document.getElementById("root");

const NAV = [
  { id: "search", label: "Search", ic: "search", href: "#/" },
  { id: "cases", label: "Cases", ic: "folder", href: "#/cases" },
  { id: "connections", label: "Connections", ic: "plug", href: "#/connections" },
  { id: "health", label: "Health", ic: "pulse", href: "#/health" },
  { id: "settings", label: "Settings", ic: "sliders", href: "#/settings" },
];

const searchRoute = { nav: "search", title: "Search", mod: () => import("./mot_view_search.js"), fn: "mountSearch" };
const ROUTES = {
  "": searchRoute,
  search: searchRoute,
  run: { nav: "search", title: "Search results", mod: () => import("./mot_view_results.js"), fn: "mountRun" },
  cases: { nav: "cases", title: "Cases", mod: () => import("./mot_view_cases.js"), fn: "mountCases" },
  case: { nav: "cases", title: "Case", mod: () => import("./mot_view_results.js"), fn: "mountCase" },
  connections: { nav: "connections", title: "Connections", mod: () => import("./mot_view_connections.js"), fn: "mountConnections" },
  shield: { nav: "shield", title: "Network shield", mod: () => import("./mot_view_shield.js"), fn: "mountShield" },
  health: { nav: "health", title: "Health", mod: () => import("./mot_view_health.js"), fn: "mountHealth" },
  settings: { nav: "settings", title: "Settings", mod: () => import("./mot_view_settings.js"), fn: "mountSettings" },
};

const app = { shell: null, cleanup: null, token: 0, S: null, gateOpen: false, lastTouch: 0, offlineStrip: null, failures: 0, lastErrorToast: 0 };

// ------------------------------------------------------------------------------------------------ small helpers
const setTitle = (t) => {
  document.title = t ? `${t} · MULTI-OSINT-TOOL` : "MULTI-OSINT-TOOL";
};

function parseHash() {
  const m = /^#\/([a-z]*)(?:\/([A-Za-z0-9_-]{1,40}))?\/?$/.exec(location.hash || "#/");
  return m ? { name: m[1], arg: m[2] || "" } : { name: "?", arg: "" };
}

function runCleanup(c) {
  try {
    if (typeof c === "function") c();
    else if (c && typeof c.dispose === "function") c.dispose();
  } catch (e) {
    console.error("view cleanup failed", e);
  }
}

// ------------------------------------------------------------------------------------------------ connection loss strip (works on every screen)
function setOffline(on_) {
  if (on_ && !app.offlineStrip) {
    app.offlineStrip = h("div", { class: "net-strip", role: "alert" }, "MULTI-OSINT-TOOL is not responding. Trying to reconnect…");
    document.body.appendChild(app.offlineStrip);
    startReconnect();
  } else if (!on_ && app.offlineStrip) {
    app.offlineStrip.remove();
    app.offlineStrip = null;
    stopReconnect();
    refreshAfterReconnect();
  }
}
let reconnectTimer = 0;
function startReconnect() {
  stopReconnect();
  reconnectTimer = setInterval(() => api.get("/api/ping").catch(() => {}), 3000);
}
function stopReconnect() {
  clearInterval(reconnectTimer);
  reconnectTimer = 0;
}
async function refreshAfterReconnect() {
  try {
    const s = await api.get("/api/session"); // also refreshes the CSRF token
    api.setCsrf(s.csrf);
    state.status = s.status;
    if (s.status.state === "unlocked") {
      if (!app.shell && !app.gateOpen) await enterApp();
    } else if (!app.gateOpen) {
      await leaveToGate(s.status, app.shell ? "MULTI-OSINT-TOOL restarted, so the vault is locked. Enter your password to continue." : "");
    }
  } catch (_) {
    /* the next poll will try again */
  }
}

// ------------------------------------------------------------------------------------------------ screens without a vault session
function plainScreen({ title, lead, body = null, actions = null }) {
  app.shell = null;
  mount(root, h("main", { class: "gate" }, h("div", { class: "gate-card cert" },
    h("div", { class: "gate-brand" }, brandMark(), h("span", { class: "wordmark" }, "MULTI-OSINT-TOOL")),
    h("h1", { class: "display d-2" }, title), h("p", { class: "muted" }, lead), body, actions)));
}

function showNoSession() {
  plainScreen({
    title: "Open it from its own window",
    lead: "This browser tab has no secure session with MULTI-OSINT-TOOL. The launcher opens a private window for you; if you closed it, start the tool again, or type link in its terminal window to get a fresh single-use launch link.",
    actions: button({ label: "Try again", kind: "primary", ic: "refresh", onClick: () => location.reload() }),
  });
}

function showStopped() {
  plainScreen({
    title: "MULTI-OSINT-TOOL is not running",
    lead: "This page cannot reach the program on your computer. Start it again from its folder (the launcher file); this page will reconnect on its own.",
    actions: button({ label: "Try again", kind: "primary", ic: "refresh", onClick: () => connect() }),
  });
  setTimeout(() => {
    if (!app.shell && !app.gateOpen) connect();
  }, 4000);
}

// ------------------------------------------------------------------------------------------------ gate (create / unlock)
async function leaveToGate(status, notice = "") {
  if (app.gateOpen) return;
  teardownApp();
  await showGate(status, notice);
}

async function showGate(status, notice = "") {
  app.gateOpen = true;
  state.status = status;
  clear(root);
  try {
    const mod = await import("./mot_view_gate.js");
    mod.mountGate(root, { mode: status.state === "no_vault" ? "create" : "unlock", needsKeyfile: !!status.needs_keyfile, notice }, {
      async done(st) {
        state.status = st;
        app.gateOpen = false;
        await enterApp();
      },
    });
  } catch (e) {
    console.error("gate failed", e);
    plainScreen({ title: "The sign-in screen could not be loaded", lead: "A program file is missing or damaged. Close MULTI-OSINT-TOOL and run its Health check (mot_main.py doctor) from the terminal.", actions: button({ label: "Try again", ic: "refresh", onClick: () => location.reload() }) });
  }
}

// ------------------------------------------------------------------------------------------------ lawful-use acknowledgement (shown once per notice version)
async function lawfulUse() {
  const items = [
    "I will use MULTI-OSINT-TOOL only for lawful purposes, such as security research, due diligence, journalism, fraud prevention, or checking my own exposure.",
    "I have a legitimate reason to look up each target, and I will not use results to stalk, harass, intimidate or discriminate against anyone.",
    "I will follow the laws that apply to me and the terms of every service I connect, including the rules on breach data and on face search.",
    "I understand results are leads to verify, not proof, and that the exposure score is only a heuristic.",
    "I understand the tool reduces, but cannot remove, the chance of being identified. I stay responsible for my VPN, Tor, device and account hygiene.",
  ];
  const ctl = modal({
    title: "Before you search", dismissible: false, wide: true,
    lead: "MULTI-OSINT-TOOL gathers public and lawfully accessible information and can query breach and leak indexes. Please confirm:",
    content: [h("ol", { class: "steps" }, ...items.map((t) => h("li", {}, t)))],
    actions: [
      { label: "Decline and lock", kind: "quiet", value: false },
      { label: "I understand and accept", kind: "primary", autofocus: true, keep: true, onClick: async (c) => {
        await api.post("/api/ack", {});
        state.status = Object.assign({}, state.status, { ack_ok: true });
        c.close(true);
        return false;
      } },
    ],
  });
  return (await ctl.closed) === true;
}

// ------------------------------------------------------------------------------------------------ the app proper
async function enterApp() {
  const st = state.status || {};
  applyTheme(st.theme === "light" ? "light" : st.theme === "dark" ? "dark" : rememberedTheme());
  if (!st.ack_ok) {
    clear(root);
    if (!(await lawfulUse())) {
      try {
        const next = await api.post("/api/vault/lock", {});
        await showGate(next, "");
      } catch (_) {
        location.reload();
      }
      return;
    }
  }
  buildShell();
  startBackground();
  if (st.restored_from_backup) {
    addBanner("restored", banner({ tone: "warn", title: "Your vault file was damaged and has been restored from its backup copy.", body: "Check that your API keys and cases are all there. Open Health for details." }));
  }
  loadConns().catch(() => {});
  loadShield().then(paintSeal).catch(() => {});
  api.post("/api/shield/verify", {}).then((s) => {
    state.shield = s;
    paintSeal();
  }).catch(() => {});
  refreshRecovery();
  await route();
}

function teardownApp() {
  if (app.S) app.S.dispose();
  app.S = null;
  app.token++;
  if (app.cleanup) runCleanup(app.cleanup);
  app.cleanup = null;
  app.shell = null;
  resetState();
  clear(root);
}

// ---- shell
function buildShell() {
  clear(root);
  ensureRosetteSymbol();
  const navLinks = new Map();
  const badges = new Map();
  const nav = h("nav", { class: "nav", "aria-label": "Main" });
  for (const n of NAV) {
    const badge = h("span", { class: "nav-badge", hidden: true, "aria-hidden": "true" });
    const a = h("a", { class: "nav-link", href: n.href, "data-nav": n.id }, icon(n.ic), h("span", { class: "label-text" }, n.label), badge);
    navLinks.set(n.id, a);
    badges.set(n.id, badge);
    nav.appendChild(a);
  }
  const seal = h("a", { class: "seal", href: "#/shield", "data-nav": "shield" });
  const themeBtn = h("button", { class: "btn btn-quiet btn-icon", type: "button", on: { click: toggleTheme } });
  const lockBtn = button({ label: "Lock the vault", kind: "quiet", ic: "lock", iconOnly: true, title: "Lock the vault", onClick: lockNow });
  const panicBtn = button({ label: "Panic: lock now, stop everything, wipe temporary files", kind: "danger", ic: "power", iconOnly: true, title: "Panic: lock now, stop everything, wipe temporary files", onClick: panic });
  const skip = h("button", { class: "skip", type: "button", on: { click: () => main.focus() } }, "Skip to content");
  const bannerHost = h("div", { class: "page banners", "aria-live": "polite", hidden: true });
  const main = h("main", { class: "main", id: "main", tabIndex: -1 });
  const top = h("header", { class: "topbar" },
    h("a", { class: "brand", href: "#/", "aria-label": "MULTI-OSINT-TOOL, home" }, brandMark(), h("span", { class: "wordmark" }, "MULTI-OSINT-TOOL")),
    nav, h("div", { class: "topbar-end" }, seal, themeBtn, lockBtn, panicBtn));
  const foot = h("footer", { class: "foot" },
    h("span", {}, `MULTI-OSINT-TOOL ${state.status && state.status.version ? "v" + state.status.version : ""}`.trim()),
    h("span", {}, "Everything stays on this computer. Network tools run only behind the shield. Lawful use only."));
  mount(root, h("div", { class: "shell" }, skip, top, bannerHost, main, foot));
  app.shell = { main, seal, nav: navLinks, badges, bannerHost, themeBtn, banners: new Map() };
  paintTheme();
  paintSeal();
}

function paintTheme() {
  if (!app.shell) return;
  const light = document.documentElement.getAttribute("data-theme") === "light";
  const b = app.shell.themeBtn;
  mount(b, icon(light ? "moon" : "sun"));
  b.setAttribute("aria-label", light ? "Switch to the dark theme" : "Switch to the light theme");
  b.title = light ? "Dark theme" : "Light theme";
}

async function toggleTheme() {
  const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  applyTheme(next);
  paintTheme();
  api.post("/api/settings", { theme: next }).catch(() => {});
}

function paintSeal() {
  if (!app.shell) return;
  const s = app.shell.seal;
  const sh = state.shield;
  const st = sh && sh.state;
  let tone = "var(--ink-2)";
  let ic = "shield";
  let text = "Checking shield";
  let mode = "";
  if (st && st.age !== null && st.age !== undefined) {
    const modes = Object.fromEntries(((sh && sh.modes) || []).map((m) => [m.id, m.name]));
    mode = modes[st.mode || sh.mode] || "";
    if (st.ok) {
      tone = "var(--ok)";
      ic = "shieldCheck";
      text = "Shielded";
    } else if (st.offline) {
      tone = "var(--warn)";
      ic = "shieldWarn";
      text = "Offline";
    } else {
      tone = "var(--bad)";
      ic = "shieldOff";
      text = "Not shielded";
    }
  }
  mount(s, icon(ic), h("span", {}, text), mode ? h("span", { class: "seal-mode" }, mode) : null);
  s.style.setProperty("--tone", tone);
  s.setAttribute("aria-label", `Network shield: ${text}${mode ? ", " + mode : ""}. Open shield details.`);
}

function paintNav(id) {
  if (!app.shell) return;
  for (const [k, a] of app.shell.nav) {
    if (k === id) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  if (id === "shield") app.shell.seal.setAttribute("aria-current", "page");
  else app.shell.seal.removeAttribute("aria-current");
}

function paintBadges() {
  if (!app.shell) return;
  const b = app.shell.badges.get("health");
  if (!b) return;
  const n = state.pending + (state.crash ? 1 : 0);
  b.hidden = n === 0;
  b.textContent = n ? String(n) : "";
}

function addBanner(id, node) {
  if (!app.shell) return;
  removeBanner(id);
  app.shell.banners.set(id, node);
  app.shell.bannerHost.appendChild(node);
  app.shell.bannerHost.hidden = false;
}
function removeBanner(id) {
  if (!app.shell) return;
  const old = app.shell.banners.get(id);
  if (old) old.remove();
  app.shell.banners.delete(id);
  app.shell.bannerHost.hidden = app.shell.banners.size === 0;
}

async function refreshRecovery() {
  try {
    await loadRecovery();
  } catch (_) {
    return;
  }
  paintBadges();
  if (state.crash || state.pending) {
    const n = state.pending;
    addBanner("recovery", banner({
      tone: "warn",
      title: state.crash ? "MULTI-OSINT-TOOL did not close cleanly last time." : "Unfinished searches were found.",
      body: n ? `${n} search${n === 1 ? "" : "es"} can be resumed or saved as a case. Nothing was lost.` : "Run a health check to make sure everything is in order.",
      actions: h("a", { class: "btn btn-s", href: "#/health" }, "Review"),
    }));
  } else removeBanner("recovery");
}

// ---- actions
async function lockNow() {
  try {
    const st = await api.post("/api/vault/lock", {});
    await leaveToGate(st, "The vault is locked.");
  } catch (e) {
    if (!(e instanceof api.ApiError && e.code === "locked")) toast(e.message, "bad");
  }
}

async function panic() {
  try {
    const st = await api.post("/api/panic", {});
    await leaveToGate(st, "Panic lock done: searches stopped, the vault is locked, temporary files were removed.");
  } catch (e) {
    toast(e.message || "Could not run the panic lock.", "bad");
  }
}

// ---- router
const ctx = {
  go(hash) {
    location.hash = hash;
  },
  setTitle,
  paintSeal,
  refreshRecovery,
  banner: { add: addBanner, remove: removeBanner },
};

async function route() {
  if (!app.shell) return;
  const token = ++app.token;
  const { name, arg } = parseHash();
  const def = ROUTES[name];
  if (!def) {
    location.replace("#/");
    return;
  }
  if (app.cleanup) runCleanup(app.cleanup);
  app.cleanup = null;
  const view = h("div", { class: "view" });
  mount(app.shell.main, view);
  paintNav(def.nav);
  setTitle(def.title);
  window.scrollTo(0, 0);
  try {
    const mod = await def.mod();
    if (token !== app.token) return;
    const cleanup = await mod[def.fn](view, { name, arg }, ctx);
    if (token !== app.token) {
      runCleanup(cleanup);
      return;
    }
    app.cleanup = cleanup || null;
  } catch (e) {
    if (token !== app.token) return;
    console.error("screen failed", name, e);
    const shown = e instanceof api.ApiError ? e : new Error("This screen could not be opened. Try again, or open Health.");
    mount(view, h("div", { class: "page" }, errorPlate(shown, () => route())));
  }
  if (token === app.token && app.shell && !view.contains(document.activeElement)) app.shell.main.focus({ preventScroll: true });
}

// ------------------------------------------------------------------------------------------------ background upkeep
function startBackground() {
  if (app.S) app.S.dispose();
  const S = (app.S = scope());
  S.interval(async () => {
    try {
      const st = await api.get("/api/ping");
      state.status = st;
      if (st.state !== "unlocked") await leaveToGate(st, "The vault was locked. Enter your password to continue.");
    } catch (_) {
      /* offline handling is done by the api client */
    }
  }, 15000);
  S.interval(() => loadShield().then(paintSeal).catch(() => {}), 12000);
  S.interval(() => refreshRecovery(), 60000);
  const touch = () => {
    const now = Date.now();
    if (now - app.lastTouch < 45000 || !app.shell) return;
    app.lastTouch = now;
    api.post("/api/touch", {}).catch(() => {});
  };
  S.listen(document, "pointerdown", touch, { passive: true });
  S.listen(document, "keydown", touch, { passive: true });
  S.listen(document, "visibilitychange", () => {
    if (document.visibilityState === "visible") api.get("/api/ping").then((st) => {
      state.status = st;
      if (st.state !== "unlocked") leaveToGate(st, "The vault was locked. Enter your password to continue.");
    }).catch(() => {});
  });
}

// ------------------------------------------------------------------------------------------------ boot
async function connect() {
  if (app.shell || app.gateOpen) return;
  try {
    const s = await api.get("/api/session");
    api.setCsrf(s.csrf);
    state.status = s.status;
    if (s.status.state === "unlocked") await enterApp();
    else await showGate(s.status, "");
  } catch (e) {
    if (e instanceof api.ApiError && e.code === "no_session") showNoSession();
    else if (e instanceof api.ApiError && e.code === "offline") showStopped();
    else {
      console.error("boot failed", e);
      plainScreen({ title: "Something went wrong while starting", lead: (e && e.message) || "Unknown error.", actions: button({ label: "Try again", kind: "primary", ic: "refresh", onClick: () => location.reload() }) });
    }
  }
}

window.addEventListener("hashchange", () => route());
function softError(e) {
  console.error("unexpected interface error", e);
  const now = Date.now();
  if (now - app.lastErrorToast > 15000) {
    app.lastErrorToast = now;
    toast("Something unexpected happened in the interface. If it repeats, open Health.", "warn", 7000);
  }
}
window.addEventListener("error", (ev) => softError(ev.error || ev.message));
window.addEventListener("unhandledrejection", (ev) => {
  const r = ev.reason;
  if (r instanceof api.ApiError) return; // already shown where it happened
  softError(r);
});

api.setHooks({
  locked: () => {
    api.get("/api/ping").then((st) => {
      state.status = st;
      if (st.state !== "unlocked") leaveToGate(st, "The vault is locked. Enter your password to continue.");
    }).catch(() => {});
  },
  noSession: () => {
    teardownApp();
    showNoSession();
  },
  offline: () => setOffline(true),
  online: () => setOffline(false),
});

applyTheme(rememberedTheme());
ensureRosetteSymbol();
connect();

