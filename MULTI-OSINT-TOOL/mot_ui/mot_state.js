// MULTI-OSINT-TOOL :: shared client state (in memory only; nothing is written to browser storage except the theme name).
import * as api from "./mot_api.js";

export const state = {
  status: null, // /api/ping payload: {state: no_vault|locked|unlocked, theme, ack_ok, ...}
  shield: null, // /api/shield payload (last known)
  conns: new Map(), // id -> connection row
  connList: [],
  connSummary: null,
  pending: 0, // recoverable searches waiting
  crash: false,
};

const listeners = new Map();
export function on(evt, fn) {
  if (!listeners.has(evt)) listeners.set(evt, new Set());
  listeners.get(evt).add(fn);
  return () => listeners.get(evt).delete(fn);
}
export function emit(evt, data) {
  for (const fn of listeners.get(evt) || []) {
    try {
      fn(data);
    } catch (e) {
      console.error("listener failed", evt, e);
    }
  }
}

export async function loadConns(force = false) {
  if (state.connList.length && !force) return state.connList;
  const d = await api.get("/api/connections");
  state.connList = d.connections;
  state.connSummary = d.summary;
  state.conns = new Map(d.connections.map((c) => [c.id, c]));
  emit("conns", d);
  return state.connList;
}

/** Forgets everything held in memory (called when the vault locks). */
export function resetState() {
  state.shield = null;
  state.conns = new Map();
  state.connList = [];
  state.connSummary = null;
  state.pending = 0;
  state.crash = false;
}

export const connName = (id) => (state.conns.get(id) || {}).name || id;

export async function loadShield() {
  state.shield = await api.get("/api/shield");
  emit("shield", state.shield);
  return state.shield;
}

export async function loadRecovery() {
  const r = await api.get("/api/recovery");
  state.pending = (r.pending || []).length;
  state.crash = !!r.crash;
  emit("recovery", r);
  return r;
}

// ------------------------------------------------------------------------------------------------ theme
export function applyTheme(theme) {
  const t = theme === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", t);
  try {
    localStorage.setItem("mot_theme", t); // a colour name only; harmless if blocked
  } catch (_) {
    /* private window or blocked storage: the server value wins next load */
  }
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (meta) meta.setAttribute("content", t);
  return t;
}

export function rememberedTheme() {
  try {
    return localStorage.getItem("mot_theme") === "light" ? "light" : "dark";
  } catch (_) {
    return "dark";
  }
}
