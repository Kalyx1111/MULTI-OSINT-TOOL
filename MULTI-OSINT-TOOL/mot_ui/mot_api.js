// MULTI-OSINT-TOOL :: API client. Same-origin only, JSON only, CSRF header on every state change.
// Nothing sensitive ever goes into a URL: only opaque ids and short enumerations.

export class ApiError extends Error {
  constructor(message, status, code, extra) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.extra = extra || {};
  }
}

const hooks = { locked: null, noSession: null, offline: null, online: null };
let csrf = "";
let offline = false;

export function setHooks(h) {
  Object.assign(hooks, h);
}
export function setCsrf(v) {
  csrf = String(v || "");
}

async function call(method, path, body) {
  const init = { method, credentials: "same-origin", cache: "no-store", redirect: "error", headers: {} };
  if (method === "POST") {
    init.headers["Content-Type"] = "application/json";
    init.headers["X-MOT-CSRF"] = csrf;
    init.body = JSON.stringify(body || {});
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch (_) {
    if (!offline) {
      offline = true;
      if (hooks.offline) hooks.offline();
    }
    throw new ApiError("MULTI-OSINT-TOOL is not responding. If it restarted, this page reconnects by itself.", 0, "offline");
  }
  if (offline) {
    offline = false;
    if (hooks.online) hooks.online();
  }
  const ctype = res.headers.get("content-type") || "";
  const disp = res.headers.get("content-disposition") || "";
  if (res.ok && /^attachment/i.test(disp)) return res; // a file (even a .json export is a file, not an API envelope)
  if (ctype.includes("application/json")) {
    let j = null;
    try {
      j = await res.json();
    } catch (_) {
      throw new ApiError("The reply could not be read.", res.status, "bad_reply");
    }
    if (res.ok && j && j.ok) return j.data;
    const err = new ApiError((j && j.error) || "The request failed.", res.status, (j && j.code) || "error", j || {});
    if (err.code === "locked" || res.status === 423) {
      if (hooks.locked) hooks.locked();
    } else if (err.code === "no_session") {
      if (hooks.noSession) hooks.noSession();
    }
    throw err;
  }
  if (!res.ok) throw new ApiError(`Unexpected reply (${res.status}).`, res.status, "bad_reply");
  return res; // a download
}

export const get = (path) => call("GET", path);
export const post = (path, body) => call("POST", path, body);

/** Fetches a file and hands it to the browser's save dialog: GET when `body` is undefined, otherwise POST. */
export async function download(path, fallbackName, body) {
  const res = await call(body === undefined ? "GET" : "POST", path, body);
  const blob = await res.blob();
  const cd = res.headers.get("content-disposition") || "";
  const m = /filename="([^"]+)"/.exec(cd);
  saveBlob(blob, m ? m[1] : fallbackName);
}

export function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

export const q = (obj) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? "?" + s : "";
};
