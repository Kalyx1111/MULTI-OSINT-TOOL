// MULTI-OSINT-TOOL :: tiny DOM toolkit. There is deliberately NO innerHTML anywhere in this interface:
// every string from the server or from a third-party tool becomes a text node, so it can never become markup.
const SVG_NS = "http://www.w3.org/2000/svg";
const PROPS = new Set(["value", "checked", "disabled", "selected", "hidden", "open", "required", "readOnly", "tabIndex", "indeterminate", "multiple", "autofocus"]);
const SAFE_HREF = /^(#\/[A-Za-z0-9_\-/.]*|\/api\/[A-Za-z0-9_\-/.?=&%]*)$/;

function addChildren(el, kids) {
  for (const k of kids) {
    if (k === null || k === undefined || k === false || k === true) continue;
    if (Array.isArray(k)) addChildren(el, k);
    else if (k instanceof Node) el.appendChild(k);
    else el.appendChild(document.createTextNode(String(k)));
  }
}

function applyProps(el, props, isSvg) {
  for (const [key, val] of Object.entries(props || {})) {
    if (val === null || val === undefined || val === false) continue;
    if (key === "class") el.setAttribute("class", val);
    else if (key === "text") el.textContent = String(val);
    else if (key === "on") for (const [ev, fn] of Object.entries(val)) el.addEventListener(ev, fn);
    else if (key === "vars") for (const [k, v] of Object.entries(val)) el.style.setProperty(k, String(v)); // CSSOM is allowed by the CSP; style="" attributes are not
    else if (key === "for") el.htmlFor = val;
    else if (key === "href" && !isSvg) {
      if (!SAFE_HREF.test(String(val))) throw new Error("Blocked href: only in-app routes and /api/ downloads are allowed");
      el.setAttribute("href", val);
    } else if (!isSvg && PROPS.has(key)) el[key] = val;
    else if (key === "href" || key === "src" || key.toLowerCase().startsWith("on")) {
      if (!(isSvg && key === "href" && String(val).startsWith("#"))) throw new Error("Blocked attribute: " + key);
      el.setAttribute("href", val);
    } else el.setAttribute(key, val === true ? "" : String(val));
  }
}

/** h("div", {class: "x", on: {click: fn}}, "text", child, [more]) */
export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  applyProps(el, props, false);
  addChildren(el, kids);
  return el;
}

export function svg(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  applyProps(el, attrs, true);
  addChildren(el, kids);
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function mount(el, ...kids) {
  clear(el);
  addChildren(el, kids);
  return el;
}

// ------------------------------------------------------------------------------------------------ icons
const I = {
  search: '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/>',
  folder: '<path d="M3.5 7.5A1.5 1.5 0 0 1 5 6h4l2 2h8a1.5 1.5 0 0 1 1.5 1.5V18a1.5 1.5 0 0 1-1.5 1.5H5A1.5 1.5 0 0 1 3.5 18z"/>',
  plug: '<path d="M9 3v5M15 3v5M6.5 8h11v3.5a5.5 5.5 0 0 1-11 0zM12 17v4"/>',
  shield: '<path d="M12 3l7.5 2.8v5.4c0 4.6-3.1 8.2-7.5 9.8-4.4-1.6-7.5-5.2-7.5-9.8V5.8z"/>',
  shieldCheck: '<path d="M12 3l7.5 2.8v5.4c0 4.6-3.1 8.2-7.5 9.8-4.4-1.6-7.5-5.2-7.5-9.8V5.8z"/><path d="M8.8 12l2.4 2.4 4.2-4.6"/>',
  shieldOff: '<path d="M12 3l7.5 2.8v5.4c0 4.6-3.1 8.2-7.5 9.8-4.4-1.6-7.5-5.2-7.5-9.8V5.8z"/><path d="M9 9l6 6M15 9l-6 6"/>',
  shieldWarn: '<path d="M12 3l7.5 2.8v5.4c0 4.6-3.1 8.2-7.5 9.8-4.4-1.6-7.5-5.2-7.5-9.8V5.8z"/><path d="M12 8.5v4.2M12 15.4v.1"/>',
  pulse: '<path d="M3 12h4l2.2-6 4 12 2.4-6H21"/>',
  sliders: '<path d="M4 7h8M17 7h3M4 12h3M12 12h8M4 17h10M19 17h1"/><circle cx="14.5" cy="7" r="2"/><circle cx="9.5" cy="12" r="2"/><circle cx="16.5" cy="17" r="2"/>',
  lock: '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>',
  unlock: '<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8 10.5V8a4 4 0 0 1 7.6-1.7"/>',
  key: '<circle cx="8" cy="15" r="3.5"/><path d="M10.5 12.5L20 3M16.5 6.5L19 9M13.5 9.5L15.5 11.5"/>',
  external: '<path d="M14 4h6v6M20 4l-9 9M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  warn: '<path d="M12 4l9 16H3z"/><path d="M12 10v4.5M12 17.2v.1"/>',
  cross: '<path d="M6 6l12 12M18 6L6 18"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.5M12 7.6v.1"/>',
  copy: '<rect x="8.5" y="8.5" width="11" height="11" rx="1.5"/><path d="M15.5 8.5V6A1.5 1.5 0 0 0 14 4.5H6A1.5 1.5 0 0 0 4.5 6v8A1.5 1.5 0 0 0 6 15.5h2.5"/>',
  download: '<path d="M12 4v11M7.5 10.5L12 15l4.5-4.5M5 19.5h14"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/><path d="M4 4l16 16"/>',
  trash: '<path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13M10 11v5.5M14 11v5.5"/>',
  play: '<path d="M7 5l12 7-12 7z"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="1.5"/>',
  refresh: '<path d="M20 11a8 8 0 0 0-14.5-4M4 4v4h4M4 13a8 8 0 0 0 14.5 4M20 20v-4h-4"/>',
  chevronDown: '<path d="M6 9l6 6 6-6"/>',
  chevronRight: '<path d="M9 6l6 6-6 6"/>',
  wrench: '<path d="M14.5 6.5a4 4 0 0 0-5 5L4 17l3 3 5.5-5.5a4 4 0 0 0 5-5l-2.5 2.5-2.5-.5-.5-2.5z"/>',
  onion: '<path d="M12 3c3.5 3 6 6 6 9.5S15.5 21 12 21s-6-4.500-6-8.500S8.500 6 12 3z"/><path d="M12 3v18M9 6.500C7.500 9 7.500 16 9.500 20M15 6.500c1.500 2.500 1.500 9.500-.5 13.500"/>',
  globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c3 3.500 3 13.500 0 17M12 3.500c-3 3.500-3 13.500 0 17"/>',
  mail: '<rect x="3.500" y="5.500" width="17" height="13" rx="2"/><path d="M4 7l8 6 8-6"/>',
  user: '<circle cx="12" cy="8.500" r="3.500"/><path d="M5 20c.8-4 3.600-6 7-6s6.200 2 7 6"/>',
  network: '<circle cx="12" cy="5.500" r="2"/><circle cx="5.500" cy="17.500" r="2"/><circle cx="18.500" cy="17.500" r="2"/><path d="M12 7.500v4M12 11.500l-5.200 4.500M12 11.500l5.200 4.500"/>',
  phone: '<path d="M6.500 4h3l1.500 4-2 1.500a11 11 0 0 0 5.500 5.500l1.500-2 4 1.500v3A2 2 0 0 1 18 19C10.500 19 5 13.500 5 6a2 2 0 0 1 1.500-2z"/>',
  hash: '<path d="M9 4L7 20M17 4l-2 16M4.500 9h15M3.500 15h15"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.700 0l3-3a4 4 0 0 0-5.700-5.700l-1 1M14 10a4 4 0 0 0-5.700 0l-3 3a4 4 0 0 0 5.700 5.700l1-1"/>',
  tag: '<path d="M3.500 12.500V5a1.500 1.500 0 0 1 1.500-1.500h7.500l8 8-9 9z"/><circle cx="8" cy="8" r="1.200"/>',
  image: '<rect x="4" y="5" width="16" height="14" rx="2"/><circle cx="9" cy="10" r="1.600"/><path d="M5 17l4.500-4.500 3 3L15 13l4 4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  clock: '<circle cx="12" cy="12" r="8.500"/><path d="M12 7v5l3 2"/>',
  file: '<path d="M7 3.500h7l4.500 4.500v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4.500a1 1 0 0 1 1-1z"/><path d="M14 3.500V8h4.500M9 13h6M9 16.500h6"/>',
  dots: '<path d="M5.500 12h.01M12 12h.01M18.500 12h.01"/>',
  sun: '<circle cx="12" cy="12" r="3.800"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.600 5.600L7 7M17 17l1.400 1.400M5.600 18.400L7 17M17 7l1.400-1.400"/>',
  moon: '<path d="M20 14.500A8.500 8.500 0 0 1 9.500 4a8.500 8.500 0 1 0 10.500 10.500z"/>',
  power: '<path d="M12 3.500v8M7 6.500a7.500 7.500 0 1 0 10 0"/>',
  diamond: '<path d="M12 4l7 8-7 8-7-8z"/>',
  bolt: '<path d="M13 3L5.500 13.500H11L10 21l7.500-10.500H12z"/>',
  book: '<path d="M5 4.500h10a3 3 0 0 1 3 3V20H8a3 3 0 0 1-3-3z"/><path d="M5 17a3 3 0 0 1 3-3h10"/>',
  database: '<ellipse cx="12" cy="6.500" rx="7" ry="2.800"/><path d="M5 6.500v11c0 1.500 3.100 2.800 7 2.800s7-1.300 7-2.800v-11M5 12c0 1.500 3.100 2.800 7 2.800s7-1.300 7-2.800"/>',
  upload: '<path d="M12 16V5M7.500 9.500L12 5l4.500 4.500M5 19.500h14"/>',
  minus: '<path d="M6 12h12"/>',
  arrowLeft: '<path d="M19 12H5M11 6l-6 6 6 6"/>',
  edit: '<path d="M4 20h4L19 9a2.100 2.100 0 0 0-4-4L4 16z M13.500 6.500l4 4"/>',
};

/** icon("check", "size-s") -> inline SVG (stroke icon on a 24 grid). Markup comes from the constant table above, never from data. */
export function icon(name, cls = "") {
  const el = document.createElementNS(SVG_NS, "svg");
  el.setAttribute("viewBox", "0 0 24 24");
  el.setAttribute("class", ("icon " + cls).trim());
  el.setAttribute("aria-hidden", "true");
  el.setAttribute("focusable", "false");
  const body = I[name] || I.info;
  const doc = new DOMParser().parseFromString(`<svg xmlns="${SVG_NS}">${body}</svg>`, "image/svg+xml");
  for (const n of Array.from(doc.documentElement.childNodes)) el.appendChild(document.importNode(n, true));
  return el;
}

export const TYPE_ICON = { username: "user", email: "mail", domain: "globe", ip: "network", phone: "phone", url: "link", hash: "hash", keyword: "tag", password: "key", image: "image" };

// ------------------------------------------------------------------------------------------------ formatting
const nf = new Intl.NumberFormat(undefined);
export const fmtNum = (n) => nf.format(n);
export function fmtTime(ts) {
  if (!ts) return "";
  try {
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(ts * 1000));
  } catch (_) {
    return "";
  }
}
export function ago(ts) {
  if (!ts) return "";
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}
export function secs(n) {
  if (n === undefined || n === null) return "";
  return n < 10 ? `${n.toFixed(1)} s` : `${Math.round(n)} s`;
}
export const plural = (n, one, many) => `${fmtNum(n)} ${n === 1 ? one : many || one + "s"}`;
export const shorten = (s, n = 80) => (String(s).length > n ? String(s).slice(0, n - 1) + "…" : String(s));

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) {
    const ta = h("textarea", { class: "sr-only", "aria-hidden": "true" });
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (_) {
      ok = false;
    }
    ta.remove();
    return ok;
  }
}

/** Debounce for input handlers. */
export function debounce(fn, ms) {
  let t = 0;
  return (...a) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...a), ms);
  };
}
