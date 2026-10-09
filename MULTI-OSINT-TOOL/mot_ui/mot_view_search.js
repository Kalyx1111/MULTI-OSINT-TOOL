// MULTI-OSINT-TOOL :: search screen. One box, automatic type detection, and a live plan drawn on the 20-tool dial.
// The typed text is sent only to this program on this computer (detect + search); it is never put in a URL, a title or browser storage.
import { h, icon, mount, clear, debounce, TYPE_ICON, plural, ago, shorten } from "./mot_dom.js";
import * as api from "./mot_api.js";
import { state, loadConns, on } from "./mot_state.js";
import { createDial, JEWEL_ORDER } from "./mot_rosette.js";
import { TYPE_LABEL, TYPE_ORDER, TYPE_EXAMPLE, scope, banner, spinner, chip, popMenu, switchEl, textInput, field, toast, reportError, errorPlate, sectionHead } from "./mot_ui.js";

const NOUN = { username: "username", email: "email address", domain: "domain", ip: "IP address", phone: "phone number", url: "web address", hash: "hash", keyword: "name", password: "password", image: "face" };

function entryForMode(mode, missing) {
  if (missing) return { state: "done", status: "missing_tool", label: "Not installed" };
  if (mode === "paid") return { state: "queued", label: "Ready, using your key" };
  if (mode === "free") return { state: "queued", label: "Ready, free tier" };
  if (mode === "needs_key") return { state: "done", status: "no_key", label: "Needs a key" };
  if (mode === "handoff") return { state: "done", status: "handoff", label: "Manual step" };
  if (mode === "export") return { state: "done", status: "export", label: "Export file" };
  return { state: "queued" };
}

// One plan row -> its dial entry. `state` comes from the server: will_run | needs_key | off | handoff | export | manual | research.
function entryForRow(r, missing) {
  if (missing) return { state: "done", status: "missing_tool", label: "Not installed" };
  if (r.state === "will_run") return { state: "queued", label: r.mode === "paid" ? "Ready, using your key" : "Ready, free tier" };
  if (r.state === "needs_key") return { state: "done", status: "no_key", label: "Needs a key" };
  if (r.state === "off") return { state: "done", status: "off", label: "Off in Connections" };
  if (r.state === "handoff") return { state: "done", status: "handoff", label: "Manual step" };
  if (r.state === "export") return { state: "done", status: "export", label: "Export file" };
  return { state: "done", status: "not_automated", label: "Not searched automatically" };
}

// Order of the kind buttons: the kinds of target the program can search.
const TYPE_ROW = ["email", "username", "ip", "phone", "domain", "url", "hash", "keyword", "password", "image"];

const levelTone = (l) => (l === "low" ? "ok" : l === "moderate" ? "warn" : "bad");

export async function mountSearch(root, params, ctx) {
  const S = scope();
  mount(root, h("div", { class: "page" }, h("div", { class: "empty" }, spinner(), h("p", {}, "Getting your tools ready…"))));
  try {
    await loadConns();
  } catch (e) {
    mount(root, h("div", { class: "page" }, errorPlate(e, () => ctx.go("#/"))));
    return () => S.dispose();
  }
  if (!S.alive) return () => S.dispose();

  const names = Object.fromEntries(state.connList.map((c) => [c.id, c.name]));
  const planCache = new Map();
  const typeInfo = { list: [] }; // from /api/types: label, example and how many tools will run for each kind
  const st = { target: "", manualType: "", detected: "", detectErr: "", detectSeq: 0, deselected: new Set(), busy: false, save: true, faceConsent: false, blocked: null };
  const effType = () => st.manualType || st.detected;
  const rowsNow = () => (effType() ? planCache.get(effType()) || null : null);

  // ---- finder
  const input = h("input", { class: "finder-input", type: "text", id: "finder", autocomplete: "off", spellcheck: "false", autocapitalize: "off", maxlength: "500",
    placeholder: "name@example.com, janedoe, example.com, 203.0.113.7 …", "aria-label": "What to look into", "aria-describedby": "finder-meta" });
  const typeBtn = h("button", { class: "finder-type is-empty", type: "button", "aria-haspopup": "menu", "aria-expanded": "false", "aria-label": "Kind of target. Choose manually", on: { click: openTypeMenu } });
  const typeWrap = h("div", { class: "menu-anchor finder-type-wrap" }, typeBtn);
  const meta = h("p", { class: "finder-meta", id: "finder-meta", "aria-live": "polite" });
  const submitBtn = h("button", { class: "btn btn-primary btn-lg", type: "submit", disabled: true }, icon("search"), "Search");
  const typeNotice = h("div", { class: "stack-s" });
  const toolpickHost = h("div", { class: "stack-s" });
  const typeRowHost = h("div", { class: "typerow", role: "group", "aria-label": "Kind of search" });
  const bannerHost = h("div", { class: "stack-s" });

  // ---- options
  const saveSwitch = switchEl({ checked: true, label: "Save this search as a case", onChange: (v) => (st.save = v) });
  const purpose = textInput({ id: "purpose", maxlength: 200, placeholder: "e.g. due diligence on a supplier" });
  const options = h("details", { class: "disclose" },
    h("summary", {}, icon("chevronRight", "s"), "Options and tool choice"),
    h("div", { class: "disclose-body stack" },
      h("div", { class: "opts" },
        h("div", { class: "field" }, h("span", { class: "label" }, "Save as a case"), h("div", { class: "cluster-s" }, saveSwitch.el, h("span", { class: "small muted" }, "Kept encrypted in your vault. Passwords are never saved.")) ),
        field({ label: "Purpose (optional)", hint: "Written to your private audit log, never sent anywhere.", control: purpose }).el)));

  const form = h("form", { class: "finder cert", novalidate: true, on: { submit: onSubmit } },
    h("div", { class: "finder-row" }, h("div", { class: "finder-box" }, typeWrap, input), submitBtn),
    typeRowHost, meta, typeNotice, toolpickHost, options);

  // ---- dial
  const dial = createDial(names);

  // ---- sections below the hero
  const toolboxHost = h("div", {});
  const recentHost = h("div", {});

  const hero = h("section", { class: "hero", "aria-label": "Search" },
    h("div", { class: "hero-copy" },
      bannerHost,
      h("h1", { class: "display d-hero", tabIndex: -1, "data-page-title": "" }, "What would you like to look into?"),
      h("p", { class: "lead" }, "Type an email, username, domain, IP address, phone number, URL or file hash. MULTI-OSINT-TOOL picks the tools that can answer and searches them together."),
      form),
    h("div", { class: "hero-dial" }, dial.el));

  const privacy = h("section", { class: "section", "aria-label": "How your privacy is protected" },
    sectionHead("How your privacy is protected"),
    h("div", { class: "guide" },
      h("article", {}, icon("shieldCheck", "l"), h("h3", { class: "h3" }, "Nothing leaves unshielded"), h("p", { class: "muted small" }, "Network tools run only through Tor and your VPN, and only after the shield is proven. If it is not, nothing is sent.")),
      h("article", {}, icon("lock", "l"), h("h3", { class: "h3" }, "Keys and cases stay sealed"), h("p", { class: "muted small" }, "Everything is encrypted on this computer with AES-256-GCM. Vendor pages open in your own browser only after a clear warning.")),
      h("article", {}, icon("power", "l"), h("h3", { class: "h3" }, "One button ends it all"), h("p", { class: "muted small" }, "Panic stops running searches, locks the vault and wipes temporary files. The vault also locks itself when you are idle."))));

  mount(root, h("div", { class: "page stack-l" }, hero, h("section", { class: "section", "aria-label": "Your toolbox" }, toolboxHost), h("section", { class: "section", "aria-label": "Recent" }, recentHost), privacy));

  // ------------------------------------------------------------------------------------------ painting
  function tally(rows) {
    const c = { ready: 0, free: 0, paid: 0, manual: 0, needKey: 0, missing: 0, off: 0, notAuto: 0, total: rows.length };
    for (const r of rows) {
      if (r.state === "will_run" && st.deselected.has(r.id)) continue;
      if (r.kind === "cli" && r.installed === false) c.missing++;
      else if (r.state === "will_run" && r.mode === "paid") (c.paid++, c.ready++);
      else if (r.state === "will_run") (c.free++, c.ready++);
      else if (r.state === "needs_key") c.needKey++;
      else if (r.state === "off") c.off++;
      else if (r.state === "handoff" || r.state === "export") c.manual++;
      else c.notAuto++;
    }
    return c;
  }

  function paintType() {
    const t = effType();
    clear(typeBtn);
    typeBtn.classList.toggle("is-empty", !t);
    typeBtn.appendChild(t ? icon(TYPE_ICON[t] || "tag") : icon("tag"));
    typeBtn.appendChild(h("span", {}, t ? TYPE_LABEL[t] : "Kind"));
    typeBtn.appendChild(h("span", { class: "push" }, icon("chevronDown", "s")));
    typeBtn.title = st.manualType ? "You chose this kind. Open to change it." : t ? "Detected automatically. Open to choose another." : "Choose the kind of target";
    const isPw = t === "password";
    input.type = isPw ? "password" : "text";
    input.autocomplete = isPw ? "new-password" : "off";
    input.placeholder = t ? TYPE_EXAMPLE[t] : "name@example.com, janedoe, example.com, 203.0.113.7 …";
  }

  function paintMeta() {
    const t = effType();
    const rows = rowsNow();
    meta.classList.remove("is-bad");
    if (st.blocked && st.blocked.text) {
      meta.classList.add("is-bad");
      meta.textContent = st.blocked.text;
    } else if (!st.target.trim() && !st.manualType) meta.textContent = "Examples: name@example.com · janedoe · example.com · 203.0.113.7 · +14155552671";
    else if (st.detectErr && !t) {
      meta.classList.add("is-bad");
      meta.textContent = st.detectErr;
    } else if (t && rows) {
      const c = tally(rows);
      const how = [];
      if (c.free) how.push(`${c.free} free`);
      if (c.paid) how.push(`${c.paid} on your keys`);
      let s = c.ready ? `${plural(c.ready, "tool")} will search this ${NOUN[t]}${how.length ? ` (${how.join(", ")})` : ""}.` : `No tool can search this ${NOUN[t]} yet.`;
      const extra = [];
      if (c.needKey) extra.push(`${c.needKey} need a key`);
      if (c.missing) extra.push(`${c.missing} not installed`);
      if (c.off) extra.push(`${c.off} off in Connections`);
      if (c.manual) extra.push(`${c.manual} website only`);
      if (c.notAuto) extra.push(`${c.notAuto} not searched automatically`);
      if (extra.length) s += " Also: " + extra.join(", ") + ".";
      if (st.manualType && !st.target.trim()) s = `Searching for a ${NOUN[t]}. ` + s;
      meta.textContent = s;
    } else if (t) meta.textContent = "Checking which tools apply…";
    else meta.textContent = "Choose what kind of target this is.";
  }

  function paintDial() {
    const t = effType();
    const rows = rowsNow();
    const map = {};
    let ready = 0, free = 0, paid = 0;
    if (!rows) {
      for (const id of JEWEL_ORDER) {
        const c = state.conns.get(id);
        const e = c ? entryForMode(c.mode, c.kind === "cli" && c.installed === false) : { na: true };
        map[id] = e;
        if (e.state === "queued") (ready++, c.mode === "paid" ? paid++ : free++);
      }
    } else {
      const inPlan = new Map(rows.map((r) => [r.id, r]));
      for (const id of JEWEL_ORDER) {
        const r = inPlan.get(id);
        if (!r) map[id] = { na: true, label: `Does not apply to a ${NOUN[t]} search` };
        else if (st.deselected.has(id)) map[id] = { na: true, label: "Not selected" };
        else {
          const e = entryForRow(r, r.kind === "cli" && r.installed === false);
          map[id] = e;
          if (e.state === "queued") (ready++, r.mode === "paid" ? paid++ : free++);
        }
      }
    }
    dial.update(map);
    if (!rows) {
      dial.setCentre(String(JEWEL_ORDER.length), "tools in MULTI-OSINT-TOOL", "type a target to see which run");
      return;
    }
    const detail = ready === 0 ? "add a key to unlock more" : [free ? `${free} free` : "", paid ? `${paid} on your keys` : ""].filter(Boolean).join(" · ");
    dial.setCentre(String(ready), ready === 1 ? "tool ready" : "tools ready", detail);
  }

  function paintExtras() {
    const t = effType();
    clear(typeNotice);
    if (t === "password") {
      typeNotice.appendChild(banner({ tone: "info", title: "Checked privately.", body: "Only the first 5 characters of a hash of this password leave your computer (k-anonymity), through the shield. The password itself is never sent, saved or logged." }));
    }
    if (t === "image") {
      typeNotice.appendChild(banner({ tone: "warn", title: "Face search needs your consent.", body: "Only search for your own face, or for someone who has agreed. PimEyes has no public API and MULTI-OSINT-TOOL never uploads a photo: you finish this step on their website yourself." }));
      const cb = h("input", { type: "checkbox", id: "face-consent", checked: st.faceConsent, on: { change: () => { st.faceConsent = cb.checked; paintSubmit(); } } });
      typeNotice.appendChild(h("label", { class: "check" }, cb, h("span", {}, "This is my own face, or the person has given consent for this search.")));
    }
    // Which tools search this kind, which wait for you, and which are never searched automatically.
    clear(toolpickHost);
    const rows = rowsNow();
    if (rows && rows.length) {
      const runs = rows.filter((r) => r.state === "will_run" || r.state === "needs_key" || r.state === "off");
      const other = rows.filter((r) => !runs.includes(r));
      const toggleFor = (r) => (ev) => {
        if (ev.target.checked) st.deselected.delete(r.id);
        else st.deselected.add(r.id);
        paintMeta();
        paintDial();
        paintSubmit();
      };
      toolpickHost.append(h("span", { class: "label" }, "Which tools search this"),
        h("div", { class: "toollist" }, ...runs.map((r) => toolLine(r, r.state === "will_run" ? toggleFor(r) : null))),
        other.length ? h("details", { class: "disclose" },
          h("summary", {}, icon("chevronRight", "s"), `Not searched automatically (${other.length})`),
          h("div", { class: "disclose-body" }, h("div", { class: "toollist" }, ...other.map((r) => toolLine(r, null))))) : null,
        h("p", { class: "hint" }, "Untick a tool to leave it out of this search. Website-only and research items are never sent anything."));
    }
  }

  function canSubmit() {
    const t = effType();
    if (st.busy || !t) return false;
    if (!st.target.trim() && t !== "image") return false;
    if (t === "image" && !st.faceConsent) return false;
    const rows = rowsNow();
    if (rows && !rows.some((r) => r.state === "will_run" && !st.deselected.has(r.id))) return false;
    return true;
  }
  function paintSubmit() {
    submitBtn.disabled = !canSubmit();
  }

  function paintBanners() {
    clear(bannerHost);
    const sh = state.shield && state.shield.state;
    if (st.blocked) {
      const reasons = st.blocked.reasons || [];
      bannerHost.appendChild(banner({ tone: "bad", title: "No search was sent.", body: [st.blocked.head, reasons.length ? h("ul", { class: "stack-s small" }, ...reasons.map((r) => h("li", {}, r))) : null],
        actions: h("a", { class: "btn btn-s", href: "#/shield" }, "Open Shield") }));
    } else if (sh && sh.age !== null && sh.age !== undefined && !sh.ok) {
      bannerHost.appendChild(banner({ tone: "warn", title: "The network shield is not verified.", body: "Tools that use the internet will not run until it is. Tools that work on this computer still do.",
        actions: h("a", { class: "btn btn-s", href: "#/shield" }, "Fix it") }));
    }
  }

  function paintAll() {
    paintTypeRow();
    paintType();
    paintMeta();
    paintDial();
    paintExtras();
    paintSubmit();
    paintBanners();
  }

  // One tool in the list: what it is used for, whether it will search, and why not when it will not.
  const STATE_CHIP = {
    will_run: (r) => (r.mode === "paid" ? ["Will search · your key", "accent"] : ["Will search · free", "ok"]),
    needs_key: () => ["Needs a key", "warn"],
    off: () => ["Off in Connections", "mute"],
    handoff: () => ["Website only", "info"],
    export: () => ["Export file", "info"],
    manual: () => ["Kept manual", "mute"],
    research: () => ["Research required", "mute"],
  };
  function toolLine(r, onToggle) {
    const missing = r.kind === "cli" && r.installed === false;
    const [text, tone] = missing ? ["Not installed", "warn"] : (STATE_CHIP[r.state] || (() => ["Not automated", "mute"]))(r);
    const control = onToggle
      ? h("input", { type: "checkbox", checked: !st.deselected.has(r.id), "aria-label": `Search with ${r.name}`, on: { change: onToggle } })
      : h("span", { class: "tool-dash", "aria-hidden": "true" }, "–");
    return h("div", { class: "tool-line" }, control,
      h("div", { class: "stack-s" }, h("span", { class: "strong" }, r.name),
        r.use ? h("span", { class: "small muted wrap-any" }, r.use) : null,
        r.reason && r.state !== "will_run" ? h("span", { class: "tiny muted wrap-any" }, r.reason) : null),
      chip(text, tone));
  }

  // The kind buttons: each shows how many tools will search that kind (from /api/types).
  function paintTypeRow() {
    clear(typeRowHost);
    const t = effType();
    const list = typeInfo.list.length ? typeInfo.list : TYPE_ROW.map((id) => ({ id, label: TYPE_LABEL[id] || id }));
    for (const it of list) {
      const counted = typeof it.will_run === "number";
      typeRowHost.appendChild(h("button", { class: "btn btn-s typebtn", type: "button", "aria-pressed": String(t === it.id),
        title: it.example ? `Example: ${it.example}` : "", on: { click: () => pickType(it.id) } },
        icon(TYPE_ICON[it.id] || "tag", "s"), h("span", {}, it.label),
        counted ? h("span", { class: "tiny muted", title: "Tools that will search this kind of target" }, String(it.will_run)) : null));
    }
  }

  async function pickType(v) {
    st.manualType = st.manualType === v ? "" : v; // pressing the active kind again returns to automatic detection
    st.blocked = null;
    st.deselected.clear();
    if (!st.manualType) {
      st.detected = "";
      st.detectErr = "";
      detect();
    }
    if (st.manualType !== "image") st.faceConsent = false;
    await refreshType();
    paintAll();
    input.focus();
  }

  api.get("/api/types").then((d) => {
    typeInfo.list = d.types || [];
    if (S.alive) paintTypeRow();
  }).catch(() => {});

  // ------------------------------------------------------------------------------------------ behaviour
  async function ensurePlan(type) {
    if (!type || planCache.has(type)) return;
    const d = await api.get("/api/plan?ttype=" + encodeURIComponent(type));
    planCache.set(type, d.tools);
  }

  async function refreshType() {
    const t = effType();
    try {
      await ensurePlan(t);
    } catch (e) {
      if (S.alive) {
        st.detectErr = e.message;
        paintMeta();
      }
      return;
    }
    if (S.alive) paintAll();
  }

  const detect = debounce(async () => {
    const text = st.target.trim();
    if (!S.alive || st.manualType) return;
    if (!text) {
      st.detected = "";
      st.detectErr = "";
      paintAll();
      return;
    }
    const my = ++st.detectSeq;
    try {
      const r = await api.post("/api/detect", { target: text });
      if (my !== st.detectSeq || !S.alive) return;
      st.detected = r.ttype;
      st.detectErr = "";
    } catch (e) {
      if (my !== st.detectSeq || !S.alive) return;
      st.detected = "";
      st.detectErr = e.message || "Could not recognise this input. Choose the kind of target yourself.";
    }
    await refreshType();
  }, 220);

  input.addEventListener("input", () => {
    st.target = input.value;
    st.blocked = null;
    st.detectSeq++;
    if (!st.manualType) {
      if (!st.target.trim()) {
        st.detected = "";
        st.detectErr = "";
      }
      detect();
    }
    paintAll();
  });

  function openTypeMenu() {
    popMenu({
      anchor: typeBtn, label: "Kind of target",
      items: [{ label: "Detect automatically", ic: "refresh", value: "", selected: !st.manualType }, { sep: true },
        ...TYPE_ORDER.map((t) => ({ label: TYPE_LABEL[t], ic: TYPE_ICON[t], value: t, selected: st.manualType === t }))],
      onPick: async (v) => {
        st.manualType = v;
        st.blocked = null;
        st.deselected.clear();
        if (!v) {
          st.detected = "";
          st.detectErr = "";
          detect();
        }
        if (v !== "image") st.faceConsent = false;
        await refreshType();
        paintAll();
        input.focus();
      },
    });
  }

  async function onSubmit(ev) {
    ev.preventDefault();
    if (!canSubmit()) return;
    const t = effType();
    const rows = rowsNow() || [];
    const body = { target: t === "image" && !st.target.trim() ? "photo" : input.value, ttype: t, save: st.save && t !== "password", face_consent: t === "image" ? st.faceConsent : false, purpose: purpose.value.trim() };
    if (st.deselected.size) body.tools = rows.filter((r) => r.state === "will_run" && !st.deselected.has(r.id)).map((r) => r.id);
    st.busy = true;
    st.blocked = null;
    clear(submitBtn);
    submitBtn.append(spinner(), "Starting…");
    submitBtn.disabled = true;
    try {
      const job = await api.post("/api/search", body);
      if (t === "password") input.value = ""; // never leave a searched password in the page
      st.target = "";
      ctx.go("#/run/" + job.id);
      return;
    } catch (e) {
      if (e instanceof api.ApiError && e.code === "shield_down") {
        st.blocked = { head: "The network shield is not verified, so nothing was sent.", reasons: (e.extra && e.extra.reasons) || [], text: "Blocked: the shield is not verified." };
      } else if (e instanceof api.ApiError && e.code === "ack_required") {
        toast("Please accept the lawful-use notice first. Reload the page to see it.", "warn", 7000);
      } else if (e instanceof api.ApiError && (e.code === "locked" || e.code === "no_session")) {
        return;
      } else {
        st.blocked = { head: "", reasons: [], text: e.message || "The search could not be started." };
      }
    }
    st.busy = false;
    clear(submitBtn);
    submitBtn.append(icon("search"), "Search");
    paintAll();
  }

  // "/" jumps to the box, like a command palette
  S.listen(document, "keydown", (e) => {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    const a = document.activeElement;
    if (a && (a.tagName === "INPUT" || a.tagName === "TEXTAREA" || a.tagName === "SELECT" || a.isContentEditable)) return;
    if (document.querySelector("dialog[open]")) return;
    e.preventDefault();
    input.focus();
  });
  S.add(on("shield", () => paintBanners()));

  // ------------------------------------------------------------------------------------------ below the hero
  function paintToolbox() {
    const sm = state.connSummary || { total: 20, paid: 0, free_ready: 0, needs_key: 0 };
    mount(toolboxHost,
      sectionHead("Your toolbox", h("a", { class: "btn btn-s", href: "#/connections" }, icon("plug", "s"), "Connect tools")),
      h("div", { class: "summary-bar" },
        h("span", {}, h("b", {}, String(sm.paid)), "on your own keys"),
        h("span", {}, h("b", {}, String(sm.free_ready)), "free tier"),
        h("span", {}, h("b", {}, String(sm.needs_key)), "waiting for a key")),
      h("p", { class: "muted small measure" }, "Where you have no key, the free tier is used automatically. Add a paid key in Connections and that tool switches to it by itself."));
  }

  async function paintRecent() {
    const [cs, js] = await Promise.allSettled([api.get("/api/cases"), api.get("/api/jobs")]);
    if (!S.alive) return;
    const items = [];
    if (js.status === "fulfilled") {
      for (const j of js.value.jobs.filter((x) => x.status === "running").slice(0, 3)) {
        items.push(h("li", {}, icon(TYPE_ICON[j.ttype] || "tag", "s"), h("a", { href: "#/run/" + j.id }, shorten(j.target, 60)), h("span", { class: "muted small" }, `${j.done} of ${j.total} tools done`), h("span", { class: "push" }, chip("Running", "accent"))));
      }
    }
    if (cs.status === "fulfilled") {
      for (const c of cs.value.cases.slice(0, 5)) {
        items.push(h("li", {}, icon(TYPE_ICON[c.ttype] || "tag", "s"), c.damaged ? h("span", {}, "Damaged case file") : h("a", { href: "#/case/" + c.id }, shorten(c.target, 60)),
          h("span", { class: "muted small" }, `${TYPE_LABEL[c.ttype] || c.ttype} · ${ago(c.created)}`), h("span", { class: "push" }, c.damaged ? chip("Damaged", "bad") : chip(`Exposure ${c.score}`, levelTone(c.level)))));
      }
    }
    if (!items.length) {
      mount(recentHost, sectionHead("Recent"), h("p", { class: "muted small" }, "Your searches will appear here, saved encrypted on this computer."));
      return;
    }
    mount(recentHost, sectionHead("Recent", h("a", { class: "btn btn-s", href: "#/cases" }, "All cases")), h("ul", { class: "recent" }, ...items));
  }

  paintToolbox();
  paintAll();
  paintRecent();
  S.add(on("conns", () => {
    paintToolbox();
    paintDial();
  }));
  S.timeout(() => dial.wake(), 60);
  if (S.alive) input.focus();
  ctx.setTitle("Search");
  return () => S.dispose();
}
