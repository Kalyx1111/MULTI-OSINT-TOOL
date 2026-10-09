// MULTI-OSINT-TOOL :: network shield. Shows whether network tools may run, why, and lets the person choose the route.
// Addresses are shown only in the masked form the server returns. Nothing here is stored in the browser.
import { h, icon, mount, ago } from "./mot_dom.js";
import * as api from "./mot_api.js";
import { state, loadShield, emit } from "./mot_state.js";
import { scope, banner, pageHead, sectionHead, loadingPlate, textInput, button, externalLink, confirmBox, toast, reportError } from "./mot_ui.js";

const TONE_VAR = { ok: "var(--ok)", warn: "var(--warn)", bad: "var(--bad)", mute: "var(--ink-2)" };
const yesNo = (v, yes, no, unknown = "Not checked") => (v === true ? yes : v === false ? no : unknown);

export async function mountShield(root, p, ctx) {
  const S = scope();
  const body = h("div", { class: "stack-l" });
  mount(root, h("div", { class: "page stack-l" },
    pageHead({ eyebrow: "Privacy", title: "Network shield",
      lead: "Network tools send nothing until the shield is verified: traffic goes through Tor and/or your VPN, and the shield checks that your real address is hidden." }),
    body));
  mount(body, loadingPlate("Checking the shield…"));
  let sh = null;
  let torTimer = 0;
  S.add(() => clearTimeout(torTimer));

  function publish(next) {
    sh = next;
    state.shield = next;
    emit("shield", next);
    ctx.paintSeal();
    paint();
  }

  async function verify() {
    try {
      publish(await api.post("/api/shield/verify", {}));
      toast("Shield checked.", "ok", 2400);
    } catch (e) {
      reportError(e, "The shield could not be checked.");
    }
  }

  function verdict() {
    const st = sh.state || {};
    const checked = st.age !== null && st.age !== undefined;
    const tone = !checked ? "mute" : st.ok ? "ok" : st.offline ? "warn" : "bad";
    const ic = !checked ? "shield" : st.ok ? "shieldCheck" : st.offline ? "shieldWarn" : "shieldOff";
    const title = !checked ? "Not checked yet" : st.ok ? "Shielded: network tools can run" : st.offline ? "Offline: network tools wait" : "Not shielded: network tools are blocked";
    const modeName = (sh.modes || []).find((m) => m.id === sh.mode)?.name || sh.mode || "No mode";
    const when = checked ? `Checked ${ago(Date.now() / 1000 - st.age)} · ${modeName}.` : "Press Verify to check now.";
    const btn = button({ label: "Verify now", kind: "primary", ic: "refresh", onClick: () => verify() });
    return h("section", { class: "plate verdict", vars: { "--tone": TONE_VAR[tone] }, "aria-label": "Shield verdict" },
      h("div", { class: "verdict-ic" }, icon(ic)),
      h("div", { class: "stack-s" }, h("h2", { class: "h3" }, title), h("p", { class: "muted small" }, when),
        (st.reasons || []).length ? h("ul", { class: "small stack-s" }, ...st.reasons.map((r) => h("li", {}, String(r)))) : null,
        (st.warnings || []).length ? h("ul", { class: "small muted" }, ...st.warnings.map((w) => h("li", {}, String(w)))) : null),
      btn);
  }

  function proofs() {
    const st = sh.state || {};
    const adapters = (st.adapters || []).length ? st.adapters.join(", ") : "";
    const items = [
      { label: "Tor relay", value: yesNo(st.tor_port, "Running", "Not found"), tone: st.tor_port === true ? "ok" : st.tor_port === false ? "warn" : "mute", ic: "onion" },
      { label: "Tor exit", value: yesNo(st.tor_exit, "Routing through Tor", "Not through Tor"), tone: st.tor_exit === true ? "ok" : st.tor_exit === false ? "warn" : "mute", ic: "onion" },
      { label: "VPN adapter", value: yesNo(st.vpn_adapter, adapters ? "Active: " + adapters : "Active", "Not found"), tone: st.vpn_adapter === true ? "ok" : st.vpn_adapter === false ? "warn" : "mute", ic: "shield" },
      { label: "Exit address", value: st.egress_ip || "Not used", tone: "mute", ic: "globe" },
      { label: "VPN address", value: st.vpn_egress_ip || "Not used", tone: "mute", ic: "network" },
      { label: "Real address baseline", value: sh.baseline_set ? "Recorded (kept hidden)" : "Not recorded", tone: sh.baseline_set ? "ok" : "warn", ic: "eye" },
    ];
    return h("div", { class: "proofs", role: "list", "aria-label": "Shield checks" }, ...items.map((it) => h("div", { class: "proof", role: "listitem", vars: { "--tone": TONE_VAR[it.tone] } },
      icon(it.ic, "s"), h("div", {}, h("div", { class: "tiny muted" }, it.label), h("div", { class: "strong wrap-any" }, it.value)))));
  }

  let allowDirect = false; // set only by the person's own tick; the server refuses direct mode without it
  function modes() {
    const direct = h("label", { class: "check" }, h("input", { type: "checkbox", checked: allowDirect, on: { change: (ev) => (allowDirect = ev.currentTarget.checked) } }),
      h("span", {}, "I understand that in direct mode every service sees my real address."));
    const opts = (sh.modes || []).map((m) => {
      const input = h("input", { type: "radio", name: "shield-mode", value: m.id, checked: sh.mode === m.id, on: { change: async () => {
        try {
          publish(await api.post("/api/shield/config", { mode: m.id, allow_direct: allowDirect }));
          toast(`Mode set: ${m.name}. Verifying…`, "info", 2600);
          await verify();
        } catch (e) {
          if (e instanceof api.ApiError && e.code === "confirm_direct") toast("Tick the direct-mode confirmation first.", "warn", 5000);
          else reportError(e, "The mode was not changed.");
          paint();
        }
      } } });
      return h("label", { class: "mode" }, input, h("span", { class: "stack-s" }, h("span", { class: "strong" }, m.name), h("span", { class: "small muted" }, m.text)));
    });
    return h("section", { class: "section stack-s", "aria-label": "Shield mode" }, sectionHead("How traffic leaves your computer"),
      h("div", { class: "stack-s", role: "radiogroup", "aria-label": "Shield mode" }, ...opts),
      h("div", { class: "stack-s" }, direct, h("p", { class: "hint" }, "Direct mode stays off unless you tick the box above and choose it.")));
  }

  function fieldRow(key, label, placeholder, hint) {
    const val = (sh.config || {})[key] || "";
    const input = textInput({ id: "shield-" + key, value: val, placeholder, maxlength: key === "custom_proxy" ? 300 : key === "tor_socks" ? 120 : 80 });
    return h("div", { class: "stack-s" }, h("label", { class: "label", for: input.id }, label), h("div", { class: "cluster" }, input,
      button({ label: "Save", small: true, ic: "check", onClick: async () => {
        try {
          publish(await api.post("/api/shield/config", { [key]: input.value.trim() }));
          toast(`${label} saved.`, "ok", 2200);
        } catch (e) {
          reportError(e, `${label} was not saved.`);
        }
      } })), h("p", { class: "hint" }, hint));
  }

  function torBlock() {
    const t = sh.tor || {};
    const status = (t.status && t.status.msg) || (t.binary ? "Tor is installed. Start it here, or run Tor Browser." : "Tor was not found. Install the Tor Expert Bundle or Tor Browser.");
    const start = button({ label: "Start Tor", ic: "play", onClick: async () => {
      try {
        await api.post("/api/shield/tor/start", {});
        toast("Starting Tor…", "info", 2600);
        pollTor(0);
      } catch (e) {
        reportError(e, "Tor did not start.");
      }
    } });
    return h("section", { class: "section stack-l", "aria-label": "Tor and VPN" }, sectionHead("Tor, VPN and proxy"),
      h("p", { class: "small muted" }, status, (t.detected || []).length ? ` Found: ${t.detected.join(", ")}.` : ""),
      h("div", { class: "cluster" }, start),
      fieldRow("tor_socks", "Tor address", "127.0.0.1:9050", "Where Tor listens on this computer. Tor Browser uses 127.0.0.1:9150."),
      fieldRow("vpn_iface_pattern", "VPN adapter name pattern", "e.g. wg|tun|proton", "The shield looks for a VPN adapter whose name matches this pattern."),
      fieldRow("custom_proxy", "Your own proxy (optional)", "socks5://127.0.0.1:1080", "Only without a username or password in the address."));
  }

  function baselineBlock() {
    const recorded = !!sh.baseline_set;
    const btn = button({ label: recorded ? "Record again" : "Record my real address", kind: recorded ? "quiet" : "primary", ic: "eye", onClick: async () => {
      const ok = await confirmBox({ title: "Record your real address?", body: "It is kept encrypted in your vault and used only to detect when your address leaks through a tool. It is never shown in full and never sent anywhere.", confirmLabel: "Record" });
      if (!ok) return;
      try {
        await api.post("/api/shield/baseline", { force: recorded });
        publish(await api.get("/api/shield"));
        toast("Recorded. It stays hidden.", "ok", 2600);
      } catch (e) {
        reportError(e, "Could not record it.");
      }
    } });
    return h("section", { class: "section stack-s", "aria-label": "Real address baseline" }, sectionHead("Leak check"),
      h("p", { class: "small muted measure" }, "With a recorded baseline, the shield can tell when your real address would reach a service. Without one it cannot."), btn);
  }

  function guidance() {
    return h("section", { class: "section stack-l", "aria-label": "Guidance" }, sectionHead("Setting it up safely"),
      h("div", { class: "guide" }, ...(sh.guidance || []).map((g) => h("article", {},
        h("h3", { class: "h3" }, g.title), h("p", { class: "muted small" }, g.why),
        h("div", { class: "cluster-s" }, ...(g.links || []).map((l, i) => externalLink(l.name, "guide", g.id, String(i), l.name)))))));
  }

  function paint() {
    if (!sh) return;
    mount(body, verdict(), proofs(), modes(), torBlock(), baselineBlock(), guidance());
  }

  function pollTor(n) {
    clearTimeout(torTimer);
    if (!S.alive || n > 30) return;
    torTimer = setTimeout(async () => {
      try {
        const next = await api.get("/api/shield");
        publish(next);
        const st = next.tor && next.tor.status && next.tor.status.state;
        if (st === "starting" || st === undefined) pollTor(n + 1);
      } catch (_) {
        pollTor(n + 1);
      }
    }, 1500);
  }

  try {
    const cur = await loadShield();
    if (!S.alive) return () => S.dispose();
    publish(cur);
  } catch (e) {
    if (S.alive) mount(body, banner({ tone: "bad", title: "The shield could not be read.", body: e.message || "Try again." }));
  }
  return () => S.dispose();
}
