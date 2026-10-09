// MULTI-OSINT-TOOL :: Settings. Preferences, timing, privacy switches, the vault password and an encrypted backup.
// Every change is checked by the server; the page only collects values and shows what the server answers.
import { h, mount, fmtNum } from "./mot_dom.js";
import * as api from "./mot_api.js";
import { applyTheme } from "./mot_state.js";
import { scope, banner, pageHead, sectionHead, loadingPlate, switchEl, segmented, textInput, pwInput, field, strengthMeter, assessPassword, askPassword, button, toast, reportError } from "./mot_ui.js";

export async function mountSettings(root, p, ctx) {
  const S = scope();
  const body = h("div", { class: "stack-l" });
  mount(root, h("div", { class: "page stack-l" },
    pageHead({ eyebrow: "Preferences", title: "Settings", lead: "What is kept, how long the vault stays open, and how the program behaves. Every value is checked before it is saved." }),
    body));
  mount(body, loadingPlate("Loading your settings…"));

  let cfg = null;

  async function save(patch, done) {
    try {
      cfg = await api.post("/api/settings", patch);
      if (done) toast(done, "ok", 2600);
      return true;
    } catch (e) {
      reportError(e, "Not saved.");
      return false;
    }
  }

  function numberRow(key, label, hint, lo, hi, unit) {
    const input = textInput({ id: "s-" + key, value: String(cfg[key] ?? ""), inputmode: "numeric", maxlength: 4 });
    const err = h("p", { class: "hint is-error", role: "alert" });
    err.hidden = true;
    return h("div", { class: "form-grid" },
      h("div", { class: "stack-s" }, h("label", { class: "label", for: input.id }, label), h("p", { class: "hint" }, hint)),
      h("div", { class: "stack-s" }, h("div", { class: "cluster" }, input, h("span", { class: "small muted" }, unit || ""),
        button({ label: "Save", small: true, ic: "check", onClick: async () => {
          const v = Number(input.value);
          if (!Number.isInteger(v) || v < lo || v > hi) {
            err.textContent = `Enter a whole number from ${lo} to ${hi}.`;
            err.hidden = false;
            return;
          }
          err.hidden = true;
          if (await save({ [key]: v }, `${label} saved.`)) input.value = String(cfg[key]);
        } })), err));
  }

  function switchRow(key, label, hint, tone) {
    const sw = switchEl({ checked: !!cfg[key], label, onChange: async (v) => {
      if (!(await save({ [key]: v }, `${label}: ${v ? "on" : "off"}.`))) sw.set(!v);
    } });
    return h("div", { class: "setting" }, h("div", { class: "stack-s" }, h("span", { class: "strong" }, label), h("span", { class: "small muted" }, hint),
      tone ? banner({ tone, body: tone === "warn" ? "Turn this on only if you need the results saved in readable form." : "" }) : null), sw.el);
  }

  function appearance() {
    const seg = segmented({ options: [{ value: "dark", label: "Dark" }, { value: "light", label: "Light" }], value: cfg.theme === "light" ? "light" : "dark", label: "Theme",
      onChange: async (v) => {
        applyTheme(v);
        await save({ theme: v }, `Theme: ${v}.`);
      } });
    return h("section", { class: "section stack-l", "aria-label": "Appearance" }, sectionHead("Appearance"),
      h("div", { class: "setting" }, h("div", { class: "stack-s" }, h("span", { class: "strong" }, "Theme"), h("span", { class: "small muted" }, "Dark is the default. The choice is also remembered on this computer.")), seg.el));
  }

  function privacy() {
    return h("section", { class: "section stack-l", "aria-label": "Privacy" }, sectionHead("Privacy"),
      switchRow("mask_sensitive", "Hide sensitive records until I open them", "Breach records, infostealer data and other sensitive items stay hidden in results until you choose to show each one."),
      switchRow("persist_secrets", "Keep secret values in saved cases", "Off by default. When on, passwords and tokens found by a search are kept in the case, encrypted. Leave it off unless you need them later.", "warn"),
      switchRow("secure_window", "Open the window in an isolated profile", "Uses a separate browser profile for this window, so its history and cache stay apart from your own browser. Applies the next time the program starts."));
  }

  function timing() {
    return h("section", { class: "section stack-l", "aria-label": "Timing and resources" }, sectionHead("Timing and resources"),
      numberRow("idle_lock_minutes", "Lock after idle", "The vault locks itself after this many minutes without any activity.", 1, 240, "minutes"),
      numberRow("job_timeout", "Stop a search after", "A search that runs longer than this is stopped; finished tools keep their results.", 30, 3600, "seconds"),
      numberRow("connector_timeout", "Wait for each tool up to", "A single tool that takes longer than this is reported as timed out.", 10, 900, "seconds"),
      numberRow("max_workers", "Tools that run at once (0 = automatic)", `Automatic picks ${fmtNum(cfg.recommended ? cfg.recommended.max_workers : 0)} for this computer.`, 0, 32, "tools"));
  }

  function integrations() {
    const harvest = textInput({ id: "s-harvest", value: cfg.theharvester_sources || "", maxlength: 300 });
    const py = textInput({ id: "s-python", value: cfg.toolenv_python || "", maxlength: 400, placeholder: "Leave empty to use this program's Python" });
    return h("section", { class: "section stack-l", "aria-label": "Tool settings" }, sectionHead("Tool settings"),
      h("div", { class: "form-grid" },
        field({ label: "theHarvester sources", hint: "Letters, digits, commas, dashes and underscores only.", control: harvest }).el,
        field({ label: "Python for tool installs", hint: "Optional. Use a newer Python for tools that need one.", control: py }).el),
      h("div", { class: "cluster" }, button({ label: "Save tool settings", kind: "primary", small: true, ic: "check", onClick: async () => {
        const patch = { theharvester_sources: harvest.value.trim(), toolenv_python: py.value.trim() };
        if (await save(patch, "Tool settings saved.")) {
          harvest.value = cfg.theharvester_sources || "";
          py.value = cfg.toolenv_python || "";
        }
      } })),
      h("p", { class: "small muted" }, "Keys can also come from environment variables named ", h("span", { class: "mono" }, cfg.env_keys || "MOT_KEY_<TOOL>_<FIELD>"), ". Keys in the vault win over them."));
  }

  function vault() {
    const oldPw = pwInput({ autocomplete: "current-password" });
    const newPw = pwInput({ autocomplete: "new-password" });
    const confirmPw = pwInput({ autocomplete: "new-password" });
    const meter = strengthMeter();
    const note = h("p", { class: "hint", "aria-live": "polite" }, "At least 12 characters. A passphrase of 20 or more is best.");
    newPw.input.addEventListener("input", () => {
      const a = assessPassword(newPw.value);
      meter.set(a.level);
      note.textContent = !newPw.value ? "At least 12 characters. A passphrase of 20 or more is best." : a.ok ? "Acceptable." : a.problem;
    });
    const change = button({ label: "Change master password", kind: "primary", ic: "lock", onClick: async () => {
      if (!oldPw.value || !newPw.value) return toast("Fill in the current and the new password.", "warn", 4000);
      if (newPw.value !== confirmPw.value) return toast("The new passwords do not match.", "warn", 4000);
      try {
        await api.post("/api/vault/password", { old: oldPw.value, new: newPw.value, confirm: confirmPw.value });
        oldPw.wipe();
        newPw.wipe();
        confirmPw.wipe();
        toast("Master password changed. Keep it safe: there is no recovery.", "ok", 5200);
      } catch (e) {
        reportError(e, "The password was not changed.");
      }
    } });
    const backup = button({ label: "Download an encrypted backup", ic: "download", onClick: () => askPassword({ title: "Make a backup", confirmLabel: "Download",
      lead: "The backup file is encrypted with your master password. Keep it somewhere safe; it is not a substitute for remembering the password.",
      action: async (pw) => {
        await api.download("/api/vault/backup", "mot-vault-backup.motv", { password: pw });
        toast("Backup ready. Your browser saves it to your downloads.", "ok", 4200);
      } }) });
    return h("section", { class: "section stack-l", "aria-label": "Vault" }, sectionHead("Vault"),
      h("div", { class: "form-grid" },
        h("div", { class: "stack-s" }, h("span", { class: "label" }, "Current master password"), oldPw.el),
        h("div", { class: "stack-s" }, h("span", { class: "label" }, "New master password"), newPw.el, meter.el, note)),
      h("div", { class: "stack-s" }, h("span", { class: "label" }, "Repeat the new password"), confirmPw.el),
      h("div", { class: "cluster" }, change, backup));
  }

  try {
    cfg = await api.get("/api/settings");
    if (!S.alive) return () => S.dispose();
    mount(body,
      appearance(), privacy(), timing(), integrations(), vault(),
      banner({ tone: "info", body: "Your theme choice is kept on this computer. Everything else is stored in the encrypted vault." }));
  } catch (e) {
    if (S.alive) mount(body, banner({ tone: "bad", title: "Settings could not be loaded.", body: e.message || "Try again." }));
  }
  return () => S.dispose();
}
