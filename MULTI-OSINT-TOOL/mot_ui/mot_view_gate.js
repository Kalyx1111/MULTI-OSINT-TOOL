// MULTI-OSINT-TOOL :: vault gate (create / unlock). Nothing here is stored: the password lives in the input until the request is sent, then is wiped.
import { h, icon, clear, mount } from "./mot_dom.js";
import * as api from "./mot_api.js";
import { saveBlob } from "./mot_api.js";
import { banner, field, pwInput, strengthMeter, assessPassword, readFileBase64, waitText, scope } from "./mot_ui.js";
import { rosette, brandMark } from "./mot_rosette.js";

export function mountGate(root, { mode, needsKeyfile, notice }, { done }) {
  const create = mode === "create";
  const S = scope();
  let keyfile = null; // {name, b64}
  let cooling = 0;
  let busy = false;

  const pw1 = pwInput({ autocomplete: create ? "new-password" : "current-password", autofocus: true });
  const pw2 = create ? pwInput({ autocomplete: "new-password" }) : null;
  const meter = strengthMeter();
  const meterText = h("p", { class: "hint", "aria-live": "polite" }, create ? "At least 12 characters. A passphrase of 20 or more is best." : "");
  const f1 = field({ label: create ? "Master password" : "Master password", control: pw1.el, target: pw1.input });
  const f2 = create ? field({ label: "Repeat the master password", control: pw2.el, target: pw2.input }) : null;
  const understand = create ? h("input", { type: "checkbox", id: "gate-understand" }) : null;
  const errorLine = h("p", { class: "hint is-error", role: "alert" });
  errorLine.hidden = true;

  // ---- key file (optional when creating, required when the vault was sealed with one)
  const fileInput = h("input", { type: "file", class: "sr-only", tabIndex: -1, "aria-hidden": "true" });
  const fileName = h("span", { class: "small muted" }, "No key file chosen");
  const chooseBtn = h("button", { class: "btn btn-s", type: "button", on: { click: () => fileInput.click() } }, icon("key", "s"), needsKeyfile ? "Choose your key file" : "Choose a key file");
  const clearBtn = h("button", { class: "btn btn-s btn-quiet", type: "button", hidden: true, on: { click: () => setKeyfile(null) } }, "Remove");
  const genBtn = create ? h("button", { class: "btn btn-s btn-quiet", type: "button", on: { click: generateKeyfile } }, icon("plus", "s"), "Make one for me") : null;
  function setKeyfile(kf) {
    keyfile = kf;
    fileName.textContent = kf ? kf.name : "No key file chosen";
    clearBtn.hidden = !kf;
    if (!kf) fileInput.value = "";
  }
  fileInput.addEventListener("change", async () => {
    try {
      const f = fileInput.files && fileInput.files[0];
      setKeyfile(f ? { name: f.name, b64: await readFileBase64(f) } : null);
      showError("");
    } catch (e) {
      setKeyfile(null);
      showError(e.message);
    }
  });
  function generateKeyfile() {
    const bytes = new Uint8Array(64);
    crypto.getRandomValues(bytes);
    saveBlob(new Blob([bytes], { type: "application/octet-stream" }), "mot-keyfile.bin");
    let bin = "";
    bytes.forEach((b) => (bin += String.fromCharCode(b)));
    setKeyfile({ name: "mot-keyfile.bin (saved to your Downloads folder)", b64: btoa(bin) });
  }
  const keyBlock = h("div", { class: "stack-s" },
    h("div", { class: "cluster" }, chooseBtn, genBtn, clearBtn), fileName, fileInput,
    create ? h("p", { class: "hint" }, "A key file is a second lock: the vault then opens only with the password and this exact file. Move it to a USB stick or another safe place. Without it, nobody can open the vault, including you.") : null);

  // ---- submit button
  const submitLabel = create ? "Create vault" : "Unlock";
  const submit = h("button", { class: "btn btn-primary btn-lg btn-block", type: "submit" }, submitLabel);

  function showError(msg) {
    errorLine.textContent = msg || "";
    errorLine.hidden = !msg;
  }
  function paintSubmit() {
    submit.disabled = busy || cooling > 0 || (create && !(understand && understand.checked));
    if (busy) return;
    clear(submit);
    submit.append(cooling > 0 ? `Try again in ${waitText(cooling)}` : submitLabel);
  }
  function startCooldown(seconds) {
    cooling = Math.max(1, Math.ceil(Number(seconds) || 5));
    paintSubmit();
    const t = S.interval(() => {
      cooling -= 1;
      if (cooling <= 0) {
        clearInterval(t);
        cooling = 0;
      }
      paintSubmit();
    }, 1000);
  }

  function onInput() {
    if (!create) return;
    const a = assessPassword(pw1.value);
    meter.set(a.level);
    meterText.textContent = !pw1.value ? "At least 12 characters. A passphrase of 20 or more is best." : a.ok ? (a.level >= 3 ? "Strong." : "Acceptable. Longer is stronger.") : a.problem;
    f1.setError("");
  }
  pw1.input.addEventListener("input", onInput);
  if (understand) understand.addEventListener("change", paintSubmit);

  async function onSubmit(ev) {
    ev.preventDefault();
    if (busy || cooling > 0) return;
    showError("");
    f1.setError("");
    if (f2) f2.setError("");
    const pw = pw1.value;
    if (!pw) return f1.setError("Enter your master password.");
    if (create) {
      const a = assessPassword(pw);
      if (!a.ok) return f1.setError(a.problem || "Choose a stronger password.");
      if (pw !== pw2.value) return f2.setError("The two passwords do not match.");
      if (!understand.checked) return showError("Please confirm that you understand there is no password recovery.");
    } else if (needsKeyfile && !keyfile) {
      return showError("This vault was sealed with a key file. Choose it first.");
    }
    busy = true;
    submit.disabled = true;
    mount(submit, h("span", { class: "spinner" }), create ? "Sealing your vault…" : "Unlocking…");
    try {
      const body = { password: pw };
      if (create) body.confirm = pw2.value;
      if (keyfile) body.keyfile = keyfile.b64;
      const st = await api.post(create ? "/api/vault/create" : "/api/vault/unlock", body);
      pw1.wipe();
      if (pw2) pw2.wipe();
      keyfile = null;
      S.dispose();
      done(st);
      return;
    } catch (e) {
      if (e instanceof api.ApiError && e.code === "throttled") {
        startCooldown(e.extra.wait);
        showError(e.message);
      } else if (e instanceof api.ApiError && e.code === "weak_password") f1.setError(e.message);
      else showError(e.message || "That did not work.");
      if (!create) pw1.wipe();
    }
    busy = false;
    paintSubmit();
  }

  const lead = create
    ? "One master password protects everything MULTI-OSINT-TOOL keeps: your API keys, your cases and the audit log. It is all encrypted on this computer with AES-256-GCM. Nothing leaves it."
    : "Your keys and cases stay sealed until you enter the master password.";

  const form = h("form", { class: "stack", novalidate: true, autocomplete: "off", on: { submit: onSubmit } },
    f1.el,
    create ? h("div", { class: "stack-s" }, meter.el, meterText) : null,
    f2 ? f2.el : null,
    create ? h("details", { class: "disclose" }, h("summary", {}, icon("chevronRight", "s"), "Add a key file (optional, stronger)"), h("div", { class: "disclose-body" }, keyBlock)) : needsKeyfile ? h("div", { class: "stack-s" }, h("span", { class: "label" }, "Key file"), keyBlock) : null,
    create ? h("label", { class: "check" }, understand, h("span", {}, "I understand there is no way to recover this password. If I lose it (or my key file), the vault cannot be opened by anyone.")) : null,
    errorLine, submit);

  const card = h("div", { class: "gate-card cert" },
    h("div", { class: "gate-brand" }, brandMark(), h("span", { class: "wordmark" }, "MULTI-OSINT-TOOL")),
    h("div", { class: "stack-s" }, h("h1", { class: "display d-2" }, create ? "Create your vault" : "Unlock your vault"), h("p", { class: "muted" }, lead)),
    notice ? banner({ tone: "info", body: notice }) : null,
    form,
    h("p", { class: "tiny faint gate-note" }, icon("lock", "s"), h("span", {}, "AES-256-GCM, key derived with Argon2id. Stays on this computer.")));

  mount(root, h("main", { class: "gate" }, rosette("gate-rosette"), card));
  paintSubmit();
  if (needsKeyfile && !create) pw1.input.focus();
  return () => S.dispose();
}
