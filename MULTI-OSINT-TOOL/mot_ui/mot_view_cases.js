// MULTI-OSINT-TOOL :: Cases. Every saved search, newest first. Opening one shows it in the results screen.
// Only what the server returns is shown, as text. A case file that cannot be read is listed as damaged, never hidden.
import { h, icon, mount, shorten, ago, plural, TYPE_ICON } from "./mot_dom.js";
import * as api from "./mot_api.js";
import { TYPE_LABEL, scope, banner, chip, emptyState, errorPlate, loadingPlate, pageHead } from "./mot_ui.js";

const LEVEL = { low: "Low", moderate: "Moderate", high: "High", critical: "Critical" };
const TONE = { low: "ok", moderate: "warn", high: "bad", critical: "bad" };

export async function mountCases(root, p, ctx) {
  const S = scope();
  const U = { q: "" };
  const search = h("input", { class: "input", type: "search", id: "case-filter", placeholder: "Filter by name or address", maxlength: "200",
    autocomplete: "off", spellcheck: "false", "aria-label": "Filter cases" });
  const count = h("p", { class: "small muted", "aria-live": "polite" });
  const list = h("div", { class: "stack-l" });
  search.addEventListener("input", () => {
    U.q = search.value.trim().toLowerCase();
    paintList(cases);
  });
  mount(root, h("div", { class: "page stack-l" },
    pageHead({ eyebrow: "Saved searches", title: "Cases",
      lead: "Every search you saved, kept encrypted in your vault. Open one to see its findings, relationships and notes, or to export it.",
      actions: h("a", { class: "btn btn-primary", href: "#/" }, icon("search", "s"), "New search") }),
    banner({ tone: "info", body: "Cases stay on this computer. Passwords and tokens are never saved with a case." }),
    h("div", { class: "filterbar" }, search, count),
    list));

  let cases = [];

  function caseRow(c) {
    const title = c.damaged ? h("span", { class: "strong" }, "Damaged case file") : h("a", { class: "case-link", href: "#/case/" + c.id }, shorten(c.title || c.target || "Case", 140));
    return h("div", { class: "case-row" },
      h("div", { class: "stack-s" }, title,
        h("div", { class: "small muted cluster-s" }, icon(TYPE_ICON[c.ttype] || "tag", "s"), h("span", {}, TYPE_LABEL[c.ttype] || c.ttype || "Target"),
          h("span", {}, "·"), h("span", {}, ago(c.created)),
          c.damaged ? h("span", {}, "This file could not be read. Health can check it.") : null)),
      c.damaged ? chip("Damaged", "bad", "warn") : chip(`Exposure ${c.score} · ${LEVEL[c.level] || "Unknown"}`, TONE[c.level] || "mute"),
      h("span", { class: "small muted" }, c.damaged ? "" : plural(c.tools_ok || 0, "tool") + " with data"),
      c.damaged ? null : h("a", { class: "btn btn-s", href: "#/case/" + c.id }, "Open"));
  }

  function paintList(all) {
    const shown = all.filter((c) => !U.q || [c.title, c.target, TYPE_LABEL[c.ttype], c.ttype].join(" ").toLowerCase().includes(U.q));
    count.textContent = all.length ? (shown.length === all.length ? plural(all.length, "case") : `${plural(shown.length, "case")} of ${all.length}`) : "";
    list.replaceChildren();
    if (!all.length) {
      list.appendChild(emptyState({ ic: "folder", title: "No cases yet", text: "Search for an email, a username, a domain, an address or a phone number. Searches are saved as cases unless you turn saving off.",
        action: h("a", { class: "btn btn-primary", href: "#/" }, icon("search", "s"), "Start a search") }));
      return;
    }
    if (!shown.length) {
      list.appendChild(emptyState({ ic: "search", title: "No case matches", text: "Clear the filter to see all of them." }));
      return;
    }
    list.appendChild(h("div", { class: "stack-s", role: "list" }, ...shown.map((c) => caseRow(c))));
  }

  mount(list, loadingPlate("Opening your cases…"));
  try {
    const d = await api.get("/api/cases");
    if (S.alive) {
      cases = Array.isArray(d.cases) ? d.cases : [];
      paintList(cases);
    }
  } catch (e) {
    if (S.alive) mount(list, errorPlate(e, null));
  }
  return () => S.dispose();
}
