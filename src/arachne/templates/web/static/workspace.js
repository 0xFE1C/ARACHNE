/* ARACHNE triage workspace — the keyboard layer (REQ-UIX-006, .spec/06-ui-ux.md §4.3).
 *
 * Two layers, deliberately separated:
 *
 *   core   — pure functions over a plain state object. No DOM, no globals, no I/O. This is the
 *            whole keyboard model: moving, selecting, the range anchor, and what a re-render
 *            does to focus. It is what the scripted usability run drives and what the test
 *            suite asserts against the *documented* shortcut table in arachne/api/workspace.py.
 *   adapter— the thin binding to the page: keydown listener, the hidden fields the server
 *            renders selection from, and the re-apply after an htmx swap. Kept small on purpose,
 *            because the DOM is the part a test cannot reach in this repository.
 *
 * The server is authoritative for everything that is data: which findings exist, what a page
 * contains, and what a bulk action does. Nothing here filters, counts or decides. Filtering is
 * the server's (REQ-UIX-002) — a client-side filter would disagree with the counts, which is
 * the WP-05 pitfall.
 *
 * KEYMAP is the advertised key → action binding. `tests/unit/test_workspace.py` asserts it is an
 * exact bijection with the Python SHORTCUTS table, so a key cannot exist undocumented and a
 * documented key cannot be missing.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api; // node (the scripted run and the test driver)
  }
  if (typeof window !== "undefined") {
    window.ArachneWorkspace = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const KEYMAP = {
    j: "next",
    k: "previous",
    x: "select",
    "shift+x": "select-range",
    t: "triage",
    s: "suppress",
    a: "accept",
    enter: "open",
    "mod+z": "undo",
    "/": "search",
    "?": "shortcut-sheet",
    escape: "escape",
  };

  /** The canonical spelling of a keyboard event, or null when it is not a shortcut. */
  function normalize(event) {
    const key = event && typeof event.key === "string" ? event.key : "";
    if (!key) return null;
    if (key === "Escape" || key === "Esc") return "escape";
    if (key === "Enter") return "enter";
    const mod = Boolean(event.metaKey || event.ctrlKey);
    const lower = key.toLowerCase();
    if (mod) return lower === "z" ? "mod+z" : null; // ⌘/Ctrl+Z, and nothing else with a modifier
    if (event.altKey) return null;
    // `?` and `/` are the printed characters, and `?` already *is* Shift+/ on most layouts: the
    // event's key is the character, so folding it into `shift+?` would bind a chord nobody has.
    if (lower === "?" || lower === "/") return lower;
    if (event.shiftKey && lower.length === 1) return "shift+" + lower;
    if (lower.length === 1) return lower;
    return null;
  }

  function createState(options) {
    const ids = (options && options.ids ? options.ids : []).map(Number);
    const selected = (options && options.selected ? options.selected : []).map(Number);
    return {
      ids: ids,
      focusId: options && options.focusId != null ? Number(options.focusId) : null,
      selected: selected.filter(function (id) { return ids.indexOf(id) >= 0; }),
      anchor: options && options.anchor != null ? Number(options.anchor) : null,
      scroll: options && options.scroll ? Number(options.scroll) : 0,
      drawer: null,
      sheet: false,
    };
  }

  function clone(state) {
    return {
      ids: state.ids.slice(),
      focusId: state.focusId,
      selected: state.selected.slice(),
      anchor: state.anchor,
      scroll: state.scroll,
      drawer: state.drawer,
      sheet: state.sheet,
    };
  }

  function indexOfId(state, id) {
    return state.ids.indexOf(id);
  }

  /** The focused row, or the first row when nothing is focused yet. */
  function currentId(state) {
    if (state.focusId != null && indexOfId(state, state.focusId) >= 0) return state.focusId;
    return state.ids.length ? state.ids[0] : null;
  }

  /** The rows an action applies to: the selection, or the focused row when nothing is selected. */
  function targetIds(state) {
    if (state.selected.length) return state.selected.slice();
    const id = currentId(state);
    return id == null ? [] : [id];
  }

  function move(state, step) {
    if (!state.ids.length) return state;
    const from = currentId(state) == null ? -1 : indexOfId(state, currentId(state));
    const next = Math.min(state.ids.length - 1, Math.max(0, from + step));
    const moved = clone(state);
    moved.focusId = state.ids[next];
    return moved;
  }

  function toggle(state, id) {
    if (id == null) return state;
    const next = clone(state);
    const at = next.selected.indexOf(id);
    if (at >= 0) next.selected.splice(at, 1);
    else next.selected.push(id);
    next.selected.sort(function (a, b) { return a - b; });
    next.anchor = id;
    return next;
  }

  /** Shift+X: every row between the anchor and the focused one, inclusive. */
  function selectRange(state) {
    const focusId = currentId(state);
    if (focusId == null) return state;
    const anchor = state.anchor == null ? focusId : state.anchor;
    const a = indexOfId(state, anchor);
    const b = indexOfId(state, focusId);
    if (a < 0 || b < 0) return state;
    const span = state.ids.slice(Math.min(a, b), Math.max(a, b) + 1);
    const next = clone(state);
    span.forEach(function (id) {
      if (next.selected.indexOf(id) < 0) next.selected.push(id);
    });
    next.selected.sort(function (a2, b2) { return a2 - b2; });
    return next;
  }

  /**
   * A key press, as a new state and the effect the page should carry out.
   *
   * `effects` in the shape the adapter dispatches:
   *   focus | selection | clear | submit{action, ids} | drawer{drawer} | sheet{open, close}
   *   open{href} | undo | search | none
   *
   * `hrefs` maps a finding id to its detail href, so `Enter` produces a plain link the driver
   * can follow — the core never touches the DOM to find one.
   */
  function press(state, event, options) {
    const hrefs = (options && options.hrefs) || {};
    const action = KEYMAP[normalize(event)];
    if (!action) return { state: state, effect: { type: "none" } };
    if (action === "next" || action === "previous") {
      const moved = move(state, action === "next" ? 1 : -1);
      return { state: moved, effect: { type: "focus", id: moved.focusId } };
    }
    if (action === "select") {
      const moved = toggle(state, currentId(state));
      return { state: moved, effect: { type: "selection", selected: moved.selected.slice() } };
    }
    if (action === "select-range") {
      const moved = selectRange(state);
      return { state: moved, effect: { type: "selection", selected: moved.selected.slice() } };
    }
    if (action === "triage") {
      return { state: state, effect: { type: "submit", action: "triage", ids: targetIds(state) } };
    }
    if (action === "suppress" || action === "accept") {
      const opened = clone(state);
      opened.drawer = action;
      return { state: opened, effect: { type: "drawer", drawer: action } };
    }
    if (action === "open") {
      const id = currentId(state);
      if (id == null) return { state: state, effect: { type: "none" } };
      return { state: state, effect: { type: "open", id: id, href: hrefs[id] || null } };
    }
    if (action === "undo") return { state: state, effect: { type: "undo" } };
    if (action === "search") return { state: state, effect: { type: "search" } };
    if (action === "shortcut-sheet") {
      const opened = clone(state);
      opened.sheet = true;
      return { state: opened, effect: { type: "sheet", open: true } };
    }
    // escape: the sheet first, then the drawer, then the selection and focus.
    if (state.sheet) {
      const closed = clone(state);
      closed.sheet = false;
      return { state: closed, effect: { type: "sheet", close: true } };
    }
    if (state.drawer) {
      const closed = clone(state);
      closed.drawer = null;
      return { state: closed, effect: { type: "drawer", drawer: null, close: true } };
    }
    const cleared = clone(state);
    cleared.selected = [];
    cleared.anchor = null;
    cleared.focusId = null;
    return { state: cleared, effect: { type: "clear" } };
  }

  /**
   * What survives a re-render (the htmx swap after a bulk action).
   *
   * This is the WP-05 pitfall made into a function: a roving tabindex that resets on re-render
   * makes the screen unusable, so focus is *carried* — the same row when it is still on the page,
   * and otherwise the row that took its place, so the operator's next `J` continues where they
   * were instead of jumping to the top. Selection keeps only ids still present; a page that
   * changed under the operator is not a licence to act on a stale id.
   */
  function afterRerender(state, ids) {
    const next = clone(state);
    const previous = state.focusId;
    const before = previous == null ? -1 : indexOfId(state, previous);
    next.ids = ids.map(Number);
    next.selected = state.selected.filter(function (id) { return next.ids.indexOf(id) >= 0; });
    if (next.ids.length === 0) {
      next.focusId = null;
    } else if (previous != null && next.ids.indexOf(previous) >= 0) {
      next.focusId = previous;
    } else {
      const at = Math.min(next.ids.length - 1, Math.max(0, before));
      next.focusId = next.ids[at];
    }
    if (next.anchor != null && next.ids.indexOf(next.anchor) < 0) next.anchor = null;
    return { state: next, focusId: next.focusId };
  }

  /** The three fields the server renders focus, selection and the scroll offset from. */
  function requestParams(state) {
    return {
      sel: state.selected.join(","),
      focus: state.focusId == null ? "" : String(state.focusId),
      scroll: String(state.scroll || 0),
    };
  }

  /** The URL a row's Enter should open: the detail screen, with the workspace state attached. */
  function detailHref(base, id, state) {
    const params = requestParams(state);
    const query = [];
    if (params.sel) query.push("sel=" + encodeURIComponent(params.sel));
    query.push("focus=" + encodeURIComponent(String(id)));
    if (state.scroll) query.push("scroll=" + encodeURIComponent(params.scroll));
    return base + "?" + query.join("&");
  }

  /** True when a drawer holds something the operator typed, so navigation needs a confirm. */
  function hasDraft(fields) {
    return (fields || []).some(function (value) {
      return typeof value === "string" && value.trim() !== "";
    });
  }

  const core = {
    KEYMAP: KEYMAP,
    normalize: normalize,
    createState: createState,
    press: press,
    afterRerender: afterRerender,
    targetIds: targetIds,
    requestParams: requestParams,
    detailHref: detailHref,
    hasDraft: hasDraft,
  };

  // ------------------------------------------------------------------------- DOM adapter
  if (typeof document === "undefined") {
    return core;
  }

  let state = null;
  let root = null;

  function rowsOf(node) {
    return Array.prototype.slice.call(node.querySelectorAll("[data-row-id]"));
  }

  function hrefsOf(node) {
    const hrefs = {};
    rowsOf(node).forEach(function (row) {
      const link = row.querySelector("[data-row-open]");
      if (link) hrefs[row.getAttribute("data-row-id")] = link.getAttribute("href");
    });
    return hrefs;
  }

  function setField(name, value) {
    const field = root && root.querySelector('[data-workspace="' + name + '"]');
    if (field) field.value = value;
  }

  function syncFields() {
    const params = requestParams(state);
    setField("sel", params.sel);
    setField("focus", params.focus);
    setField("scroll", String(window.scrollY || state.scroll || 0));
  }

  function paint(focus) {
    const rows = rowsOf(root);
    rows.forEach(function (row) {
      const id = Number(row.getAttribute("data-row-id"));
      const focused = id === state.focusId;
      row.setAttribute("data-focused", focused ? "true" : "false");
      row.setAttribute("tabindex", focused ? "0" : "-1");
      if (focused) row.setAttribute("aria-current", "true");
      else row.removeAttribute("aria-current");
      const box = row.querySelector("[data-row-check]");
      if (box) box.checked = state.selected.indexOf(id) >= 0;
    });
    const count = root.querySelector("[data-selection-count]");
    if (count) count.textContent = state.selected.length + " selected";
    syncFields();
    if (focus) {
      const target = rows.filter(function (row) {
        return Number(row.getAttribute("data-row-id")) === state.focusId;
      })[0];
      if (target) target.focus({ preventScroll: true });
    }
  }

  function drawerNode(name) {
    return name ? root.querySelector('[data-drawer="' + name + '"]') : null;
  }

  function drawerFields(name) {
    const node = drawerNode(name);
    if (!node) return [];
    return Array.prototype.slice.call(node.querySelectorAll("input, textarea, button"));
  }

  /**
   * Open one drawer and close the other.
   *
   * The closed drawer's fields are *disabled*, not merely hidden: a `display: none` field is still
   * a candidate for constraint validation, so leaving its `required` attribute live would let a
   * closed drawer block the `T` key with an error nobody can see (and would post an empty reason
   * with every triage). Disabling is what makes "closed" mean closed.
   */
  function showDrawer(name) {
    ["suppress", "accept"].forEach(function (other) {
      const node = drawerNode(other);
      if (!node) return;
      const open = other === name;
      node.hidden = !open;
      drawerFields(other).forEach(function (field) {
        field.disabled = !open;
      });
    });
    const node = drawerNode(name);
    if (!node) return;
    const first = node.querySelector("[data-drawer-first]");
    if (first) first.focus();
  }

  function openSheet() {
    const sheet = root.querySelector("[data-shortcut-sheet]");
    if (!sheet) return;
    if (typeof sheet.showModal === "function") sheet.showModal();
    else sheet.removeAttribute("hidden");
    const closer = sheet.querySelector("[data-close-sheet]");
    if (closer) closer.focus();
  }

  function closeSheet() {
    const sheet = root.querySelector("[data-shortcut-sheet]");
    if (!sheet) return;
    if (typeof sheet.close === "function" && sheet.open) sheet.close();
    else sheet.setAttribute("hidden", "");
    paint(false);
  }

  function fieldsInDrawers() {
    if (!root) return [];
    return Array.prototype.slice
      .call(root.querySelectorAll("[data-drawer] input, [data-drawer] textarea"))
      .map(function (field) {
        return field.value;
      });
  }

  function submit(effect) {
    const form = root && root.querySelector("#triage-form");
    if (!form) return;
    syncFields();
    setField("action", effect.action || "triage");
    const boxes = Array.prototype.slice.call(form.querySelectorAll("[data-row-check]"));
    boxes.forEach(function (box) {
      const id = Number(box.value);
      box.checked = state.selected.indexOf(id) >= 0;
    });
    if (typeof form.requestSubmit === "function") form.requestSubmit();
    else form.submit();
  }

  function run(effect, event) {
    if (effect.type === "none") return;
    if (event) event.preventDefault();
    if (effect.type === "focus" || effect.type === "selection" || effect.type === "clear") {
      paint(effect.type === "focus");
      return;
    }
    if (effect.type === "drawer") {
      showDrawer(effect.drawer);
      if (effect.close) {
        if (hasDraft(fieldsInDrawers()) && !window.confirm("Discard what you typed?")) return;
        showDrawer(null);
        paint(false);
      }
      return;
    }
    if (effect.type === "sheet") {
      if (effect.open) openSheet();
      else closeSheet();
      return;
    }
    if (effect.type === "search") {
      const box = document.querySelector("[data-search-input]");
      if (box) box.focus();
      return;
    }
    if (effect.type === "open") {
      if (effect.href) window.location.assign(effect.href);
      return;
    }
    if (effect.type === "undo") {
      const toast = root.querySelector("[data-undo-toast]");
      const button = toast && toast.querySelector("[data-undo]");
      if (button) button.click();
      return;
    }
    if (effect.type === "submit") submit(effect);
  }

  function onKeydown(event) {
    if (event.defaultPrevented) return;
    const target = event.target;
    const typing =
      target &&
      (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
    if (typing && event.key !== "Escape") return;
    const result = press(state, event, { hrefs: hrefsOf(root) });
    state = result.state;
    run(result.effect, event);
  }

  function onSwap(event) {
    const swapped = event.target;
    const next = swapped && swapped.id === "workspace" ? swapped : null;
    if (!next && !(swapped && swapped.querySelector && swapped.querySelector("[data-workspace-root]"))) {
      return;
    }
    const found = next && next.hasAttribute("data-workspace-root")
      ? next
      : swapped.querySelector("[data-workspace-root]");
    if (!found) return;
    root = found;
    const ids = rowsOf(root).map(function (row) {
      return Number(row.getAttribute("data-row-id"));
    });
    state = afterRerender(state, ids).state;
    paint(true); // the operator's next key continues from where they were (§4.3 pitfall)
  }

  function init() {
    root = document.querySelector("[data-workspace-root]");
    if (!root) {
      // The finding detail screen: Esc is the way back, with the state the link carries.
      const back = document.querySelector("[data-back-to-list]");
      document.addEventListener("keydown", function (event) {
        if (normalize(event) === "escape" && back) window.location.assign(back.getAttribute("href"));
      });
      return;
    }
    const ids = rowsOf(root).map(function (row) {
      return Number(row.getAttribute("data-row-id"));
    });
    const selected = (root.getAttribute("data-selected") || "")
      .split(",")
      .filter(function (part) { return part !== ""; })
      .map(Number);
    const focused = root.getAttribute("data-focused");
    state = createState({
      ids: ids,
      selected: selected,
      focusId: focused ? Number(focused) : null,
      scroll: Number(root.getAttribute("data-scroll") || 0),
    });
    if (state.scroll) window.scrollTo(0, state.scroll);
    showDrawer(null); // every drawer starts closed *and* disabled (see showDrawer)
    document.addEventListener("keydown", onKeydown);
    document.addEventListener("htmx:afterSwap", onSwap);
    const sheet = root.querySelector("[data-shortcut-sheet]");
    if (sheet) {
      // The browser closes a modal <dialog> on Esc itself; keep the model in step with it.
      sheet.addEventListener("close", function () {
        state.sheet = false;
      });
    }
    window.addEventListener("beforeunload", function (event) {
      if (hasDraft(fieldsInDrawers())) {
        event.preventDefault();
        event.returnValue = "";
      }
    });
    root.addEventListener("change", function (event) {
      const box = event.target;
      if (box && box.hasAttribute && box.hasAttribute("data-row-check")) {
        const id = Number(box.value);
        const at = state.selected.indexOf(id);
        if (box.checked && at < 0) state.selected.push(id);
        if (!box.checked && at >= 0) state.selected.splice(at, 1);
        state.selected.sort(function (a, b) { return a - b; });
        state.anchor = id;
        paint(false);
      }
    });
    // One `action` field, set by the button that was pressed (capture phase, so it is set before
    // htmx sees the submit). A form with a name on every button would post two values.
    root.addEventListener(
      "click",
      function (event) {
        const node = event.target;
        if (node && node.hasAttribute && node.hasAttribute("data-action")) {
          setField("action", node.getAttribute("data-action"));
        }
      },
      true
    );
    root.addEventListener("click", function (event) {
      const node = event.target;
      if (!node || !node.hasAttribute) return;
      for (const name of ["suppress", "accept"]) {
        if (node.hasAttribute("data-open-drawer") && node.getAttribute("data-open-drawer") === name) {
          showDrawer(name);
        }
      }
      if (node.hasAttribute("data-open-sheet")) openSheet();
      if (node.hasAttribute("data-close-drawer")) {
        showDrawer(null);
        paint(false);
      }
      if (node.hasAttribute("data-close-sheet")) closeSheet();
    });
    paint(false); // the current row is marked on load, but focus is not stolen
  }

  core.init = init;
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
  return core;
});
