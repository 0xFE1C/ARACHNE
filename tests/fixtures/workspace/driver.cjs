// The driver `tests/integration/test_ui_triage_usability.py` runs in node.
//
// It loads the *shipped* keyboard model (REQ-UIX-006's `workspace.js`) with
// `require`, presses documented keys on it, performs the HTTP requests those keys produce
// against a real server, and prints one JSON line of observations on stdout. Nothing here decides
// what is correct: the assertions live in the Python test, and the shortcut table it is checked
// against lives in `arachne/api/workspace.py`.
//
// Invocation: `node tests/fixtures/workspace/driver.cjs`, with the scenario as a JSON document on
// **stdin** — `{mode, base_url, api_key, count, table}`. The command line carries no data at all,
// which is why the caller can hand this process nothing but a literal program and this path.
/* eslint-disable no-console */
const fs = require("fs");

// Resolved relative to this file, so the path is fixed and a moved script fails loudly here.
const core = require("../../../src/arachne/templates/web/static/workspace.js");
const args = JSON.parse(fs.readFileSync(0, "utf8"));
const baseUrl = args.base_url;
const HEADERS = { "x-api-key": args.api_key };

// The synthetic key events a browser would dispatch for each documented spelling.
function eventFor(key) {
  if (key === "mod+z") return { key: "z", ctrlKey: true };
  if (key === "shift+x") return { key: "X", shiftKey: true };
  if (key === "?") return { key: "?", shiftKey: true };
  if (key === "enter") return { key: "Enter" };
  if (key === "escape") return { key: "Escape" };
  return { key: key };
}

function pressKeys(state, keys, hrefs) {
  const effects = [];
  for (const key of keys) {
    const result = core.press(state, eventFor(key), { hrefs: hrefs || {} });
    state = result.state;
    effects.push({ key: key, effect: result.effect });
  }
  return { state: state, effects: effects };
}

async function text(url, init) {
  const response = await fetch(url, init || { headers: HEADERS });
  const body = await response.text();
  if (!response.ok) throw new Error(url + " -> " + response.status + " " + body.slice(0, 200));
  return body;
}

async function post(path, form) {
  return await text(baseUrl + path, {
    method: "POST",
    headers: Object.assign(
      { "content-type": "application/x-www-form-urlencoded", "hx-request": "true" },
      HEADERS
    ),
    body: new URLSearchParams(form),
  });
}

// The rows the server rendered: their ids, and each row's detail link (so `Enter` is a real link).
function parseRows(body) {
  const ids = [];
  const hrefs = {};
  const blocks = body.split('<tr class="row"').slice(1);
  for (const block of blocks) {
    const idMatch = block.match(/data-row-id="(\d+)"/);
    if (!idMatch) continue;
    const id = Number(idMatch[1]);
    ids.push(id);
    const link = block.match(/href="([^"]+)"[^>]*data-row-open/);
    if (link) hrefs[id] = link[1].replace(/&amp;/g, "&");
  }
  return { ids: ids, hrefs: hrefs };
}

function tokenOf(body) {
  const match = body.match(/name="token" value="([^"]+)"/);
  if (!match) throw new Error("the action offered no undo");
  return match[1];
}

function focusParams(state) {
  const params = core.requestParams(state);
  return { sel: params.sel, focus: params.focus, scroll: params.scroll };
}

function modeShortcuts() {
  const bound = {};
  const mismatches = [];
  for (const shortcut of args.table) {
    for (const key of shortcut.keys) {
      bound[key] = core.KEYMAP[key] || null;
      if (bound[key] !== shortcut.action) {
        mismatches.push(key + ": documented " + shortcut.action + ", bound " + bound[key]);
      }
    }
  }
  const undocumented = Object.keys(core.KEYMAP).filter(function (key) {
    return !(key in bound);
  });
  const presses = [];
  for (const shortcut of args.table) {
    const start = core.createState({ ids: [1, 2, 3], focusId: 2, selected: [2] });
    for (const key of shortcut.keys) {
      const result = core.press(start, eventFor(key), { hrefs: { 2: "/ui/findings/2" } });
      presses.push({ key: key, action: shortcut.action, effect: result.effect.type });
    }
  }
  return { bound: bound, mismatches: mismatches, undocumented: undocumented, presses: presses };
}

function modeRerender() {
  const started = core.createState({ ids: [1, 2, 3, 4], focusId: 3, selected: [1, 3] });
  const same = core.afterRerender(started, [1, 2, 3, 4]);
  const removed = core.afterRerender(started, [1, 2, 4, 5]);
  const emptied = core.afterRerender(started, []);
  // Anchor on row 1, then J twice to row 3: Shift+X takes the range between them.
  let ranged = core.createState({ ids: [1, 2, 3, 4], focusId: 1, selected: [1], anchor: 1 });
  ranged = pressKeys(ranged, ["j", "j", "shift+x"]).state;
  return {
    kept_focus: same.focusId,
    kept_selection: same.state.selected,
    replaced_focus: removed.focusId,
    replaced_selection: removed.state.selected,
    empty_focus: emptied.focusId,
    shift_range: ranged.selected,
    params: core.requestParams(started),
  };
}

async function modeRun() {
  const page = await text(baseUrl + "/ui/findings");
  const parsed = parseRows(page);
  if (parsed.ids.length !== args.count) {
    throw new Error("expected " + args.count + " rows, the server rendered " + parsed.ids.length);
  }
  let state = core.createState({ ids: parsed.ids, selected: [], focusId: parsed.ids[0], scroll: 0 });
  const pressed = [];

  // ---- phase A: one finding at a time, keyboard only, timed.
  const started = Date.now();
  const tokens = [];
  for (let i = 0; i < parsed.ids.length; i++) {
    if (i > 0) {
      state = pressKeys(state, ["j"]).state;
      pressed.push("j");
    }
    const result = core.press(state, eventFor("t"), { hrefs: {} });
    state = result.state;
    pressed.push("t");
    if (result.effect.type !== "submit") throw new Error("t did not produce a triage");
    const fragment = await post(
      "/ui/findings/actions",
      Object.assign(
        { action: "triage", finding_ids: result.effect.ids.join(",") },
        focusParams(state)
      )
    );
    tokens.push(tokenOf(fragment));
    state = core.afterRerender(state, parseRows(fragment).ids).state;
  }
  const elapsedMs = Date.now() - started;

  // ---- phase B: one undo for that batch, via Cmd/Ctrl+Z.
  const undone = await post(
    "/ui/findings/undo",
    Object.assign({ token: tokens[tokens.length - 1] }, focusParams(state))
  );
  pressed.push("mod+z");

  // ---- phase C: select everything from the keyboard, suppress with a reason, undo it.
  state = pressKeys(state, ["x"]).state;
  pressed.push("x");
  for (let i = 0; i < parsed.ids.length - 1; i++) {
    state = pressKeys(state, ["k"]).state;
    pressed.push("k");
  }
  const range = pressKeys(state, ["shift+x"]);
  state = range.state;
  pressed.push("shift+x");
  const selectedCount = state.selected.length;
  const drawer = pressKeys(state, ["s"]);
  state = drawer.state;
  pressed.push("s");
  if (drawer.effects[0].effect.type !== "drawer") throw new Error("s did not open the drawer");
  const suppressed = await post(
    "/ui/findings/actions",
    Object.assign(
      {
        action: "suppress",
        finding_ids: state.selected.join(","),
        reason: "trimmed in the scripted usability run: static banner, not an issue",
      },
      focusParams(state)
    )
  );
  const suppressToken = tokenOf(suppressed);
  state = core.afterRerender(state, parseRows(suppressed).ids).state;
  const afterUndo = await post(
    "/ui/findings/undo",
    Object.assign({ token: suppressToken }, focusParams(state))
  );
  pressed.push("mod+z");

  // ---- phase D: open a finding and come back with the selection intact (§4.4).
  const opened = core.press(state, eventFor("enter"), { hrefs: parseRows(afterUndo).hrefs });
  pressed.push("enter");
  let roundTrip = false;
  if (opened.effect.type === "open" && opened.effect.href) {
    const detail = await text(baseUrl + opened.effect.href);
    const back = detail.match(/href="([^"]+)" data-back-to-list/);
    const backHref = back ? back[1].replace(/&amp;/g, "&") : "";
    const list = backHref ? await text(baseUrl + backHref) : "";
    roundTrip = /aria-current="true"/.test(list) && /data-selected="true"/.test(list);
  }

  return {
    ids: parsed.ids,
    pressed: pressed,
    elapsed_ms: elapsedMs,
    triaged: parsed.ids.length,
    undo_restored: /Undone: 1 finding/.test(undone),
    selected_count: selectedCount,
    suppressed: /suppressed\./.test(suppressed),
    suppressed_then_undone: new RegExp("Undone: " + parsed.ids.length + " finding").test(afterUndo),
    round_trip: roundTrip,
    keyboard_only: pressed.every(function (key) {
      return key in core.KEYMAP;
    }),
  };
}

(async function main() {
  const modes = { shortcuts: modeShortcuts, rerender: modeRerender, run: modeRun };
  const handler = modes[args.mode];
  if (!handler) throw new Error("unknown mode " + args.mode);
  console.log(JSON.stringify(await handler()));
})().catch(function (error) {
  console.error(error && error.stack ? error.stack : String(error));
  process.exit(1);
});
