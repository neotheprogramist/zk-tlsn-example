// In-page mirror of the structured event stream that log.mjs already emits.
// Subscribes via onLog() so it picks up both main-thread events and
// worker-relayed events (see flow.mjs).
//
// Usage:
//   const log = createLog(container, { filterPrefix: "zktls" });
//   log.clear();      // reset
//   log.dispose();    // unsubscribe (e.g. on page unload)

import { onLog } from "../log.mjs";

const MAX_ROWS_DEFAULT = 500;

function fmtTime(isoTs) {
  const d = new Date(isoTs);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

function fmtFields(fields) {
  const parts = [];
  for (const [k, v] of Object.entries(fields)) {
    let s;
    if (typeof v === "boolean" || typeof v === "number" || v == null) s = String(v);
    else if (typeof v === "string" && /^[A-Za-z0-9_.-]+$/.test(v)) s = v;
    else s = JSON.stringify(v);
    parts.push(`${k}=${s}`);
  }
  return parts.join(" ");
}

export function createLog(container, opts = {}) {
  const { filterPrefix = "", maxRows = MAX_ROWS_DEFAULT } = opts;
  container.classList.add("log");
  container.replaceChildren();

  function append(entry) {
    if (filterPrefix && !entry.name.startsWith(filterPrefix)) return;
    const row = document.createElement("div");
    row.className = "log__row";
    row.dataset.level = entry.level.toLowerCase();

    const time = document.createElement("span");
    time.className = "log__time";
    time.textContent = fmtTime(entry.ts);

    const name = document.createElement("span");
    name.className = "log__name";
    name.textContent = entry.name;

    const fields = document.createElement("span");
    fields.className = "log__fields";
    fields.textContent = fmtFields(entry.fields);

    row.append(time, name, fields);
    container.append(row);

    while (container.childElementCount > maxRows) {
      container.firstChild.remove();
    }
    container.scrollTop = container.scrollHeight;
  }

  function clear() {
    container.replaceChildren();
  }

  const off = onLog((entry) => append(entry));

  return { append, clear, dispose: off };
}
