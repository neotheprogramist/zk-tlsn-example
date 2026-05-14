// Ordered step list. Each step is `{ id, label }`; lifecycle = begin → done | fail.
// State on the row is mirrored to data-state so .state-dot and steplist styles pick it up.
//
// Usage:
//   const steps = createSteps(container, [
//     { id: "init",    label: "wasm init"      },
//     { id: "connect", label: "WebTransport"   },
//   ]);
//   steps.begin("init");
//   steps.done("init");
//   steps.fail("connect", "no route to host");

export function createSteps(container, defs) {
  container.classList.add("steplist");
  container.replaceChildren();

  const rows = new Map();

  defs.forEach((def, i) => {
    const row = document.createElement("div");
    row.className = "steplist__row";
    row.dataset.state = "queued";
    row.dataset.id = def.id;

    const dot = document.createElement("span");
    dot.className = "steplist__dot state-dot";
    dot.dataset.state = "queued";

    const index = document.createElement("span");
    index.className = "steplist__index";
    index.textContent = String(i + 1);

    const label = document.createElement("span");
    label.className = "steplist__label";
    label.textContent = def.label;

    const status = document.createElement("span");
    status.className = "steplist__status";
    status.textContent = "queued";

    const elapsed = document.createElement("span");
    elapsed.className = "steplist__elapsed";
    elapsed.textContent = "—";

    const err = document.createElement("span");
    err.className = "steplist__error";

    row.append(dot, index, label, status, elapsed, err);
    container.append(row);
    rows.set(def.id, { row, dot, status, elapsed, err, startedAt: null });
  });

  function setState(id, state) {
    const r = rows.get(id);
    if (!r) return;
    r.row.dataset.state = state;
    r.dot.dataset.state = state;
    r.status.textContent = state;
  }

  function begin(id) {
    const r = rows.get(id);
    if (!r) return;
    r.startedAt = performance.now();
    setState(id, "running");
  }

  function done(id) {
    const r = rows.get(id);
    if (!r) return;
    if (r.startedAt != null) {
      r.elapsed.textContent = `${Math.round(performance.now() - r.startedAt)}ms`;
    }
    setState(id, "done");
  }

  function fail(id, message) {
    const r = rows.get(id);
    if (!r) return;
    if (r.startedAt != null) {
      r.elapsed.textContent = `${Math.round(performance.now() - r.startedAt)}ms`;
    }
    setState(id, "failed");
    r.err.textContent = message ?? "";
  }

  function reset() {
    for (const [id, r] of rows) {
      r.startedAt = null;
      r.elapsed.textContent = "—";
      r.err.textContent = "";
      setState(id, "queued");
    }
  }

  function failAllPending(message) {
    for (const [id, r] of rows) {
      const state = r.row.dataset.state;
      if (state === "running") fail(id, message);
      else if (state === "queued") setState(id, "failed");
    }
  }

  return { begin, done, fail, reset, failAllPending };
}
