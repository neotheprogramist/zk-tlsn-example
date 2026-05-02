// MMR-of-proofs visualization. Modelled on the layout at
// https://mmr.herodotus.dev/ — leaves at the bottom row, merges branching
// upward, peaks (right-spine) highlighted. Colors track per-node state
// (queued/proving/proved/verified/failed) and a sidebar shows each worker
// in the pool with its current job + elapsed time.
//
// v1 supports unbounded N via horizontal scroll on an outer container;
// Ctrl/Cmd + mouse-wheel zooms via a CSS transform on the inner SVG.
// Updates re-render the full SVG on every scheduler snapshot — for the
// demo's working set (low hundreds of nodes) this is comfortably fast.

import { NODE_KIND, NODE_STATE } from "./zkp.scheduler.mjs";

const COL_WIDTH = 64;
const ROW_HEIGHT = 56;
const NODE_W = 56;
const NODE_H = 30;
const PADDING = 32;

const SVG_NS = "http://www.w3.org/2000/svg";

const STATE_COLOR = {
  [NODE_STATE.QUEUED]: { fill: "#dadada", stroke: "#888", textOpacity: 0.6 },
  [NODE_STATE.PROVING]: { fill: "#ffe97a", stroke: "#a18900", textOpacity: 1, pulse: true },
  [NODE_STATE.PROVED]: { fill: "#7ed987", stroke: "#3a8c41", textOpacity: 1 },
  [NODE_STATE.VERIFIED]: { fill: "#7ed987", stroke: "#0e51a8", textOpacity: 1 },
  [NODE_STATE.FAILED]: { fill: "#ff8b8b", stroke: "#a00000", textOpacity: 1 },
};

const PULSE_STYLE_TEXT = `
.zkp-pulse { animation: zkp-pulse-anim 1s ease-in-out infinite; }
@keyframes zkp-pulse-anim {
  0%, 100% { opacity: 1; }
  50%      { opacity: 0.55; }
}
`;

function svg(name, attrs = {}) {
  const el = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
  return el;
}

export function attachVisualization(container, scheduler) {
  // ─── DOM scaffold ─────────────────────────────────────────────────────
  container.replaceChildren();
  container.classList.add("zkp-viz");

  const treePanel = document.createElement("div");
  treePanel.className = "zkp-viz-tree";
  const workerPanel = document.createElement("div");
  workerPanel.className = "zkp-viz-workers";
  container.append(treePanel, workerPanel);

  const treeScroller = document.createElement("div");
  treeScroller.className = "zkp-viz-tree-scroll";
  treePanel.append(treeScroller);

  const root = svg("svg", { class: "zkp-viz-svg" });
  treeScroller.append(root);

  // ─── zoom (CSS transform) ─────────────────────────────────────────────
  let zoom = 1;
  function setZoom(z) {
    zoom = Math.max(0.25, Math.min(2.5, z));
    root.style.transformOrigin = "0 100%";
    root.style.transform = `scale(${zoom})`;
  }
  treeScroller.addEventListener(
    "wheel",
    (ev) => {
      if (!ev.ctrlKey && !ev.metaKey) return; // plain wheel scrolls; Ctrl/Cmd zooms
      ev.preventDefault();
      const delta = ev.deltaY < 0 ? 1.1 : 1 / 1.1;
      setZoom(zoom * delta);
    },
    { passive: false },
  );
  setZoom(1);

  // ─── render ───────────────────────────────────────────────────────────
  function render(state) {
    renderTree(state);
    renderWorkers(state);
  }

  function renderTree(state) {
    // Compute (row, x) for every node. Iterate in nodeId order — children
    // always have smaller ids than parents by construction of the scheduler.
    const layout = new Map();
    let maxX = 0;
    let maxRow = 0;
    for (const node of state.nodes) {
      let row, x;
      if (node.kind === NODE_KIND.LEAF) {
        row = 0;
        x = (node.index ?? 0) * COL_WIDTH + PADDING;
      } else {
        const left = layout.get(node.leftId);
        const right = layout.get(node.rightId);
        if (!left || !right) continue;
        row = Math.max(left.row, right.row) + 1;
        x = (left.x + right.x) / 2;
      }
      const y = -row * ROW_HEIGHT;
      layout.set(node.nodeId, { x, y, row });
      if (x + NODE_W > maxX) maxX = x + NODE_W;
      if (row > maxRow) maxRow = row;
    }

    const peakSet = new Set(state.peaks);

    const width = Math.max(maxX + PADDING, 320);
    const height = (maxRow + 1) * ROW_HEIGHT + 2 * PADDING;
    root.setAttribute("width", String(width));
    root.setAttribute("height", String(height));
    root.setAttribute(
      "viewBox",
      `${-PADDING} ${-(maxRow * ROW_HEIGHT) - PADDING} ${width + PADDING} ${height}`,
    );

    root.replaceChildren();

    // Pulse animation lives in a single <defs><style>.
    const defs = svg("defs");
    const style = svg("style");
    style.textContent = PULSE_STYLE_TEXT;
    defs.append(style);
    root.append(defs);

    // Edges (drawn before nodes so they render underneath).
    for (const node of state.nodes) {
      if (node.kind !== NODE_KIND.MERGE) continue;
      const here = layout.get(node.nodeId);
      const left = layout.get(node.leftId);
      const right = layout.get(node.rightId);
      if (!here || !left || !right) continue;
      drawEdge(here, left);
      drawEdge(here, right);
    }

    for (const node of state.nodes) {
      const pos = layout.get(node.nodeId);
      if (!pos) continue;
      drawNode(node, pos, peakSet.has(node.nodeId));
    }
  }

  function drawEdge(parent, child) {
    const x1 = parent.x;
    const y1 = parent.y + NODE_H / 2;
    const x2 = child.x;
    const y2 = child.y - NODE_H / 2;
    const ymid = (y1 + y2) / 2;
    const path = svg("path", {
      d: `M ${x1} ${y1} C ${x1} ${ymid}, ${x2} ${ymid}, ${x2} ${y2}`,
      class: "zkp-viz-edge",
      fill: "none",
      stroke: "#888",
      "stroke-width": "1.4",
    });
    root.append(path);
  }

  function drawNode(node, pos, isPeak) {
    const colors = STATE_COLOR[node.state] ?? STATE_COLOR[NODE_STATE.QUEUED];
    const g = svg("g", {
      transform: `translate(${pos.x - NODE_W / 2}, ${pos.y - NODE_H / 2})`,
    });

    const rectAttrs = {
      width: NODE_W,
      height: NODE_H,
      rx: 4,
      fill: colors.fill,
      stroke: isPeak ? "#0e51a8" : colors.stroke,
      "stroke-width": isPeak ? "2.5" : "1.2",
      "stroke-dasharray": node.state === NODE_STATE.QUEUED ? "3 3" : "0",
    };
    if (colors.pulse) rectAttrs.class = "zkp-pulse";
    g.append(svg("rect", rectAttrs));

    const text = svg("text", {
      x: NODE_W / 2,
      y: NODE_H / 2 + 4,
      "text-anchor": "middle",
      "font-size": "11",
      "font-family": "ui-monospace, monospace",
      fill: "#000",
      opacity: colors.textOpacity ?? 1,
    });
    text.textContent = formatNodeLabel(node);
    g.append(text);

    const title = svg("title");
    title.textContent = formatNodeTooltip(node, isPeak);
    g.append(title);

    root.append(g);
  }

  function formatNodeLabel(node) {
    if (node.lo != null && node.hi != null) {
      return node.lo === node.hi ? `${node.lo}` : `${node.lo}–${node.hi}`;
    }
    if (node.kind === NODE_KIND.LEAF && node.index != null) return `${node.index}?`;
    return "?";
  }
  function formatNodeTooltip(node, isPeak) {
    const lines = [
      `id: ${node.nodeId}`,
      `kind: ${node.kind}`,
      `state: ${node.state}${isPeak ? " (peak)" : ""}`,
    ];
    if (node.lo != null) lines.push(`range: [${node.lo}–${node.hi}] count=${node.count}`);
    if (node.proveMs != null) lines.push(`prove_ms: ${node.proveMs}`);
    if (node.proofSizeBytes != null)
      lines.push(`size: ${(node.proofSizeBytes / 1024).toFixed(1)} KB`);
    if (node.verifyMs != null) lines.push(`verify_ms: ${node.verifyMs}`);
    if (node.errorMessage) lines.push(`error: ${node.errorMessage}`);
    return lines.join("\n");
  }

  function renderWorkers(state) {
    workerPanel.replaceChildren();

    const heading = document.createElement("h3");
    heading.textContent = `Workers (${state.workersBusy}/${state.poolSize} busy)`;
    workerPanel.append(heading);

    const list = document.createElement("ul");
    list.className = "zkp-viz-worker-list";
    for (const w of state.workers) {
      const li = document.createElement("li");
      li.className = `zkp-viz-worker zkp-viz-worker-${w.busy ? "busy" : "idle"}`;
      const elapsed = w.elapsedMs != null ? `${(w.elapsedMs / 1000).toFixed(1)}s` : "—";
      li.textContent = w.busy
        ? `worker ${w.slot}: ${w.op ?? "?"} node ${w.nodeId} (${elapsed})`
        : `worker ${w.slot}: idle`;
      list.append(li);
    }
    workerPanel.append(list);

    const summary = document.createElement("div");
    summary.className = "zkp-viz-summary";
    summary.textContent = `queue=${state.queueLength}  inflight=${state.inflight}  peaks=${state.peaks.length}  next_leaf=${state.nextLeafIndex}`;
    workerPanel.append(summary);
  }

  // ─── attach to scheduler + repaint timer ──────────────────────────────
  let lastState = null;
  scheduler.subscribe((state) => {
    lastState = state;
    render(state);
  });

  // Re-render the worker panel on a slow timer so per-worker `elapsedMs`
  // ticks even when no scheduler events fire.
  const interval = setInterval(() => {
    if (lastState) renderWorkers(lastState);
  }, 250);

  return {
    setZoom,
    detach() {
      clearInterval(interval);
      container.replaceChildren();
    },
  };
}
