// Per-Action proving viz. Renders a list of action sub-trees: each
// action shows its leaf nodes (one row), the binary fold merges
// (subsequent rows), and a tooltip on each node with public-input +
// witness summary.
//
// Built as a DOM-only renderer (no SVG/canvas) so that the e2e test can
// scrape the structure with querySelector. Drives off the scheduler's
// snapshot subscription.

export function attachVisualization(container, scheduler) {
  container.classList.add("vault-viz-container");
  const inner = document.createElement("div");
  inner.className = "vault-viz-actions";
  inner.setAttribute("data-role", "viz-actions");
  container.replaceChildren(inner);

  scheduler.subscribe((state) => render(inner, state));
}

function render(host, state) {
  // Sort actions newest-first so freshly-submitted work is on top.
  const actions = state.actions.slice().sort((a, b) => b.actionId - a.actionId);
  const previous = new Map();
  for (const child of Array.from(host.children)) {
    previous.set(child.dataset.actionId, child);
  }
  host.replaceChildren();
  for (const action of actions) {
    const reused = previous.get(String(action.actionId));
    if (reused) {
      updateActionElement(reused, action);
      host.appendChild(reused);
    } else {
      host.appendChild(renderAction(action));
    }
  }
}

function renderAction(action) {
  const root = document.createElement("section");
  root.className = "vault-viz-action";
  root.dataset.actionId = String(action.actionId);
  root.dataset.flow = action.flow;
  root.setAttribute("data-role", "viz-action");
  updateActionElement(root, action);
  return root;
}

function updateActionElement(root, action) {
  root.dataset.state = action.state;
  const header = renderHeader(action);
  const tree = renderTree(action);
  root.replaceChildren(header, tree);
}

function renderHeader(action) {
  const header = document.createElement("div");
  header.className = "vault-viz-action-header";
  const flow = document.createElement("span");
  flow.className = "vault-viz-action-flow";
  flow.textContent = `#${action.actionId} · ${action.flow}`;
  const stateLbl = document.createElement("span");
  stateLbl.className = "vault-viz-action-state";
  stateLbl.dataset.role = "viz-action-state";
  stateLbl.textContent = action.state;
  header.appendChild(flow);
  header.appendChild(stateLbl);
  if (action.error) {
    const err = document.createElement("span");
    err.className = "vault-viz-action-state";
    err.style.color = "#ff8a7a";
    err.title = action.error;
    err.textContent = "✗ " + truncate(action.error, 80);
    header.appendChild(err);
  }
  return header;
}

function renderTree(action) {
  const tree = document.createElement("div");
  tree.className = "vault-viz-tree";

  // Row 1: leaves (sorted by leafIndex).
  const leaves = action.nodes.filter((n) => n.kind === "leaf");
  leaves.sort((a, b) => a.leafIndex - b.leafIndex);
  const leafRow = document.createElement("div");
  leafRow.className = "vault-viz-node-row";
  for (const node of leaves) leafRow.appendChild(renderNode(node));
  tree.appendChild(leafRow);

  // Subsequent rows: merge nodes, in submission order.
  const merges = action.nodes.filter((n) => n.kind === "merge");
  if (merges.length > 0) {
    const sep = document.createElement("div");
    sep.style.fontSize = "0.65rem";
    sep.style.opacity = "0.5";
    sep.textContent = "↓ fold ↓";
    tree.appendChild(sep);
    const mergeRow = document.createElement("div");
    mergeRow.className = "vault-viz-node-row";
    for (const node of merges) mergeRow.appendChild(renderNode(node));
    tree.appendChild(mergeRow);
  }
  return tree;
}

function renderNode(node) {
  const el = document.createElement("div");
  el.className = "vault-viz-node";
  el.dataset.role = "viz-node";
  el.dataset.air = node.air;
  el.dataset.state = node.state;
  el.dataset.leafIndex = node.leafIndex ?? "";
  el.dataset.nodeId = node.id;
  const label = document.createElement("div");
  label.textContent = node.air;
  el.appendChild(label);
  if (node.proofSizeBytes != null) {
    const detail = document.createElement("div");
    detail.className = "vault-viz-node-detail";
    detail.style.fontSize = "0.62rem";
    detail.style.opacity = "0.6";
    const ms =
      node.finishedAt && node.startedAt ? Math.round(node.finishedAt - node.startedAt) : null;
    detail.textContent =
      ms != null
        ? `${ms} ms · ${formatBytes(node.proofSizeBytes)}`
        : `${formatBytes(node.proofSizeBytes)}`;
    el.appendChild(detail);
  }
  el.title = nodeTooltip(node);
  return el;
}

function nodeTooltip(node) {
  const lines = [`id: ${node.id}`, `air: ${node.air}`, `state: ${node.state}`];
  if (node.leafIndex != null) lines.push(`leaf_index: ${node.leafIndex}`);
  if (node.digestHi != null) {
    lines.push(
      `digest: 0x${node.digestHi.toString(16).padStart(8, "0")}${node.digestLo.toString(16).padStart(8, "0")}`,
    );
  }
  if (node.proofSizeBytes != null) lines.push(`proof_size: ${node.proofSizeBytes} bytes`);
  if (node.publicInputs) {
    lines.push("public inputs:");
    lines.push(JSON.stringify(node.publicInputs, null, 2));
  }
  return lines.join("\n");
}

function formatBytes(n) {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1024 / 1024).toFixed(2)}MB`;
}

function truncate(s, max) {
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…";
}
