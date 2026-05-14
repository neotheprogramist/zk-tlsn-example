// Inline form validation messages: render error near the offending input,
// not only in the log panel.
//
// Usage:
//   setFieldError(input, "choose a USDC resource for the fee");
//   setFieldError(input, null);  // clear
//   clearFieldErrors(formRoot);  // clear every .field-error under a root

const ERR_REGISTRY = new WeakMap();

function ensureSlot(input) {
  const existing = ERR_REGISTRY.get(input);
  if (existing && existing.isConnected) return existing;
  const slot = document.createElement("span");
  slot.className = "field-error";
  slot.setAttribute("aria-live", "polite");
  const anchor = input.closest(".field, .field-row, label") ?? input.parentElement;
  if (anchor) anchor.append(slot);
  ERR_REGISTRY.set(input, slot);
  return slot;
}

export function setFieldError(input, message) {
  if (!input) return;
  const slot = ensureSlot(input);
  if (message) {
    slot.textContent = message;
    input.setAttribute("aria-invalid", "true");
  } else {
    slot.textContent = "";
    input.removeAttribute("aria-invalid");
  }
}

export function clearFieldErrors(root) {
  if (!root) return;
  for (const slot of root.querySelectorAll(".field-error")) {
    slot.textContent = "";
  }
  for (const inv of root.querySelectorAll("[aria-invalid='true']")) {
    inv.removeAttribute("aria-invalid");
  }
}
