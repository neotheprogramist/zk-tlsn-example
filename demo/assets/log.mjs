// Single source of truth for browser-side event emission.
//
// Output grammar (matches Rust `tracing-subscriber` `compact()`):
//
//   {rfc3339-ts}  {LEVEL} {event_name} key=value key=value ...
//
// `event_name` is dot-namespaced (e.g. `zkp.prove.base.done`).
// Field values are bare for `[A-Za-z0-9_.\-]+`, JSON-stringified otherwise.

function fmtField(v) {
  if (typeof v === "boolean" || typeof v === "number" || v === null || v === undefined) {
    return String(v);
  }
  if (typeof v === "string" && /^[A-Za-z0-9_.-]+$/.test(v)) return v;
  return JSON.stringify(v);
}

function emit(level, name, fields) {
  const ts = new Date().toISOString();
  let line = `${ts}  ${level} ${name}`;
  for (const [k, v] of Object.entries(fields ?? {})) {
    line += ` ${k}=${fmtField(v)}`;
  }
  (level === "ERROR" ? console.error : console.log)(line);
}

export const event = (name, fields) => emit("INFO", name, fields);
export const eventWarn = (name, fields) => emit("WARN", name, fields);
export const eventErr = (name, fields) => emit("ERROR", name, fields);
