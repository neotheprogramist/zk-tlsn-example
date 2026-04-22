# GUIDELINES.md

Engineering standards for this repository.

This file is authoritative for active development. If another doc conflicts with this file, follow `GUIDELINES.md`.

---

## Core Rules

### 1) One Happy Path, Fail Fast

- Implement one clear happy path per operation.
- Remove unnecessary alternate code paths, legacy compatibility branches, and silent fallbacks.
- Fail early with descriptive errors at the point of failure.

### 2) Declarative and Monadic

- Prefer linear, composable flow over deeply nested imperative branching.
- Use monadic composition (map, flatMap, bind, and_then) to chain operations on wrapped values — errors, optionals, futures, collections.
- Keep functions small, deterministic where possible, and named by outcome.
- Use pure helpers for transformation and validation; isolate effects at boundaries.

### 3) Monadic Error Propagation

- Errors are values, not exceptions. Model fallible operations as monadic types (Result, Option, Either) and compose them through bind/flatMap/and_then.
- Every failure must be handled or propagated — never silently ignored.
- Convert unknown failures into the project's error model at system boundaries with operation context.
- Define a single error type per boundary with automatic conversion from source errors. Source errors are wrapped transparently — the type system performs conversion during monadic composition, not the programmer at each call site.

### 4) Exhaustive Modeling

- Use closed type hierarchies for finite domain, state, and error sets.
- Use exhaustive handling for closed sets — the compiler must enforce that every variant is addressed.
- If a state can be represented, it must be valid. If it shouldn't exist, make it unrepresentable.

### 5) Ownership and Lifecycle

- Every resource has exactly one owner responsible for its lifecycle.
- Shared access is explicit — prefer borrowing over cloning, references over copies.
- Cleanup is structural, not ad-hoc. Resources are released when their owner goes out of scope.
- Long-lived resources are owned by long-lived scopes. Short-lived consumers borrow, never own.

### 6) Valid By Construction

- Runtime objects must be representable only in valid states.
- Required fields are non-optional and enforced at construction.
- Incomplete input exists only in explicitly typed intermediate states (builders, drafts, forms) — never in persisted or runtime models.
- Convert intermediate input into runtime models at boundaries with validation errors.

---

## Derived Principles

### No Hidden Traps

- Do not assert invariants the compiler cannot verify without documenting the proof.
- Panics in request-handling or concurrent code are bugs — propagate errors instead.
- Panics at startup for provably infallible setup are acceptable with a proof message.
- Infallible operations verified by the compiler (e.g., compile-time template checking) may use forceful unwrapping with a descriptive message.

### Immutability and Canonical State

- Prefer immutable data. Mutation is explicit and scoped.
- Persist only irreducible source data.
- Derive secondary/computed values on read — do not store them redundantly.

### Boundaries Own Conversion

- External input enters the system as untyped/untrusted data.
- Validation and conversion happen once, at the boundary, producing typed domain objects.
- Code inside the boundary operates on validated types only — no re-validation deeper in the stack.

### Prefer Type Inference

- Function arguments should be typed.
- Return types should be inferred from typed arguments and the function's internal transformations.
- Add explicit non-argument type annotations only when inference is insufficient, ambiguous, or needed to enforce an important boundary.
- Do not duplicate types that the compiler or checker can already derive from inputs, local values, and implementation.

### Composition Over Abstraction

- Three similar lines are better than a premature abstraction.
- Introduce abstractions only when a pattern is stable and repeated.
- Flat composition of small functions over deep inheritance or trait hierarchies.

### Self-Descriptive Code Over Comments

- Default to no comments.
- Express intent through meaningful names, precise types, and small focused functions.
- Comment only the WHY when it is non-obvious. Never comment the WHAT — that is already in the code.

---

## Anti-Patterns

| Forbidden                                             | Required                                         |
| ----------------------------------------------------- | ------------------------------------------------ |
| Silent defaulting on invalid config/state             | Return an error                                  |
| Catch-and-ignore on critical flow                     | Propagate with context                           |
| Multiple fallback branches for same action            | One happy path + fail-fast                       |
| Asserting invariants without compiler proof           | Typed validation or `// PROOF:` comment          |
| Shared mutable state without explicit synchronization | Owned state or explicit shared-access primitives |
| Cleanup via manual discipline                         | Structural cleanup tied to scope/ownership       |

---

## Enforcement Scope

- Enforce on runtime production code only.
- Test code, fixtures, build scripts, and generated artifacts are exempt unless explicitly stated.

---

## Security

- Sanitize and validate all external input at system boundaries.
- Use parameterized queries — never interpolate untrusted data into query strings.
- Never render untrusted content via raw/unescaped output.
- Template auto-escaping must not be bypassed without documented justification.

---

## Testing

### Test Double Hierarchy

Prefer real implementations over test doubles:

1. **Real implementation** — default. Use actual production code with in-process dependencies.
2. **Fake** — in-memory implementation with real behavior when the real dependency requires external I/O.
3. **Mock** — stub-based double. Only when crossing a system boundary that cannot run in tests.

Do not mock what you can fake. Do not fake what you can use directly.

### Principles

- Test through the public interface, not internal implementation details.
- Test code is exempt from strict error handling rules.
- Prefer integration tests that exercise real code paths over unit tests of isolated fragments.
