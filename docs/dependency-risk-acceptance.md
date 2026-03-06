# Dependency Risk Acceptance

## RUSTSEC-2023-0071 (`rsa` via `sqlx-mysql`)

- Status: accepted until upstream SQLx removes the dormant MySQL macro dependency chain or publishes a fixed path.
- Scope in this repository: the production code only opens SQLite pools and runs SQLite migrations. There is no MySQL configuration, driver initialization, or runtime code path in the application.
- Why it still appears in `cargo audit`: `sqlx` 0.8.6 keeps `sqlx-macros-core` in the resolved graph, and that crate still pulls `sqlx-mysql` into `Cargo.lock` even when the repository disables MySQL features and uses SQLite-only runtime code.
- Runtime exposure: none in the compiled application path reviewed here; the vulnerable crate is not used for key handling or any request path served by the binary.
- Required follow-up:
  - re-check on each SQLx release;
  - remove the ignore once SQLx eliminates the dormant MySQL dependency or ships a fixed advisory path;
  - keep CI running `cargo audit` so new advisories still fail the build.

## RUSTSEC-2024-0388 (`derivative`)

- Status: accepted as a transitive warning.
- Scope in this repository: pulled transitively through `alloy`/`ruint`; there is no direct dependency on `derivative`.
- Runtime exposure: low. The warning is about maintenance status, not a known memory-safety or remote-execution flaw in the exercised Linux binary path.
- Required follow-up:
  - re-check on each `alloy`/`ruint` update;
  - remove the acceptance once upstream drops `derivative` or replaces it.

## RUSTSEC-2024-0436 (`paste`)

- Status: accepted as a transitive warning.
- Scope in this repository: pulled through `alloy-sol-types` macro dependencies; the crate is only used at compile time for generated bindings/macros.
- Runtime exposure: none in the shipped binary path reviewed here.
- Required follow-up:
  - re-check on each `alloy-sol-types` update;
  - remove the acceptance once upstream removes or replaces `paste`.

## Yanked `js-sys` / `wasm-bindgen`

- Status: accepted as transitive warnings.
- Scope in this repository: they are brought in by cross-platform HTTP / websocket dependencies that retain optional WASM support in `Cargo.lock`.
- Runtime exposure: none for the production Linux target reviewed here; the searcher does not ship a browser/WASM build.
- Required follow-up:
  - re-check on each `reqwest` / `alloy` dependency refresh;
  - drop the acceptance once the graph resolves to non-yanked releases.
