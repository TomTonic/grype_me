# Security Hardening Summary

## Goal
Deliver a supply-chain security action that remains easy to use while not introducing additional risk into user repositories.

## Previous Issues
- The runtime image contained avoidable vulnerabilities from general-purpose OS packages.
- Integration tests hit permission errors when writing scan artifacts to the mounted GitHub workspace.
- A temporary `docker run --user $(id -u):$(id -g)` workaround reduced isolation and was not acceptable for a security-focused action.

## Implemented Direction

### 1. Reduce Runtime Attack Surface
- Runtime image moved to `scratch` to remove shell, package manager, and unnecessary OS userland from production execution.
- Build and installer tooling remain in build stages only.
- The runtime image only contains what the action needs to execute.

### 1.1 Scratch Runtime Requirements (Handled Explicitly)
- TLS trust store is copied into the final image (`/etc/ssl/certs/ca-certificates.crt`).
- `SSL_CERT_FILE` is set so HTTPS clients can validate certificates reliably.
- Writable runtime directories are pre-created and owned by UID/GID `10001`.
- `GRYPE_DB_CACHE_DIR` and `TMPDIR` are set for deterministic cache/tmp behavior.

These controls are necessary for scratch images; without them, registry access, DB updates, or HTTPS Git remotes can fail.

### 2. Replace External Git CLI Dependency
- Git operations now use `go-git` instead of invoking the `git` binary.
- This removes a large runtime dependency tree and keeps behavior inside audited Go code.
- Supported operations:
  - fetch tags
  - list and sort tags
  - resolve refs
  - create temporary scan checkout and cleanup

### 3. Keep Usability Without Host-User Execution
- The local container-run helper no longer forces host UID/GID via Docker `--user`.
- Privilege handling is done inside the action binary:
  - if running as root, prepare workspace ownership safely
  - drop to non-privileged UID/GID before scan execution
  - verify privilege drop succeeded
- This keeps workflow usage simple while preserving security boundaries better than host-user execution.

## Security Properties
- No shell available in runtime image.
- No package manager available in runtime image.
- No external `git` binary required in runtime image.
- Non-root execution for scan logic enforced by runtime privilege drop.
- Workspace write path handled explicitly for predictable artifact creation.
- HTTPS trust is explicitly configured for DB/API/registry/Git operations.
