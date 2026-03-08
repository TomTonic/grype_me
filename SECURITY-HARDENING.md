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
- TLS trust store is copied into the final image (`/etc/ssl/certs/ca-certificates.crt`).  CA certificates come from the Alpine `ca-certificates` package (Mozilla CA bundle) and are refreshed on every daily image rebuild.
- `SSL_CERT_FILE` is set so HTTPS clients can validate certificates reliably.
- Writable runtime directories are pre-created under `/app` and owned by UID/GID `10001`.  The directory is named `/app` (not `/home/…`) because no OS user exists in a scratch image.
- Directories must be created in a build stage (builder or installer) because scratch provides no shell or `mkdir`.
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
  - attempt drop to non-privileged UID/GID before scan execution
  - verify privilege drop succeeded
- This keeps workflow usage simple while preserving security boundaries better than host-user execution.

### 3.1 Privilege Drop Modes (Current Behavior)

The action now exposes explicit runtime privilege state via outputs:

- `runtime-privilege`: `already-non-root` | `dropped` | `root-fallback`
- `runtime-privilege-detail`: diagnostic reason (only set on fallback / strict failures)

#### When privilege drop may be impossible

Privilege drop can fail when `GITHUB_OUTPUT` (a host-mounted file under
`/github/file_commands/…`) cannot be opened before the process gives up root.
A non-root process that has no pre-opened handle to this file cannot write
step outputs reliably.

To avoid mutating runner-owned file-command mounts (which broke runner
post-steps in earlier iterations), the action **pre-opens `GITHUB_OUTPUT`
as root** before dropping privileges and reuses the inherited file descriptor
afterwards.  This is standard Unix behavior: an open file descriptor remains
valid after `setuid`/`setgid`, regardless of file ownership.

#### Runtime decisions

- Default (`strict-privilege-drop: false`):
  - If `GITHUB_OUTPUT` can be pre-opened, the action drops to UID/GID `10001`.
  - If the pre-open fails, the action logs warnings and uses `root-fallback` to preserve workflow reliability.
- Strict mode (`strict-privilege-drop: true`):
  - The action fails fast instead of falling back to root.

#### How users detect this

- Logs contain explicit warnings:
  - `Could not pre-open GITHUB_OUTPUT for post-drop writes`
  - `Continuing as root to preserve GitHub Actions outputs`
- Action outputs include:
  - `runtime-privilege=root-fallback`
  - `runtime-privilege-detail=…`

#### What users can do

- If reliability is most important:
  - keep default `strict-privilege-drop: false`
  - monitor `runtime-privilege` output and logs for fallback events
- If strict non-root is mandatory:
  - set `strict-privilege-drop: true`
  - treat failures as policy violations and adjust runner/container setup
- Runner-level mitigation options:
  - use a runner environment where `GITHUB_OUTPUT` is openable by root in-container
  - avoid custom runtime/mount hardening that blocks access to GitHub file-command mounts

## Security Properties
- No shell available in runtime image.
- No package manager available in runtime image.
- No external `git` binary required in runtime image.
- Non-root execution for scan logic by default when `GITHUB_OUTPUT` can be pre-opened before dropping privileges.
- Explicit root fallback path (warning + diagnostics) when the pre-open fails and strict mode is disabled.
- Workspace write path handled explicitly for predictable artifact creation.
- HTTPS trust is explicitly configured for DB/API/registry/Git operations.
