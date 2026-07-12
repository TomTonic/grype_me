# AI Agent Guidelines

## Project Overview

This is `grype_me`, a GitHub Action that scans repositories, container images,
directories, and SBOMs for known vulnerabilities using [Anchore
Grype](https://github.com/anchore/grype), and publishes shields.io badges and
Markdown reports (optionally via a GitHub Gist).

All source code is Go and lives in a single package, `cmd/grypeme` (built as
the `main` binary that runs inside the action's container). There is no
`pkg/` layer — the package is organized by responsibility instead:

- `main.go` — entry point and orchestration
- `types.go` — data structures (`GrypeOutput`, `Config`, `VulnerabilityStats`)
- `config.go` — configuration loading from `INPUT_*` environment variables
- `scanner.go` — Grype scan execution and result parsing
- `git.go` — Git operations (worktrees, tags, ref handling) via `go-git`
- `gist.go` — GitHub Gist API integration for badges/reports
- `output.go` — GitHub Actions outputs, file handling, badge/Markdown generation
- `privilege.go` — UID/GID drop handling for the scratch-based runtime image

The action runs inside a Docker container built from a `scratch` base image
(see `Dockerfile` and `SECURITY-HARDENING.md`) to minimize runtime attack
surface; it starts as root, pre-opens `GITHUB_OUTPUT`, and drops to UID/GID
`10001` before executing the scan.

## Build & Test Commands

```bash
go build ./...                                                          # Build
go test ./cmd/grypeme/...                                                # Run tests
go test ./cmd/grypeme/... -race                                          # Run tests with race detector
go test ./cmd/grypeme/... -coverprofile=coverage.txt -covermode=atomic   # Run tests with coverage
go tool cover -func=coverage.txt                                         # Display coverage summary
golangci-lint run --timeout=5m ./cmd/grypeme/...                         # Run linter
```

CI runs these same commands (see `.github/workflows/_ci-test.yml` and
`.github/workflows/_ci-lint.yml`); `golangci-lint` is invoked with
`working-directory: cmd/grypeme`. Docker image builds are covered by
`.github/workflows/_ci-docker.yml` and gated on lint+test passing.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Use `golangci-lint` with the project's lint configuration.
- Keep functions focused and under 60 lines where practical.
- Prefer returning errors over panicking.
- Use Go's standard error wrapping: `fmt.Errorf("context: %w", err)`.
- Do not use `panic()` in library code.

### Function and Method Documentation

Every exported function and method must have a godoc comment. Write it
like a good JavaDoc entry but with more emphasis on **context and usage
guidance** than a pure specification:

1. **First sentence**: A concise summary of what the function does,
   starting with the function name (Go convention).
2. **Parameters**: Document each parameter — its type, valid ranges,
   and what it controls.
3. **Return values**: What is returned on success and on error.
4. **Usage context**: When and why a caller would use this function.
   Mention typical call sites, related functions, or common patterns.
5. **Example** (optional but encouraged): A short inline example or
   reference to a testable example (`Example*` function).
6. Use **English** language.

Example (from `cmd/grypeme/scanner.go`):

```go
// determineScanTarget figures out what to scan based on the configuration inputs.
//
// config is the fully loaded action Config; exactly one of its scan-target
// fields (Scan, Image, Path, SBOM) must be set.
//
// Returns the Grype target string (e.g., "alpine:latest", "dir:/path",
// "sbom:file.json"), the path to a temporary worktree if one was created
// (empty otherwise — caller must clean it up), and an error if more than one
// or none of the scan-target inputs were provided.
//
// Called once from main.go after loadConfig, before invoking Grype. Repository
// scans of latest_release or a tag/branch route through git.go to create a
// temporary worktree; image/path/sbom scans return the target unchanged.
func determineScanTarget(config Config) (string, string, error) { ... }
```

Unexported helpers do not require full documentation, but a one-line
comment explaining *why* the helper exists is expected.

## Testing Requirements

- All new functionality must include tests.
- Use table-driven tests where appropriate.
- Maintain at least 80% test coverage.
- Run `go test ./cmd/grypeme/... -race` before submitting changes.
- Fuzz tests are welcome for functions that parse external input (see
  `fuzz_test.go` for ref-name and control-character validation).

### Test Documentation

Every test function must have a doc comment that reads **outside-in**.
Structure the comment in this order:

1. **User perspective**: What does the tested code achieve for the end user,
   described in the user's own terminology? Avoid implementation jargon.
2. **Context**: Which file or feature area does the tested code belong to?
   How does it fit into the larger action?
3. **Concrete expectation**: What specific behavior is this test verifying?

Example:

```go
// TestSetOutputsIncludesRuntimePrivilegeInfo verifies that users can see,
// from the action's step outputs, whether the scan ran with dropped
// privileges or fell back to root — so they can spot a misconfigured
// workspace mount without digging through logs.
//
// This test covers setOutputs in output.go, which writes GitHub Actions
// step outputs after a scan completes.
//
// It sets runtimePrivilegeMode/Detail, calls setOutputs, and asserts that
// runtime-privilege and runtime-privilege-detail are written to
// GITHUB_OUTPUT with the expected values.
func TestSetOutputsIncludesRuntimePrivilegeInfo(t *testing.T) { ... }
```

For table-driven tests, document the overall test function with the
outside-in structure and give each sub-test case a descriptive name
that reads as an assertion (e.g. `"returns error for empty input"`).

## Commit Messages

- Use imperative mood ("Add feature", not "Added feature").
- Limit subject line to 72 characters.
- Automated dependency updates from Renovate are prefixed `[auto]` and left
  as-is — don't rewrite them by hand.
- Separate subject from body with a blank line.

## Dependencies

- Minimize external dependencies.
- All dependencies are managed via Renovate (`.github/renovate.json`, which
  extends `github>TomTonic/go-project-defaults`).
- Run `go mod tidy` after adding or removing dependencies.
- Do not add dependencies with known vulnerabilities.

## Security

- Never commit secrets, credentials, or API keys (`gist-token` and similar
  inputs must always come from GitHub Actions secrets, never be logged).
- The `gosec` linter is enabled — do not disable it.
- Validate all external input at system boundaries (action inputs, Git refs,
  Grype/Gist API responses).
- Use `crypto/rand` for security-sensitive randomness, not `math/rand`.
- Read `SECURITY-HARDENING.md` before changing the Dockerfile, privilege-drop
  logic (`privilege.go`), or Git handling (`git.go`) — these implement
  deliberate hardening decisions (scratch base image, `go-git` instead of the
  `git` CLI, UID/GID drop before scan execution) that are easy to
  accidentally regress.

## CI/CD

- All pushes and PRs are checked by: golangci-lint, yamllint, `go vet`
  (via `go test`), `go test -race`, CodeQL, and a Docker build
  (`.github/workflows/ci.yml`).
- Coverage is uploaded to Codecov from the test workflow.
- Dependency updates are automated via Renovate with automerge configured in
  `go-project-defaults`.
- This repository scans itself daily for vulnerabilities using its own
  action (`.github/workflows/security-badge.yml`), producing the badges
  shown in `README.md`.
- The published Docker image and action tags (`latest`, `v1`, `v1.2`,
  `v1.2.3`) are rebuilt/moved daily to track the newest Grype release and
  vulnerability DB — only `-release` and `_grype-..._db-...` tags are
  immutable. Keep this in mind when changing tagging logic or
  `move-action-tags.yml`.

## File Organization

- Keep `cmd/grypeme` flat; it is a single `main` package by design (this is
  a small, single-binary action, not a library with reusable sub-packages).
- Test files live next to the code they test (`foo_test.go` next to `foo.go`).
- `action.yml` is the action's public interface (inputs/outputs) — keep it in
  sync with `config.go` and `output.go` whenever inputs or outputs change, and
  update `README.md`'s Inputs/Outputs tables in the same change.

## Release Notes

Release notes are based on the last published GitHub release. Describe what
actually changed and why it matters — not a log replay. Omit sections with
nothing to report; never add placeholder text.

### New Features
User-visible capabilities that did not exist in the previous release. Describe
each feature from the user's perspective: what they can do now that they
couldn't before, and when they would use it. Avoid internal implementation
detail unless it directly affects usage.

### Changed Behavior
Existing functionality that works differently after the upgrade. Call out
anything that could require users to update their workflow YAML, action
inputs/outputs, or expectations (e.g. badge URL format, gist file naming). If
a change is breaking, flag it explicitly.

### Architectural Changes
Significant restructuring of the codebase that affects how components interact,
how the project is organized, or how it is extended. Include here only changes
that a contributor or integrator would notice. Pure internal refactors with no
external impact may be omitted.

### Source Code Updates
Language/runtime dependency updates, including Go toolchain bumps and base
image changes (a new compiler or base image may change runtime behavior or
safety guarantees). Highlight security-relevant updates (CVE fixes, patched
vulnerabilities) explicitly, even if transitive.

### CI Updates
CI pipeline changes: linter upgrades, new analysis rules, runner image updates,
build matrix or workflow restructuring. Flag linter changes that now reject
previously accepted patterns.

### Writing Guidelines

- Plain English; assume domain knowledge, not day-to-day development context.
- Concrete names (input, output, flag, or file) — not "various improvements".
- Cross-mention items that span sections (e.g. a CVE fix in Source Code Updates and Security).
- One–two sentences per bullet; link to the relevant issue/PR when available.
- Synthesize commits; do not restate them verbatim.
