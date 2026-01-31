# grype_me

A lean GitHub Action to scan for vulnerabilities using [Anchore Grype](https://github.com/anchore/grype).

## Quick Start

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0, fetch-tags: true }
- uses: TomTonic/grype_me@v1
  with: { scan: 'latest_release', fail-build: true, severity-cutoff: 'high' }
```

> **Note**: The default scan mode is `latest_release`, which scans your highest semver tag. If your repo has no tags yet, use `scan: 'head'` instead.

## Features

- 🔍 Scans for vulnerabilities using the latest version of Grype
- 📦 **Multiple scan modes**: repositories, container images, directories, or SBOMs
- 🎯 **Latest release scanning**: Perfect for nightly scans of your published releases
- 📊 Provides detailed vulnerability counts by severity (Critical, High, Medium, Low)
- 🚨 **Fail build** on vulnerabilities at or above a severity threshold
- 🔧 Filter to show only vulnerabilities with available fixes
- 📁 Outputs results as JSON file (optional)
- 🚀 Uses Go for fast execution
- ⏰ Supports scheduled scans (e.g., nightly security checks)

## How It Works

This action runs inside a Docker container with Grype pre-installed. It supports multiple scan modes:

1. **Repository mode** (`scan` input): Scan your repository's source code
   - `latest_release`: Checkout the highest semver tag and scan it (great for nightly scans)
   - `head`: Scan the current working directory as-is
   - `<tag/branch>`: Checkout a specific tag or branch and scan it

2. **Artifact mode** (mutually exclusive inputs): Scan pre-built artifacts
   - `image`: Scan a container image (e.g., `alpine:latest`, `myregistry/app:v1.0`)
   - `path`: Scan a directory or file path
   - `sbom`: Scan a Software Bill of Materials file

### Repository mode: source-level scanning (best for Go)

Repository mode is designed for **source-level** dependency scanning and works especially well for Go projects.
Grype (via Syft) reads dependency manifests directly from the repo and builds an SBOM without compiling.

How it works:
1. Inspects the repository for supported dependency manifests (e.g., `go.mod`, `go.sum`, `package.json`, `requirements.txt`)
2. Generates a dependency inventory (SBOM) from those files
3. Matches detected packages against vulnerability databases

What this means:
- ✅ Source-declared dependencies are covered without a build
- ✅ Great for Go module repos and nightly scans of tagged releases
- ❌ Runtime-only or dynamically downloaded dependencies are **not** included unless you scan a build artifact

When to use repository mode:
- Go module repos that publish releases (use `scan: latest_release` for nightly scans)
- PR/CI checks that only need source-level coverage (use `scan: head`)
- Projects with clear manifest files and no required build steps for dependency discovery

When to use artifact mode instead:
- You need to scan compiled binaries, Docker images, or packaged distributions
- Dependencies are produced during build time (e.g., vendor directories, bundled assets)
- You need to **store** according binaries, Docker images, or packaged distributions for later/nightly scans

## Usage

> **Quick Start**: Copy [`example-workflow.yml`](example-workflow.yml) to `.github/workflows/` in your repository for a ready-to-use vulnerability scanning setup.

### Repository Scanning (Default)

Scan your repository's latest release (ideal for nightly vulnerability checks):

```yaml
name: Nightly Security Scan
on:
  schedule:
    - cron: '0 2 * * *'  # Every day at 2am

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          fetch-tags: true
      
      - name: Scan latest release for vulnerabilities
        uses: TomTonic/grype_me@v1
        with:
          scan: 'latest_release'  # Scans highest semver tag
          fail-build: true
          severity-cutoff: 'high'
```

Scan the current checkout (for CI on PRs):

```yaml
name: PR Security Check
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Scan for vulnerabilities
        uses: TomTonic/grype_me@v1
        with:
          scan: 'head'  # Scans current working directory
          fail-build: true
          severity-cutoff: 'critical'
```

### Container Image Scanning

Scan a container image after building it:

```yaml
name: Build and Scan
on: [push]

jobs:
  build-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Scan image for vulnerabilities
        uses: TomTonic/grype_me@v1
        with:
          image: 'myapp:${{ github.sha }}'
          fail-build: true
          severity-cutoff: 'high'
```

### SBOM Scanning

Scan an existing Software Bill of Materials:

```yaml
- name: Scan SBOM for vulnerabilities
  uses: TomTonic/grype_me@v1
  with:
    sbom: 'sbom.json'
    only-fixed: true  # Only show vulnerabilities with fixes available
```

### Full Example with All Options

```yaml
name: Security Scan with Options
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          fetch-tags: true
      
      - name: Run Grype vulnerability scanner
        id: grype-scan
        uses: TomTonic/grype_me@v1
        with:
          scan: 'latest_release'
          output-file: 'grype-results.json'
          fail-build: true
          severity-cutoff: 'medium'
          only-fixed: false
          variable-prefix: 'SCAN_'
      
      - name: Display scan results
        run: |
          echo "Grype Version: ${{ steps.grype-scan.outputs.grype-version }}"
          echo "Database Version: ${{ steps.grype-scan.outputs.db-version }}"
          echo "Total CVEs: ${{ steps.grype-scan.outputs.cve-count }}"
          echo "Critical: ${{ steps.grype-scan.outputs.critical }}"
          echo "High: ${{ steps.grype-scan.outputs.high }}"
          echo "Medium: ${{ steps.grype-scan.outputs.medium }}"
          echo "Low: ${{ steps.grype-scan.outputs.low }}"
      
      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: grype-scan-results
          path: grype-results.json
```

## Inputs

### Scan Mode Inputs

You can use **either** the `scan` input **or** one of `image`/`path`/`sbom` - they are mutually exclusive.

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan` | Repository scan mode: `latest_release` (highest stable semver tag), `head` (current directory), or a specific tag/branch name. | No | `latest_release` |
| `image` | Container image to scan (e.g., `alpine:latest`, `myregistry/app:v1.0`). Cannot be used with `scan`, `path`, or `sbom`. | No | |
| `path` | Directory or file path to scan. Cannot be used with `scan`, `image`, or `sbom`. | No | |
| `sbom` | SBOM file to scan (supports Syft, CycloneDX, SPDX formats). Cannot be used with `scan`, `image`, or `path`. | No | |

### Configuration Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `fail-build` | Fail the workflow if vulnerabilities are found at or above `severity-cutoff` | No | `false` |
| `severity-cutoff` | Minimum severity to trigger build failure: `negligible`, `low`, `medium`, `high`, `critical` | No | `medium` |
| `output-file` | Path to save scan results (JSON) | No | (no file saved) |
| `only-fixed` | Only report vulnerabilities with a fix available | No | `false` |
| `variable-prefix` | Prefix for environment variable names | No | `GRYPE_` |
| `debug` | Print INPUT_/GITHUB_ environment variables (warning: may expose sensitive data) | No | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `grype-version` | Version of Grype used for scanning |
| `db-version` | Version of the Grype vulnerability database |
| `cve-count` | Total number of CVEs found |
| `critical` | Number of critical severity vulnerabilities |
| `high` | Number of high severity vulnerabilities |
| `medium` | Number of medium severity vulnerabilities |
| `low` | Number of low severity vulnerabilities |
| `json-output` | Path to the output file (if `output-file` was specified) |

## Environment Variables

In addition to the outputs, the action sets environment variables with a configurable prefix (default: `GRYPE_`):

- `{prefix}VERSION` - Grype version
- `{prefix}DB_VERSION` - Database version  
- `{prefix}CVE_COUNT` - Total CVE count
- `{prefix}CRITICAL` - Critical severity count
- `{prefix}HIGH` - High severity count
- `{prefix}MEDIUM` - Medium severity count
- `{prefix}LOW` - Low severity count

## Important Notes

### For `latest_release` mode

- Requires at least one semver tag in the repository (e.g., `v1.0.0`)
- Pre-release tags (e.g., `v1.0.0-beta`) are automatically skipped
- Use `fetch-depth: 0` and `fetch-tags: true` in checkout to ensure tags are available
- If no tags exist, use `scan: 'head'` instead

### For `image` mode

- The image must be locally available or pullable
- Works with any registry (Docker Hub, GHCR, ECR, etc.)
- Build your image before scanning in the workflow

## Alerting Examples

### Create GitHub Issue on Critical CVEs

```yaml
- name: Scan for vulnerabilities
  id: grype
  uses: TomTonic/grype_me@v1
  with:
    scan: 'latest_release'

- name: Create issue on critical vulnerabilities
  if: steps.grype.outputs.critical > 0
  uses: actions/github-script@v7
  with:
    script: |
      await github.rest.issues.create({
        owner: context.repo.owner,
        repo: context.repo.repo,
        title: '🚨 Critical vulnerabilities detected',
        body: `Found ${{ steps.grype.outputs.critical }} critical CVEs in latest release.\n\nSee workflow run: ${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`,
        labels: ['security', 'critical']
      });
```

### Slack Notification

```yaml
- name: Scan for vulnerabilities
  id: grype
  uses: TomTonic/grype_me@v1
  with:
    scan: 'latest_release'

- name: Notify Slack on vulnerabilities
  if: steps.grype.outputs.cve-count > 0
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "🔒 Vulnerability scan: ${{ steps.grype.outputs.critical }} critical, ${{ steps.grype.outputs.high }} high, ${{ steps.grype.outputs.medium }} medium CVEs"
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.
