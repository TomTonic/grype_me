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

- 🔍 Uses the latest Grype version with a daily-updated vulnerability database (bundled in the action image)
- ⚡ **~2× faster** than installing Grype during a workflow run (no ~200 MB DB download)
- 📦 **Multiple scan targets**: repositories, container images, directories, or SBOMs
- 🎯 **Latest release scanning**: Ideal for nightly scans of your published releases
- 📊 Detailed vulnerability counts by severity (Critical, High, Medium, Low)
- 🚨 Fail builds on vulnerabilities at or above a configurable threshold
- 🔧 Option to show only vulnerabilities with available fixes
- 🏷️ **Dynamic badge generation**: Display vulnerability status in your README

## How It Works

This action runs inside a Docker container with Grype and a pre-downloaded vulnerability database. It supports two modes:

| Mode | Input | Description |
|------|-------|-------------|
| **Repository** | `scan` | Scans source code via dependency manifests (`go.mod`, `package.json`, `requirements.txt`, etc.) |
| **Artifact** | `image` / `path` / `sbom` | Scans container images, directories, or SBOM files |

### Repository mode

Grype reads dependency manifests directly from the repo—no build required. This works especially well for **Go projects**.

- ✅ Detects source-declared dependencies without compiling
- ✅ Great for nightly scans of tagged releases
- ❌ Runtime-only or dynamically downloaded dependencies require artifact mode

**Scan modes:**
- `latest_release` – Scans your highest stable semver tag (default)
- `head` – Scans the current working directory
- `<tag/branch>` – Scans a specific ref

### Artifact mode

Use `image`, `path`, or `sbom` to scan build artifacts. These inputs are mutually exclusive with `scan`.

## Usage

> 💡 Copy [`example-workflow.yml`](example-workflow.yml) to `.github/workflows/` for a ready-to-use setup.

### Nightly Release Scan

```yaml
name: Nightly Security Scan
on:
  schedule:
    - cron: '0 2 * * *'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0, fetch-tags: true }
      
      - uses: TomTonic/grype_me@v1
        with:
          scan: 'latest_release'
          fail-build: true
          severity-cutoff: 'high'
```

### Container Image Scan

```yaml
- name: Build image
  run: docker build -t myapp:${{ github.sha }} .

- uses: TomTonic/grype_me@v1
  with:
    image: 'myapp:${{ github.sha }}'
    fail-build: true
    severity-cutoff: 'high'
```

### Full Example with Outputs

```yaml
- name: Scan for vulnerabilities
  id: grype
  uses: TomTonic/grype_me@v1
  with:
    scan: 'latest_release'
    output-file: 'grype-results.json'
    fail-build: true
    severity-cutoff: 'medium'

- name: Show results
  run: |
    echo "Total CVEs: ${{ steps.grype.outputs.cve-count }}"
    echo "Critical: ${{ steps.grype.outputs.critical }}"

- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: grype-results
    path: grype-results.json
```

## Inputs

### Scan Target (mutually exclusive)

| Input | Description | Default |
|-------|-------------|---------|
| `scan` | Repository scan: `latest_release`, `head`, or a tag/branch | `latest_release` |
| `image` | Container image to scan (e.g., `alpine:latest`) | – |
| `path` | Directory or file to scan | – |
| `sbom` | SBOM file (Syft, CycloneDX, SPDX) | – |

### Options

| Input | Description | Default |
|-------|-------------|---------|
| `fail-build` | Fail if vulnerabilities ≥ `severity-cutoff` | `false` |
| `severity-cutoff` | Threshold: `negligible`, `low`, `medium`, `high`, `critical` | `medium` |
| `output-file` | Save results to JSON file | – |
| `only-fixed` | Only report vulnerabilities with fixes available | `false` |
| `db-update` | Update DB before scanning (see [Performance](#performance)) | `false` |
| `badge-label` | Label text for the generated badge | `vulnerabilities` |

<details>
<summary>Advanced inputs</summary>

| Input | Description | Default |
|-------|-------------|---------|
| `variable-prefix` | Prefix for environment variables | `GRYPE_` |
| `debug` | Print environment variables (may expose secrets) | `false` |

</details>

## Outputs

| Output | Description |
|--------|-------------|
| `cve-count` | Total vulnerabilities found |
| `critical` / `high` / `medium` / `low` | Count per severity |
| `grype-version` | Grype version used |
| `db-version` | Vulnerability database version |
| `json-output` | Path to output file (if `output-file` set) |
| `badge-url` | shields.io badge URL showing vulnerability summary |

The same values are also exported as environment variables with a configurable prefix (default: `GRYPE_CVE_COUNT`, `GRYPE_CRITICAL`, etc.).

## Performance

The action image is **rebuilt daily** with the latest Grype and vulnerability database. This eliminates the ~200 MB database download, making scans roughly **2× faster** than running Grype manually in a GitHub Actions workflow.

| Scenario | Recommendation |
|----------|----------------|
| Nightly scans | Use pre-baked DB (default) – fast and fresh enough |
| Security gates before release | Consider `db-update: true` for absolute freshness |

```yaml
- uses: TomTonic/grype_me@v1
  with:
    scan: 'latest_release'
    db-update: true  # Download latest DB before scanning
```

## Badge

The action generates a dynamic [shields.io](https://shields.io) badge URL that you can display in your README. The badge shows vulnerability counts and uses color-coding for quick visual assessment:

| Color | Meaning |
|-------|---------|
| ![brightgreen](https://img.shields.io/badge/vulnerabilities-none-brightgreen) | No vulnerabilities |
| ![yellowgreen](https://img.shields.io/badge/vulnerabilities-2%20low-yellowgreen) | Low severity only |
| ![yellow](https://img.shields.io/badge/vulnerabilities-3%20medium-yellow) | Medium severity |
| ![orange](https://img.shields.io/badge/vulnerabilities-1%20high-orange) | High severity |
| ![critical](https://img.shields.io/badge/vulnerabilities-2%20critical-critical) | Critical severity |

### Setting Up the Badge

1. **Create a workflow** that runs nightly and updates a gist with the badge URL:

```yaml
name: Security Badge
on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:

jobs:
  update-badge:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0, fetch-tags: true }

      - name: Run Grype scan
        id: grype
        uses: TomTonic/grype_me@v1
        with:
          scan: 'latest_release'
          badge-label: 'vulnerabilities'

      - name: Update Gist with badge data
        uses: schneegans/dynamic-badges-action@v1.7.0
        with:
          auth: ${{ secrets.GIST_TOKEN }}
          gistID: YOUR_GIST_ID
          filename: grype-badge.json
          label: vulnerabilities
          message: ${{ steps.grype.outputs.cve-count }} found
          valColorRange: ${{ steps.grype.outputs.cve-count }}
          maxColorRange: 10
          minColorRange: 0
```

2. **Alternative: Direct badge URL** - Use the `badge-url` output directly (best for dynamic scenarios):

```yaml
- name: Scan and display badge
  id: grype
  uses: TomTonic/grype_me@v1
  with:
    scan: 'latest_release'

- name: Show badge URL
  run: |
    echo "Add this to your README:"
    echo "![Vulnerabilities](${{ steps.grype.outputs.badge-url }})"
```

3. **In your README**, add the badge using the shields.io endpoint badge pointing to your gist:

```markdown
![Vulnerabilities](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/YOUR_USER/YOUR_GIST_ID/raw/grype-badge.json)
```

> 💡 **Why use a gist?** The direct badge URL changes with each scan result. By storing the badge data in a gist, your README always shows the latest scan result without needing to update the README itself. This approach has **no storage costs** for the user.

## Alerting Examples

### Create GitHub Issue

```yaml
- uses: TomTonic/grype_me@v1
  id: grype
  with: { scan: 'latest_release' }

- if: steps.grype.outputs.critical > 0
  uses: actions/github-script@v7
  with:
    script: |
      await github.rest.issues.create({
        owner: context.repo.owner,
        repo: context.repo.repo,
        title: '🚨 Critical vulnerabilities detected',
        body: `Found ${{ steps.grype.outputs.critical }} critical CVEs.\n\n[View run](${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId})`,
        labels: ['security', 'critical']
      });
```

### Slack Notification

```yaml
- uses: TomTonic/grype_me@v1
  id: grype
  with: { scan: 'latest_release' }

- if: steps.grype.outputs.cve-count > 0
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "🔒 Scan: ${{ steps.grype.outputs.critical }} critical, ${{ steps.grype.outputs.high }} high CVEs"
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

## License

BSD 3-Clause License – see [LICENSE](LICENSE).
