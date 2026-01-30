# grype_me

A lean GitHub Action to scan your repository for vulnerabilities using [Anchore Grype](https://github.com/anchore/grype).

## Features

- 🔍 Scans your repository for vulnerabilities using the latest version of Grype
- 📊 Provides detailed vulnerability counts by severity (Critical, High, Medium, Low)
- 🎯 Outputs results as JSON file (optional)
- 🔧 Configurable environment variable prefix
- 🚀 Uses Go for fast execution
- 📦 Containerized for consistent execution

## Usage

> **Quick Start**: Copy [`example-workflow.yml`](example-workflow.yml) to `.github/workflows/` in your repository for a ready-to-use vulnerability scanning setup.

### Basic Usage

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Grype vulnerability scanner
        uses: TomTonic/grype_me@v1
```

### Advanced Usage

```yaml
name: Security Scan with Options
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Grype vulnerability scanner
        id: grype-scan
        uses: TomTonic/grype_me@v1
        with:
          repository: '.'
          branch: 'main'
          output-file: 'grype-results.json'
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

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `repository` | Repository path to scan (currently only supports "." for current repository) | No | `.` (current repository) |
| `branch` | Branch to checkout before scanning (only works when repository is ".") | No | Current branch |
| `output-file` | Path to save JSON scan results | No | `` (no file saved) |
| `variable-prefix` | Prefix for environment variable names | No | `GRYPE_` |
| `debug` | Print INPUT_/GITHUB_ environment variables when `true` (warning: may expose sensitive data in logs) | No | `false` |

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
| `json-output` | Path to the JSON output file (if `output-file` was specified) |

## Environment Variables

In addition to the outputs, the action sets environment variables with a configurable prefix (default: `GRYPE_`):

- `{prefix}VERSION` - Grype version
- `{prefix}DB_VERSION` - Database version  
- `{prefix}CVE_COUNT` - Total CVE count
- `{prefix}CRITICAL` - Critical severity count
- `{prefix}HIGH` - High severity count
- `{prefix}MEDIUM` - Medium severity count
- `{prefix}LOW` - Low severity count

## Example: Fail Build on Critical Vulnerabilities

```yaml
- name: Run Grype vulnerability scanner
  id: grype-scan
  uses: TomTonic/grype_me@v1

- name: Check for critical vulnerabilities
  run: |
    if [ "${{ steps.grype-scan.outputs.critical }}" -gt "0" ]; then
      echo "Found ${{ steps.grype-scan.outputs.critical }} critical vulnerabilities!"
      exit 1
    fi
```

## Development

### Code Review: Simplicity & Robustness

The codebase is intentionally small and direct, centered around a single Go entry point that orchestrates scanning, parsing, statistics, and output handling. Simplicity is preserved by limiting configuration to a few inputs, using standard library utilities for sorting, JSON parsing, and filesystem operations, and keeping the data model tightly scoped to Grype's output schema.

Robustness is addressed through explicit error handling at each step, graceful handling of Grype's non-zero exit codes when vulnerabilities are found, and defensive file operations. The output-file copy path enforces workspace-based path traversal protection, and tests cover JSON parsing, severity aggregation, and file handling edge cases. The CI workflows add additional safety by running linting, unit tests, integration tests, and an end-to-end action run.

### CI/CD Workflows

This repository includes comprehensive CI/CD workflows to ensure code quality:

#### CI Workflow (`.github/workflows/ci.yml`)

Runs on every push and pull request:

- **Lint**: Checks code formatting with `go fmt`, `go vet`, `staticcheck`, and `yamllint`
- **Test**: Runs all unit and integration tests with coverage reporting
  - Installs grype and updates the vulnerability database
  - Runs tests with race detection enabled
  - Generates coverage reports
- **Build**: Verifies the Go application builds successfully
- **Docker Build**: Validates the Docker image can be built
- **Integration Test**: Runs the action against itself to verify end-to-end functionality

#### End-to-End Test Workflow (`.github/workflows/test.yml`)

Tests the actual GitHub Action in a real workflow environment.

### Running Tests Locally

```bash
# Install dependencies
go mod download

# Run all tests
go test -v ./...

# Run tests with coverage
go test -v -coverprofile=coverage.txt ./...
go tool cover -html=coverage.txt

# Run only unit tests (skip e2e tests requiring grype)
go test -v -short ./...

# Install grype for e2e tests
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
grype db update

# Run all tests including e2e
go test -v ./...
```

### Linting

```bash
# Format code
go fmt ./...

# Run go vet
go vet ./...

# Install and run staticcheck
go install honnef.co/go/tools/cmd/staticcheck@latest
staticcheck ./...

# Lint YAML files
pip install yamllint
yamllint -c .yamllint .github/workflows/ action.yml example-workflow.yml
```

## License

This project is licensed under the BSD 3-Clause License - see the [LICENSE](LICENSE) file for details.
