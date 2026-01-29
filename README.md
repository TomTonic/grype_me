# grype_me

A lean GitHub Action to scan your repository for vulnerabilities using [Anchore Grype](https://github.com/anchore/grype).

## Features

- 🔍 Scans your repository or any specified repository for vulnerabilities
- 📊 Provides detailed vulnerability counts by severity (Critical, High, Medium, Low)
- 🎯 Outputs results as JSON file (optional)
- 🔧 Configurable output variable names
- 🚀 Uses Go for fast execution
- 📦 Containerized for consistent execution

## Usage

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
          version: 'latest'
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
        uses: actions/upload-artifact@v3
        with:
          name: grype-scan-results
          path: grype-results.json
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `repository` | Repository to scan | No | `.` (current repository) |
| `branch` | Branch to scan | No | Current branch |
| `version` | Grype version to use | No | `latest` |
| `output-file` | Path to save JSON scan results | No | `` (no file saved) |
| `variable-prefix` | Prefix for environment variable names | No | `GRYPE_` |

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
