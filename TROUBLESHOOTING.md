# Troubleshooting GitHub Actions Workflows

This document provides guidance for troubleshooting common issues with the GitHub Actions workflows in this repository.

## Workflow Approval Required

If workflows show "action_required" status, they may need approval to run. This is common for:
- First-time contributors
- New workflows added to the repository
- Changes to workflow permissions

**Solution**: A repository maintainer needs to approve the workflow run in the GitHub Actions UI.

## Common Workflow Failures

### 1. Go Version Issues

**Symptom**: Workflow fails with "Could not find a version that satisfied version spec: '1.25'"

**Cause**: The specified Go version may not be available in GitHub Actions runners yet.

**Solution**: 
- Use version format `'1.25.x'` instead of `'1.25'` to allow patch version flexibility
- Check [Go Releases](https://go.dev/dl/) for available versions
- Consider using a stable release like `'1.23.x'` if the latest version is not available

### 2. Docker Build Failures

**Symptom**: Docker build fails with "unable to select packages" or "TLS: unspecified error"

**Cause**: Network restrictions preventing access to Alpine package repositories.

**Solutions**:
- Use specific Alpine version (e.g., `alpine:3.21`) instead of `alpine:latest`
- Consider using pre-built base images if package installation consistently fails
- Check if Docker Hub rate limiting is affecting the build

### 3. Staticcheck Installation Issues

**Symptom**: Staticcheck fails with "module requires at least go1.X, but Staticcheck was built with go1.Y"

**Cause**: Version mismatch between Go module requirements and staticcheck binary.

**Solution**: 
- In GitHub Actions, staticcheck is installed after Go is set up, so it uses the correct version
- Locally, reinstall staticcheck: `go install honnef.co/go/tools/cmd/staticcheck@latest`
- Ensure `GOROOT` and `GOPATH` are correctly set in your environment

### 4. Grype Installation Failures

**Symptom**: Docker build fails when installing grype, or grype commands fail in tests

**Cause**: 
- Network restrictions preventing download from GitHub
- Grype database update failures

**Solutions**:
- Ensure network allows access to `https://raw.githubusercontent.com/anchore/grype/`
- In tests, grype database is updated with `grype db update`
- Check grype version compatibility: `grype version`

### 5. Integration Test Failures

**Symptom**: Integration test fails with empty outputs or missing files

**Possible Causes**:
- Docker build failed (action uses Dockerfile)
- Grype scan failed without error handling
- Output file path issues

**Debug Steps**:
1. Check if Docker image builds locally: `docker build -t grype_me:test .`
2. Check action outputs in workflow logs
3. Download artifacts from failed runs to inspect scan results

## Testing Workflows Locally

### Prerequisites
```bash
# Install dependencies
go install honnef.co/go/tools/cmd/staticcheck@latest
pip install yamllint

# Install grype for e2e tests
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
grype db update
```

### Run Linting Checks
```bash
# Go formatting
gofmt -l .

# Go vet
go vet ./...

# Staticcheck
staticcheck ./...

# YAML linting
yamllint -c .yamllint .github/workflows/ action.yml example-workflow.yml
```

### Run Tests
```bash
# Unit tests only (skip e2e tests requiring grype)
go test -v -short ./...

# All tests including e2e
go test -v ./...

# With coverage
go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
```

### Test Docker Build
```bash
# Build the Docker image
docker build -t grype_me:test .

# Test the action locally (requires docker)
docker run --rm grype_me:test --help
```

## Workflow Configuration

### Disabling Specific Jobs

To temporarily disable a job while debugging:

```yaml
jobs:
  problematic-job:
    if: false  # Disable this job
    runs-on: ubuntu-latest
    # ... rest of configuration
```

### Making Jobs Continue on Error

To allow workflows to complete even if a job fails:

```yaml
- name: Potentially failing step
  run: command-that-might-fail
  continue-on-error: true
```

## Getting Help

If you encounter persistent issues:

1. Check the [GitHub Actions documentation](https://docs.github.com/en/actions)
2. Review workflow run logs in the Actions tab
3. Check if the issue is reproducible locally
4. Open an issue with:
   - Workflow run link
   - Error messages
   - Steps to reproduce
