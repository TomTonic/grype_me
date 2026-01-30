# Integration Test Failure Analysis

## Problem Statement
The Integration Test job in `.github/workflows/test.yml` is failing with:
```
ERROR: Output file grype-results.json not found
```

## Root Cause Analysis

### Possible Reasons for Failure:

#### 1. **File Not Created at All**
- Grype scan may be failing silently
- The Go program may be exiting before reaching the file copy step
- An error in `copyOutputFile()` may be preventing file creation

#### 2. **File Created in Wrong Location**
- File might be created inside the Docker container but not in the mounted workspace
- Path resolution logic may be incorrect for Docker container actions
- The `/github/workspace` mount may not be set up correctly

#### 3. **Docker Container Action Specifics**
- **Key Insight**: Docker-based GitHub Actions mount the workspace at `/github/workspace`
- The `$GITHUB_WORKSPACE` environment variable contains the **host** path, not the container path
- Files must be written to `/github/workspace` inside the container to appear in the host workspace

#### 4. **Timing Issues**
- File may be created but deleted/cleaned up before the artifact upload step
- Container may be terminating before file operations complete

#### 5. **Permissions Issues**
- File may be created with incorrect permissions
- Directory permissions may prevent file creation

## Current Implementation Review

### Path Resolution Logic (copyOutputFile function)
```go
if !filepath.IsAbs(dst) {
    // 1. Check for Docker workspace
    if _, err := os.Stat("/github/workspace"); err == nil {
        dst = filepath.Join("/github/workspace", dst)
    }
    // 2. Fall back to GITHUB_WORKSPACE env var
    else if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" {
        dst = filepath.Join(workspace, dst)
    }
    // 3. Make absolute
    else {
        dst, err = filepath.Abs(dst)
    }
}
```

**Potential Issues**:
- Priority is correct (Docker workspace first)
- BUT: Need to verify `/github/workspace` actually exists in the container
- Need to ensure the file isn't being created relative to a different working directory

### Integration Test Workflow
```yaml
- name: Run Grype vulnerability scanner
  id: grype-scan
  uses: ./
  with:
    repository: '.'
    output-file: 'grype-results.json'  # Relative path
    variable-prefix: 'GRYPE_'

- name: Upload scan results
  uses: actions/upload-artifact@v5
  with:
    path: grype-results.json  # Expected in workspace root
```

**Potential Issues**:
- Relative path `grype-results.json` should work with our logic
- BUT: Need to verify the file is actually created where expected

## Debugging Strategy

### Current Debug Output Added
1. All input parameters logged
2. Grype command logged
3. Docker workspace detection logged
4. Source and destination paths logged
5. File sizes logged
6. Directory creation logged

### What to Look For in Logs
1. Does `/github/workspace` exist check return true?
2. What is the final destination path being used?
3. Does the file write succeed?
4. What is the current working directory when the action runs?
5. Are there any errors during file operations?

## Recommended Fixes

### Fix 1: Verify Working Directory
The action might be running from a different directory than expected.

```go
// Add at start of run()
fmt.Printf("[DEBUG] Current working directory: %s\n", mustGetwd())

func mustGetwd() string {
    wd, err := os.Getwd()
    if err != nil {
        return "unknown"
    }
    return wd
}
```

### Fix 2: Always Use Absolute Paths for Temp File
```go
// In run() function, make tempFile always use absolute path
tempFile := filepath.Join(os.TempDir(), "grype-output.json")
```

### Fix 3: Add File Existence Verification
```go
// After copyOutputFile
if _, err := os.Stat(finalPath); err != nil {
    return fmt.Errorf("verification failed: output file does not exist at %s: %w", finalPath, err)
}
```

### Fix 4: Alternative - Write Directly to Destination
Instead of temp file + copy, write directly:
```go
outputPath := outputFile
if !filepath.IsAbs(outputPath) {
    if _, err := os.Stat("/github/workspace"); err == nil {
        outputPath = filepath.Join("/github/workspace", outputPath)
    }
}

cmd := exec.Command("grype", "-o", "json", "--file", outputPath, repository)
```

## Next Steps

1. **Check CI Logs** - Look for the debug output added in commit 29eff8c
2. **Verify Path** - Confirm where the file is actually being created
3. **Test Fix** - Apply one of the recommended fixes based on log analysis
4. **Add More Logging** - If needed, add working directory logging
5. **Consider Alternative** - If copy approach keeps failing, write directly to destination

## Related Files
- `main.go` - Main execution logic
- `.github/workflows/test.yml` - Integration test workflow  
- `action.yml` - Action definition
- `Dockerfile` - Container setup
