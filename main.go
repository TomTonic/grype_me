// Package main implements a GitHub Action for scanning container images and directories
// with Anchore Grype vulnerability scanner.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// GrypeMatch represents a single vulnerability match
type GrypeMatch struct {
	Vulnerability struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
	} `json:"vulnerability"`
}

// GrypeOutput represents the JSON output from grype
type GrypeOutput struct {
	Matches    []GrypeMatch `json:"matches"`
	Descriptor struct {
		Version string `json:"version"`
		DB      struct {
			// Older grype outputs exposed the built timestamp at descriptor.db.built.
			Built string `json:"built,omitempty"`
			// Newer grype outputs (e.g. 0.106+) expose it at descriptor.db.status.built.
			Status struct {
				Built string `json:"built,omitempty"`
			} `json:"status,omitempty"`
		} `json:"db"`
	} `json:"descriptor"`
}

func (o *GrypeOutput) DBBuilt() string {
	if o == nil {
		return ""
	}
	if built := o.Descriptor.DB.Status.Built; built != "" {
		return built
	}
	return o.Descriptor.DB.Built
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Get inputs from environment variables
	// GitHub Actions prepends "INPUT_" to input names when setting environment variables and uses uppercase
	// e.g., 'output-file' becomes 'INPUT_OUTPUT-FILE'

	// Collect and display INPUT_* and GITHUB_* environment variables
	if isDebugEnabled() {
		fmt.Println("=== Environment Variables (sorted) ===")
		var envVars []string
		for _, env := range os.Environ() {
			if strings.HasPrefix(env, "INPUT_") {
				envVars = append(envVars, env)
			} else if strings.HasPrefix(env, "GITHUB_") {
				envVars = append(envVars, env)
			}
		}

		sort.Strings(envVars)

		for _, v := range envVars {
			fmt.Println(v)
		}
		fmt.Println("======================================")
	}

	scan := getEnv("INPUT_SCAN", "latest_release")
	outputFile := getEnv("INPUT_OUTPUT-FILE", "")
	variablePrefix := getEnv("INPUT_VARIABLE-PREFIX", "GRYPE_")

	fmt.Printf("Starting Grype scan...\n")
	fmt.Printf("Scan target: %s\n", scan)
	fmt.Printf("Output file: %s\n", outputFile)
	fmt.Printf("Variable prefix: %s\n", variablePrefix)
	fmt.Printf("GITHUB_WORKSPACE: %s\n", os.Getenv("GITHUB_WORKSPACE"))

	// Debug: Check if we're in a Docker container
	if _, err := os.Stat("/github/workspace"); err == nil {
		fmt.Printf("Detected Docker container environment (/github/workspace exists)\n")
	} else {
		fmt.Printf("Not in Docker container environment (/github/workspace does not exist)\n")
	}

	// Handle the scan parameter
	if err := handleScanTarget(scan); err != nil {
		return fmt.Errorf("failed to prepare scan target: %w", err)
	}

	// Create a temporary file for grype output
	tmpFile, err := os.CreateTemp("", "grype-output-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpFilePath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	defer func() {
		_ = os.Remove(tmpFilePath)
	}()

	// Run grype scan on the current directory (we've already checked out the right ref)
	if err := runGrypeScan(".", tmpFilePath); err != nil {
		return fmt.Errorf("grype scan failed: %w", err)
	}

	// Parse grype output
	output, err := parseGrypeOutput(tmpFilePath)
	if err != nil {
		return fmt.Errorf("failed to parse grype output: %w", err)
	}

	// Calculate statistics
	stats := calculateStats(output)

	// Copy output file to desired location if specified
	jsonOutputPath := ""
	if outputFile != "" {
		fmt.Printf("Copying output file from %s to %s\n", tmpFilePath, outputFile)

		// Verify source file exists and get its size
		info, err := os.Stat(tmpFilePath)
		if err != nil {
			return fmt.Errorf("source file %s does not exist: %w", tmpFilePath, err)
		}
		fmt.Printf("Source file size: %d bytes\n", info.Size())

		jsonOutputPath, err = copyOutputFile(tmpFilePath, outputFile)
		if err != nil {
			return fmt.Errorf("failed to copy output file: %w", err)
		}
		fmt.Printf("Scan results saved to: %s\n", jsonOutputPath)

		// Verify destination file was created
		if info, err := os.Stat(jsonOutputPath); err != nil {
			fmt.Printf("WARNING: Destination file %s was not created or is not accessible: %v\n", jsonOutputPath, err)
		} else {
			fmt.Printf("Destination file size: %d bytes\n", info.Size())
		}
	}

	// Set GitHub Actions outputs
	if err := setOutputs(variablePrefix, stats, output, jsonOutputPath); err != nil {
		return fmt.Errorf("failed to set outputs: %w", err)
	}

	// Print summary
	printSummary(stats, output)

	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func isDebugEnabled() bool {
	value := strings.TrimSpace(getEnv("INPUT_DEBUG", "false"))
	return strings.EqualFold(value, "true")
}

// handleScanTarget processes the scan input parameter and checks out the appropriate ref.
// Supported values:
// - "head": checkout the default branch (main/master)
// - "latest_release": checkout the latest release tag
// - any other value: treated as a tag or branch name
func handleScanTarget(scan string) error {
	// Normalize the scan value
	scan = strings.TrimSpace(scan)
	if scan == "" {
		scan = "head"
	}

	fmt.Printf("Processing scan target: %s\n", scan)

	switch strings.ToLower(scan) {
	case "head":
		// Checkout the default branch (typically main or master)
		defaultBranch, err := getDefaultBranch()
		if err != nil {
			fmt.Printf("Warning: Could not determine default branch: %v\n", err)
			// If we can't determine the default branch, we're likely already on it
			return nil
		}
		fmt.Printf("Checking out default branch: %s\n", defaultBranch)
		return checkoutRef(defaultBranch)

	case "latest_release":
		// Get and checkout the latest release tag
		latestTag, err := getLatestReleaseTag()
		if err != nil {
			return fmt.Errorf("could not determine latest release: %w", err)
		}
		fmt.Printf("Checking out latest release: %s\n", latestTag)
		return checkoutRef(latestTag)

	default:
		// Treat as a tag or branch name
		fmt.Printf("Checking out ref: %s\n", scan)
		return checkoutRef(scan)
	}
}

// getDefaultBranch returns the default branch name (e.g., "main" or "master")
func getDefaultBranch() (string, error) {
	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git not found: %w", err)
	}

	// Check if current directory is a git repository
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("not a git repository: %w", err)
	}

	// Try to get the default branch from origin
	cmd = exec.Command("git", "symbolic-ref", "refs/remotes/origin/HEAD")
	output, err := cmd.Output()
	if err == nil {
		// Parse "refs/remotes/origin/main" -> "main"
		ref := strings.TrimSpace(string(output))
		parts := strings.Split(ref, "/")
		if len(parts) > 0 {
			return parts[len(parts)-1], nil
		}
	}

	// Fallback: try common default branch names
	for _, branch := range []string{"main", "master"} {
		cmd = exec.Command("git", "rev-parse", "--verify", fmt.Sprintf("refs/heads/%s", branch))
		if err := cmd.Run(); err == nil {
			return branch, nil
		}
		// Also check remote refs
		cmd = exec.Command("git", "rev-parse", "--verify", fmt.Sprintf("refs/remotes/origin/%s", branch))
		if err := cmd.Run(); err == nil {
			return branch, nil
		}
	}

	return "", fmt.Errorf("could not determine default branch")
}

// getLatestReleaseTag returns the latest release tag in the repository
func getLatestReleaseTag() (string, error) {
	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git not found: %w", err)
	}

	// Get all tags sorted by version (descending)
	// Using git tag with version sort to get the latest version tag
	cmd := exec.Command("git", "tag", "--sort=-v:refname")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list tags: %w", err)
	}

	tags := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(tags) == 0 || tags[0] == "" {
		return "", fmt.Errorf("no tags found in repository")
	}

	// Return the first (latest) tag
	return tags[0], nil
}

// validateRefName checks if a git reference name is valid and safe to use.
// It rejects refs containing control characters, null bytes, or other suspicious patterns.
func validateRefName(ref string) error {
	if ref == "" {
		return fmt.Errorf("ref name cannot be empty")
	}

	// Check for control characters (ASCII 0-31 and 127)
	for i, c := range ref {
		if c < 32 || c == 127 {
			return fmt.Errorf("ref name contains invalid control character at position %d", i)
		}
	}

	// Check for null bytes (additional explicit check)
	if strings.Contains(ref, "\x00") {
		return fmt.Errorf("ref name contains null byte")
	}

	// Check for suspicious patterns that might indicate injection attempts
	suspiciousPatterns := []string{
		"..", // Path traversal
		"~",  // Git reflog syntax
		"^",  // Git parent syntax (could be valid but suspicious in user input)
		":",  // Git revision syntax
		"?",  // Wildcard
		"*",  // Wildcard
		"[",  // Wildcard/range
		"\\", // Escape character
		" ",  // Spaces (not valid in ref names)
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(ref, pattern) {
			return fmt.Errorf("ref name contains suspicious pattern %q", pattern)
		}
	}

	// Git ref names cannot start or end with a dot or slash
	if strings.HasPrefix(ref, ".") || strings.HasSuffix(ref, ".") {
		return fmt.Errorf("ref name cannot start or end with a dot")
	}
	if strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") {
		return fmt.Errorf("ref name cannot start or end with a slash")
	}

	return nil
}

// checkoutRef checks out a specific git reference (branch, tag, or commit)
func checkoutRef(ref string) error {
	// Validate the ref name before using it
	if err := validateRefName(ref); err != nil {
		return fmt.Errorf("invalid ref name %q: %w", ref, err)
	}

	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git not found: %w", err)
	}

	// Check if current directory is a git repository
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("not a git repository: %w", err)
	}

	// Fetch all refs to ensure we have the latest
	fmt.Printf("Fetching refs...\n")
	cmd = exec.Command("git", "fetch", "--all", "--tags")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Could not fetch refs: %v\n", err)
		// Continue anyway, the ref might already exist locally
	}

	// Checkout the ref
	cmd = exec.Command("git", "checkout", ref)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runGrypeScan(target, outputPath string) error {
	fmt.Printf("Running grype scan on: %s\n", target)

	cmd := exec.Command("grype", target, "-o", "json", "--file", outputPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Grype returns non-zero exit code when vulnerabilities are found
	// We don't want to fail the action in this case, just when grype itself fails
	err := cmd.Run()
	if err != nil {
		// Check if the output file exists - if it does, grype ran successfully
		if _, statErr := os.Stat(outputPath); statErr == nil {
			fmt.Printf("Grype scan completed (found vulnerabilities)\n")
			return nil
		}
		return err
	}

	fmt.Printf("Grype scan completed successfully\n")
	return nil
}

func parseGrypeOutput(filePath string) (*GrypeOutput, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %w", err)
	}

	var output GrypeOutput
	if err := json.Unmarshal(data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &output, nil
}

type Stats struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Other    int
}

func calculateStats(output *GrypeOutput) Stats {
	stats := Stats{}

	for _, match := range output.Matches {
		stats.Total++

		severity := strings.ToLower(match.Vulnerability.Severity)
		switch severity {
		case "critical":
			stats.Critical++
		case "high":
			stats.High++
		case "medium":
			stats.Medium++
		case "low":
			stats.Low++
		default:
			stats.Other++
		}
	}

	return stats
}

// validatePathInWorkspace ensures the destination path is within the expected workspace directory.
// This prevents path traversal attacks where malicious input could write files outside
// the intended directory (e.g., using "../../../etc/passwd").
// It only validates when a workspace was explicitly used to construct the path.
func validatePathInWorkspace(dst, workspace string) error {
	// Clean the paths to resolve any ".." or "." components
	cleanDst := filepath.Clean(dst)
	cleanWorkspace := filepath.Clean(workspace)

	// Ensure both paths are absolute for proper comparison
	absDst, err := filepath.Abs(cleanDst)
	if err != nil {
		return fmt.Errorf("failed to resolve destination path: %w", err)
	}

	absWorkspace, err := filepath.Abs(cleanWorkspace)
	if err != nil {
		return fmt.Errorf("failed to resolve workspace path: %w", err)
	}

	// Check if destination is within workspace using Rel
	// If the relative path starts with "..", it's outside the workspace
	rel, err := filepath.Rel(absWorkspace, absDst)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}

	// Check if path escapes workspace (contains ".." at the start)
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return fmt.Errorf("path traversal detected: destination %q is outside workspace %q", dst, workspace)
	}

	return nil
}

func copyOutputFile(src, dst string) (string, error) {
	fmt.Printf("[copyOutputFile] src=%s, dst=%s\n", src, dst)

	var workspace string
	var usedWorkspace bool // Track if we actually used workspace to construct the path

	// If dst is relative and we're in a GitHub Actions environment,
	// make it relative to the workspace
	if !filepath.IsAbs(dst) {
		// In Docker actions, the workspace is mounted at /github/workspace
		// Check if we're running in a Docker container action
		if _, err := os.Stat("/github/workspace"); err == nil {
			workspace = "/github/workspace"
			dst = filepath.Join(workspace, dst)
			usedWorkspace = true
			fmt.Printf("[copyOutputFile] Using Docker workspace path: %s\n", dst)
		} else if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" {
			// Fallback to GITHUB_WORKSPACE for non-Docker actions
			workspace = ws
			dst = filepath.Join(workspace, dst)
			usedWorkspace = true
			fmt.Printf("[copyOutputFile] Using GITHUB_WORKSPACE: %s\n", dst)
		} else {
			// Make destination path absolute if not in GitHub Actions
			var err error
			dst, err = filepath.Abs(dst)
			if err != nil {
				return "", fmt.Errorf("failed to make path absolute: %w", err)
			}
			fmt.Printf("[copyOutputFile] Using absolute path: %s\n", dst)
		}
	}

	// Validate that the destination path is within the workspace (security check)
	// Only validate if we explicitly used workspace to construct the path
	if usedWorkspace && workspace != "" {
		if err := validatePathInWorkspace(dst, workspace); err != nil {
			return "", fmt.Errorf("security validation failed: %w", err)
		}
		fmt.Printf("[copyOutputFile] Path validation passed: destination is within workspace\n")
	}

	// Ensure directory exists
	dir := filepath.Dir(dst)
	fmt.Printf("[copyOutputFile] Creating directory: %s\n", dir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Read source file
	fmt.Printf("[copyOutputFile] Reading source file: %s\n", src)
	data, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("failed to read source file %s: %w", src, err)
	}
	fmt.Printf("[copyOutputFile] Read %d bytes from source\n", len(data))

	// Write to destination
	fmt.Printf("[copyOutputFile] Writing to destination: %s\n", dst)
	if err := os.WriteFile(dst, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write to destination %s: %w", dst, err)
	}
	fmt.Printf("[copyOutputFile] Successfully wrote %d bytes to %s\n", len(data), dst)

	return dst, nil
}

func setOutputs(prefix string, stats Stats, output *GrypeOutput, jsonPath string) error {
	githubOutput := os.Getenv("GITHUB_OUTPUT")
	if githubOutput == "" {
		fmt.Println("Warning: GITHUB_OUTPUT not set, skipping output generation")
		return nil
	}

	f, err := os.OpenFile(githubOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	// Write standard outputs
	dbBuilt := output.DBBuilt()
	outputs := map[string]string{
		"grype-version": output.Descriptor.Version,
		"db-version":    dbBuilt,
		"cve-count":     fmt.Sprintf("%d", stats.Total),
		"critical":      fmt.Sprintf("%d", stats.Critical),
		"high":          fmt.Sprintf("%d", stats.High),
		"medium":        fmt.Sprintf("%d", stats.Medium),
		"low":           fmt.Sprintf("%d", stats.Low),
	}

	if jsonPath != "" {
		outputs["json-output"] = jsonPath
	}

	for key, value := range outputs {
		if _, err := fmt.Fprintf(f, "%s=%s\n", key, value); err != nil {
			return err
		}
	}

	// Also set environment variables with custom prefix
	githubEnv := os.Getenv("GITHUB_ENV")
	if githubEnv != "" {
		envFile, err := os.OpenFile(githubEnv, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer func() {
			_ = envFile.Close()
		}()

		envVars := map[string]string{
			"VERSION":    output.Descriptor.Version,
			"DB_VERSION": dbBuilt,
			"CVE_COUNT":  fmt.Sprintf("%d", stats.Total),
			"CRITICAL":   fmt.Sprintf("%d", stats.Critical),
			"HIGH":       fmt.Sprintf("%d", stats.High),
			"MEDIUM":     fmt.Sprintf("%d", stats.Medium),
			"LOW":        fmt.Sprintf("%d", stats.Low),
		}

		for key, value := range envVars {
			varName := prefix + key
			if _, err := fmt.Fprintf(envFile, "%s=%s\n", varName, value); err != nil {
				return err
			}
		}
	}

	return nil
}

func printSummary(stats Stats, output *GrypeOutput) {
	fmt.Println("\n=== Grype Scan Summary ===")
	fmt.Printf("Grype Version: %s\n", output.Descriptor.Version)
	fmt.Printf("Database Version: %s\n", output.DBBuilt())
	fmt.Printf("\nVulnerabilities Found:\n")
	fmt.Printf("  Total:    %d\n", stats.Total)
	fmt.Printf("  Critical: %d\n", stats.Critical)
	fmt.Printf("  High:     %d\n", stats.High)
	fmt.Printf("  Medium:   %d\n", stats.Medium)
	fmt.Printf("  Low:      %d\n", stats.Low)
	if stats.Other > 0 {
		fmt.Printf("  Other:    %d\n", stats.Other)
	}
	fmt.Println("==========================")
}
