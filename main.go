// Package main implements a GitHub Action for scanning container images, directories,
// SBOMs, and git refs with Anchore Grype vulnerability scanner.
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

// Config holds all action inputs
type Config struct {
	// Scan modes (mutually exclusive)
	Scan  string // Repository-based: latest_release, head, or tag/branch name
	Image string // Container image to scan
	Path  string // Directory or file to scan
	SBOM  string // SBOM file to scan

	// Common options
	FailBuild      bool
	SeverityCutoff string
	OutputFile     string
	VariablePrefix string
	OnlyFixed      bool
	Debug          bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	config := loadConfig()

	if config.Debug {
		printDebugEnv()
	}

	// Determine scan target
	target, err := determineScanTarget(config)
	if err != nil {
		return fmt.Errorf("failed to determine scan target: %w", err)
	}

	fmt.Printf("Grype scan target: %s\n", target)

	// Create a temporary file for grype output
	tmpFile, err := os.CreateTemp("", "grype-output-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpFilePath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFilePath) }()

	// Run grype scan
	if err := runGrypeScan(config, target, tmpFilePath); err != nil {
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
	if config.OutputFile != "" {
		jsonOutputPath, err = copyOutputFile(tmpFilePath, config.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to copy output file: %w", err)
		}
		fmt.Printf("Scan results saved to: %s\n", jsonOutputPath)
	}

	// Set GitHub Actions outputs
	if err := setOutputs(config.VariablePrefix, stats, output, jsonOutputPath); err != nil {
		return fmt.Errorf("failed to set outputs: %w", err)
	}

	// Print summary
	printSummary(stats, output)

	// Check fail-build condition
	if config.FailBuild {
		if shouldFail(stats, config.SeverityCutoff) {
			return fmt.Errorf("vulnerabilities found at or above %s severity", config.SeverityCutoff)
		}
	}

	return nil
}

func loadConfig() Config {
	return Config{
		Scan:           getEnv("INPUT_SCAN", ""),
		Image:          getEnv("INPUT_IMAGE", ""),
		Path:           getEnv("INPUT_PATH", ""),
		SBOM:           getEnv("INPUT_SBOM", ""),
		FailBuild:      strings.EqualFold(getEnv("INPUT_FAIL-BUILD", "false"), "true"),
		SeverityCutoff: strings.ToLower(getEnv("INPUT_SEVERITY-CUTOFF", "medium")),
		OutputFile:     getEnv("INPUT_OUTPUT-FILE", ""),
		VariablePrefix: getEnv("INPUT_VARIABLE-PREFIX", "GRYPE_"),
		OnlyFixed:      strings.EqualFold(getEnv("INPUT_ONLY-FIXED", "false"), "true"),
		Debug:          strings.EqualFold(getEnv("INPUT_DEBUG", "false"), "true"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func isDebugEnabled() bool {
	return strings.EqualFold(getEnv("INPUT_DEBUG", "false"), "true")
}

func printDebugEnv() {
	fmt.Println("=== Environment Variables (sorted) ===")
	var envVars []string
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "INPUT_") || strings.HasPrefix(env, "GITHUB_") {
			envVars = append(envVars, env)
		}
	}
	sort.Strings(envVars)
	for _, v := range envVars {
		fmt.Println(v)
	}
	fmt.Println("======================================")
}

// determineScanTarget figures out what to scan based on config inputs
func determineScanTarget(config Config) (string, error) {
	// Count how many artifact modes are specified
	artifactModes := 0
	if config.Image != "" {
		artifactModes++
	}
	if config.Path != "" {
		artifactModes++
	}
	if config.SBOM != "" {
		artifactModes++
	}

	// Check for mutual exclusivity
	if artifactModes > 1 {
		return "", fmt.Errorf("only one of image, path, or sbom can be specified")
	}

	if artifactModes > 0 && config.Scan != "" {
		return "", fmt.Errorf("scan cannot be used together with image, path, or sbom")
	}

	// Artifact-based scanning
	if config.Image != "" {
		return config.Image, nil
	}
	if config.Path != "" {
		// Grype uses dir: prefix for directories, file: for files
		info, err := os.Stat(config.Path)
		if err != nil {
			return "", fmt.Errorf("path %q not found: %w", config.Path, err)
		}
		if info.IsDir() {
			return "dir:" + config.Path, nil
		}
		return "file:" + config.Path, nil
	}
	if config.SBOM != "" {
		return "sbom:" + config.SBOM, nil
	}

	// Repository-based scanning (default mode)
	scan := strings.TrimSpace(config.Scan)
	if scan == "" {
		scan = "latest_release"
	}

	return handleRepoScan(scan)
}

// handleRepoScan handles repository-based scanning (latest_release, head, or specific ref)
func handleRepoScan(scan string) (string, error) {
	// Configure git safe directories for Docker container environment
	if err := configureGitSafeDirectory(); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("Repository scan mode: %s\n", scan)

	switch strings.ToLower(scan) {
	case "head":
		// Scan current working directory as-is - no git operations needed
		// The user has already checked out what they want via actions/checkout
		fmt.Println("Scanning current working directory (head mode)")
		return "dir:.", nil

	case "latest_release":
		// Get and checkout the latest release tag
		latestTag, err := getLatestReleaseTag()
		if err != nil {
			return "", fmt.Errorf("could not determine latest release: %w", err)
		}
		fmt.Printf("Found latest release: %s\n", latestTag)
		if err := checkoutRef(latestTag); err != nil {
			return "", fmt.Errorf("failed to checkout %s: %w", latestTag, err)
		}
		return "dir:.", nil

	default:
		// Treat as a specific tag or branch name
		fmt.Printf("Checking out ref: %s\n", scan)
		if err := checkoutRef(scan); err != nil {
			return "", fmt.Errorf("failed to checkout %s: %w", scan, err)
		}
		return "dir:.", nil
	}
}

// configureGitSafeDirectory adds directories to Git's safe.directory config
func configureGitSafeDirectory() error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Add current directory to safe.directory
	cmd := exec.Command("git", "config", "--global", "--add", "safe.directory", cwd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure git safe.directory: %w", err)
	}

	// Also add /github/workspace if in GitHub Actions Docker environment
	if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" && workspace != cwd {
		cmd = exec.Command("git", "config", "--global", "--add", "safe.directory", workspace)
		_ = cmd.Run() // Non-fatal
	}

	// Add wildcard for safety
	cmd = exec.Command("git", "config", "--global", "--add", "safe.directory", "*")
	_ = cmd.Run() // Non-fatal

	return nil
}

// getLatestReleaseTag returns the latest stable release tag (highest semver)
func getLatestReleaseTag() (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git not found: %w", err)
	}

	// Fetch all tags to ensure we have the latest
	fmt.Println("Fetching tags...")
	cmd := exec.Command("git", "fetch", "--tags", "--force")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Could not fetch tags: %v\n", err)
	}

	// Get all tags sorted by version (descending)
	cmd = exec.Command("git", "tag", "--sort=-v:refname")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list tags: %w", err)
	}

	tags := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(tags) == 0 || tags[0] == "" {
		return "", fmt.Errorf("no tags found in repository")
	}

	// Filter out pre-release tags
	for _, tag := range tags {
		if !isPreReleaseTag(tag) {
			return tag, nil
		}
	}

	// If all tags are pre-release, use the highest one
	fmt.Printf("Warning: All tags appear to be pre-release. Using: %s\n", tags[0])
	return tags[0], nil
}

// isPreReleaseTag checks if a tag is a pre-release version (contains hyphen after version)
func isPreReleaseTag(tag string) bool {
	normalized := strings.TrimPrefix(strings.TrimPrefix(tag, "v"), "V")
	parts := strings.SplitN(normalized, "-", 2)
	if len(parts) < 2 {
		return false
	}
	// Check if first part looks like a version number
	for _, c := range parts[0] {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return len(parts[0]) > 0 && len(parts[1]) > 0
}

// validateRefName validates a git ref name for safety
func validateRefName(ref string) error {
	if ref == "" {
		return fmt.Errorf("ref name cannot be empty")
	}
	for i, c := range ref {
		if c < 32 || c == 127 {
			return fmt.Errorf("ref contains invalid character at position %d", i)
		}
	}
	for _, pattern := range []string{"..", "~", "^", ":", "?", "*", "[", "\\", " "} {
		if strings.Contains(ref, pattern) {
			return fmt.Errorf("ref contains invalid pattern %q", pattern)
		}
	}
	if strings.HasPrefix(ref, ".") || strings.HasSuffix(ref, ".") ||
		strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") {
		return fmt.Errorf("ref cannot start or end with . or /")
	}
	return nil
}

// checkoutRef checks out a specific git ref
func checkoutRef(ref string) error {
	if err := validateRefName(ref); err != nil {
		return fmt.Errorf("invalid ref %q: %w", ref, err)
	}

	fmt.Printf("Checking out: %s\n", ref)
	cmd := exec.Command("git", "checkout", ref)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runGrypeScan(config Config, target, outputPath string) error {
	fmt.Printf("Running grype scan...\n")

	args := []string{target, "-o", "json", "--file", outputPath}

	if config.OnlyFixed {
		args = append(args, "--only-fixed")
	}

	cmd := exec.Command("grype", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		// Check if output file exists - grype returns non-zero when vulns found
		if _, statErr := os.Stat(outputPath); statErr == nil {
			fmt.Println("Grype scan completed (vulnerabilities found)")
			return nil
		}
		return err
	}

	fmt.Println("Grype scan completed")
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
		switch strings.ToLower(match.Vulnerability.Severity) {
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

func shouldFail(stats Stats, cutoff string) bool {
	switch strings.ToLower(cutoff) {
	case "critical":
		return stats.Critical > 0
	case "high":
		return stats.Critical > 0 || stats.High > 0
	case "medium":
		return stats.Critical > 0 || stats.High > 0 || stats.Medium > 0
	case "low":
		return stats.Critical > 0 || stats.High > 0 || stats.Medium > 0 || stats.Low > 0
	case "negligible":
		return stats.Total > 0
	default:
		return stats.Critical > 0 || stats.High > 0 || stats.Medium > 0
	}
}

// validatePathInWorkspace ensures dst is within workspace (prevents path traversal)
func validatePathInWorkspace(dst, workspace string) error {
	absDst, err := filepath.Abs(filepath.Clean(dst))
	if err != nil {
		return fmt.Errorf("failed to resolve destination: %w", err)
	}
	absWorkspace, err := filepath.Abs(filepath.Clean(workspace))
	if err != nil {
		return fmt.Errorf("failed to resolve workspace: %w", err)
	}
	rel, err := filepath.Rel(absWorkspace, absDst)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return fmt.Errorf("path traversal detected: %q outside workspace", dst)
	}
	return nil
}

func copyOutputFile(src, dst string) (string, error) {
	var workspace string
	var usedWorkspace bool

	if !filepath.IsAbs(dst) {
		if _, err := os.Stat("/github/workspace"); err == nil {
			workspace = "/github/workspace"
			dst = filepath.Join(workspace, dst)
			usedWorkspace = true
		} else if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" {
			workspace = ws
			dst = filepath.Join(workspace, dst)
			usedWorkspace = true
		} else {
			var err error
			dst, err = filepath.Abs(dst)
			if err != nil {
				return "", fmt.Errorf("failed to make path absolute: %w", err)
			}
		}
	}

	if usedWorkspace && workspace != "" {
		if err := validatePathInWorkspace(dst, workspace); err != nil {
			return "", err
		}
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("failed to read source: %w", err)
	}

	if err := os.WriteFile(dst, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write destination: %w", err)
	}

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
	defer func() { _ = f.Close() }()

	outputs := map[string]string{
		"grype-version": output.Descriptor.Version,
		"db-version":    output.DBBuilt(),
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

	// Set environment variables with custom prefix
	githubEnv := os.Getenv("GITHUB_ENV")
	if githubEnv != "" {
		envFile, err := os.OpenFile(githubEnv, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer func() { _ = envFile.Close() }()

		envVars := map[string]string{
			"VERSION":    output.Descriptor.Version,
			"DB_VERSION": output.DBBuilt(),
			"CVE_COUNT":  fmt.Sprintf("%d", stats.Total),
			"CRITICAL":   fmt.Sprintf("%d", stats.Critical),
			"HIGH":       fmt.Sprintf("%d", stats.High),
			"MEDIUM":     fmt.Sprintf("%d", stats.Medium),
			"LOW":        fmt.Sprintf("%d", stats.Low),
		}
		for key, value := range envVars {
			if _, err := fmt.Fprintf(envFile, "%s%s=%s\n", prefix, key, value); err != nil {
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
