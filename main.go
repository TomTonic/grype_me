// Package main implements a GitHub Action for scanning container images and directories
// with Anchore Grype vulnerability scanner.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
			Built string `json:"built"`
		} `json:"db"`
	} `json:"descriptor"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// sortStrings sorts a slice of strings in place
func sortStrings(arr []string) {
	for i := 0; i < len(arr); i++ {
		for j := i + 1; j < len(arr); j++ {
			if arr[i] > arr[j] {
				arr[i], arr[j] = arr[j], arr[i]
			}
		}
	}
}

func run() error {
	// Get inputs from environment variables
	// GitHub Actions preserves hyphens in input names when setting environment variables
	// e.g., 'output-file' becomes 'INPUT_OUTPUT-FILE' (not INPUT_OUTPUT_FILE)

	// Sort and display INPUT_* and GITHUB_* environment variables
	fmt.Printf("=== Environment Variables (sorted) ===\n")
	var inputVars []string
	var githubVars []string
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "INPUT_") {
			inputVars = append(inputVars, env)
		} else if strings.HasPrefix(env, "GITHUB_") {
			githubVars = append(githubVars, env)
		}
	}
	// Sort the slices
	sortStrings(inputVars)
	sortStrings(githubVars)
	
	// Print sorted INPUT_* variables
	for _, v := range inputVars {
		fmt.Println(v)
	}
	// Print sorted GITHUB_* variables
	for _, v := range githubVars {
		fmt.Println(v)
	}
	fmt.Printf("======================================\n\n")

	repository := getEnv("INPUT_REPOSITORY", ".")
	branch := getEnv("INPUT_BRANCH", "")
	outputFile := getEnv("INPUT_OUTPUT-FILE", "")
	variablePrefix := getEnv("INPUT_VARIABLE-PREFIX", "GRYPE_")

	fmt.Printf("Starting Grype scan...\n")
	fmt.Printf("Repository: %s\n", repository)
	fmt.Printf("Output file: %s\n", outputFile)
	fmt.Printf("Variable prefix: %s\n", variablePrefix)
	fmt.Printf("GITHUB_WORKSPACE: %s\n", os.Getenv("GITHUB_WORKSPACE"))

	// Debug: Check if we're in a Docker container
	if _, err := os.Stat("/github/workspace"); err == nil {
		fmt.Printf("Detected Docker container environment (/github/workspace exists)\n")
	} else {
		fmt.Printf("Not in Docker container environment (/github/workspace does not exist)\n")
	}
	if branch != "" {
		fmt.Printf("Branch: %s\n", branch)
	}

	// If a specific branch is requested and we're in a git repo, checkout that branch
	if branch != "" && repository == "." {
		if err := checkoutBranch(branch); err != nil {
			fmt.Printf("Warning: Could not checkout branch %s: %v\n", branch, err)
		}
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

	// Run grype scan
	if err := runGrypeScan(repository, tmpFilePath); err != nil {
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

func checkoutBranch(branch string) error {
	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git not found: %w", err)
	}

	// Check if current directory is a git repository
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("not a git repository: %w", err)
	}

	// Checkout the branch
	cmd = exec.Command("git", "checkout", branch)
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

func copyOutputFile(src, dst string) (string, error) {
	fmt.Printf("[copyOutputFile] src=%s, dst=%s\n", src, dst)

	// If dst is relative and we're in a GitHub Actions environment,
	// make it relative to the workspace
	if !filepath.IsAbs(dst) {
		// In Docker actions, the workspace is mounted at /github/workspace
		// Check if we're running in a Docker container action
		if _, err := os.Stat("/github/workspace"); err == nil {
			dst = filepath.Join("/github/workspace", dst)
			fmt.Printf("[copyOutputFile] Using Docker workspace path: %s\n", dst)
		} else if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" {
			// Fallback to GITHUB_WORKSPACE for non-Docker actions
			dst = filepath.Join(workspace, dst)
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
	outputs := map[string]string{
		"grype-version": output.Descriptor.Version,
		"db-version":    output.Descriptor.DB.Built,
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
			"DB_VERSION": output.Descriptor.DB.Built,
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
	fmt.Printf("Database Version: %s\n", output.Descriptor.DB.Built)
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
