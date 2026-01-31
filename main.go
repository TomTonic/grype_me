// Package main implements a GitHub Action for scanning container images, directories,
// SBOMs, and Git refs with Anchore Grype vulnerability scanner.
//
// The action supports multiple scan modes:
//   - Repository scanning: Scan the latest release, HEAD, or a specific tag/branch
//   - Image scanning: Scan a container image from a registry
//   - Path scanning: Scan a local directory or file
//   - SBOM scanning: Scan an existing SBOM file
//
// Results are provided as GitHub Actions outputs and can optionally be saved to a JSON file.
// A shields.io badge URL is generated for easy integration into README files.
//
// File organization:
//   - main.go: Entry point and orchestration
//   - types.go: Data structures (GrypeOutput, Config, VulnerabilityStats)
//   - config.go: Configuration loading and environment variable handling
//   - scanner.go: Grype scan execution and result parsing
//   - git.go: Git operations (worktrees, tags, ref handling)
//   - output.go: GitHub Actions outputs, file handling, badge generation
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// run is the main entry point that orchestrates the vulnerability scanning workflow.
// It loads configuration, determines the scan target, executes the scan, and processes results.
func run() error {
	config := loadConfig()

	if config.Debug {
		printDebugEnv()
	}

	// Determine what to scan based on configuration
	target, tempDir, err := determineScanTarget(config)
	if err != nil {
		return fmt.Errorf("failed to determine scan target: %w", err)
	}

	// Clean up temporary worktree if one was created (for repository scanning)
	if tempDir != "" {
		defer cleanupWorktree(tempDir)
	}

	fmt.Printf("Grype scan target: %s\n", target)

	// Update vulnerability database if requested
	if config.DBUpdate {
		if err := updateGrypeDB(); err != nil {
			return fmt.Errorf("failed to update grype database: %w", err)
		}
	}

	// Execute Grype scan and get results
	grypeOutput, err := executeScan(config, target)
	if err != nil {
		return err
	}

	// Process and output results
	return processResults(config, grypeOutput)
}

// executeScan runs the Grype vulnerability scan and parses the output.
// It creates a temporary file for Grype's JSON output, which is cleaned up after parsing.
func executeScan(config Config, target string) (*GrypeOutput, error) {
	// Create a temporary file for Grype output
	tmpFile, err := os.CreateTemp("", "grype-output-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpFilePath := tmpFile.Name()

	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFilePath) }()

	// Run the Grype scan
	if err := runGrypeScan(config, target, tmpFilePath); err != nil {
		return nil, fmt.Errorf("grype scan failed: %w", err)
	}

	// Parse the scan output
	output, err := parseGrypeOutput(tmpFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse grype output: %w", err)
	}

	// Copy output file to user-specified location if requested
	if config.OutputFile != "" {
		jsonOutputPath, err := copyOutputFile(tmpFilePath, config.OutputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to copy output file: %w", err)
		}
		fmt.Printf("Scan results saved to: %s\n", jsonOutputPath)
	}

	return output, nil
}

// processResults calculates statistics, sets outputs, prints summary, and checks fail conditions.
func processResults(config Config, output *GrypeOutput) error {
	stats := calculateStats(output)

	// Determine JSON output path for GitHub Actions outputs
	jsonOutputPath := ""
	if config.OutputFile != "" {
		resolved, _ := resolveDestinationPath(config.OutputFile)
		jsonOutputPath = resolved
	}

	// Set GitHub Actions outputs and environment variables
	scanMode := determineScanMode(config)
	if err := setOutputs(config.VariablePrefix, stats, output, jsonOutputPath, config.BadgeLabel, scanMode); err != nil {
		return fmt.Errorf("failed to set outputs: %w", err)
	}

	// Print human-readable summary
	printSummary(stats, output)

	// Check if build should fail due to vulnerabilities
	if config.FailBuild && shouldFail(stats, config.SeverityCutoff) {
		return fmt.Errorf("vulnerabilities found at or above %s severity", config.SeverityCutoff)
	}

	return nil
}
