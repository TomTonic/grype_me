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
	grypeOutput, rawJSON, err := executeScan(config, target)
	if err != nil {
		return err
	}

	// Process and output results
	return processResults(config, grypeOutput, rawJSON)
}

// executeScan runs the Grype vulnerability scan and parses the output.
// It returns the parsed output, the raw JSON bytes, and any error.
func executeScan(config Config, target string) (*GrypeOutput, []byte, error) {
	// Create a temporary file for Grype output
	tmpFile, err := os.CreateTemp("", "grype-output-*.json")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpFilePath := tmpFile.Name()

	if err := tmpFile.Close(); err != nil {
		return nil, nil, fmt.Errorf("failed to close temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFilePath) }()

	// Run the Grype scan
	if err := runGrypeScan(config, target, tmpFilePath); err != nil {
		return nil, nil, fmt.Errorf("grype scan failed: %w", err)
	}

	// Read the raw JSON before parsing (for gist upload)
	rawJSON, err := os.ReadFile(tmpFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read grype output: %w", err)
	}

	// Parse the scan output
	output, err := parseGrypeOutput(tmpFilePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse grype output: %w", err)
	}

	// Copy output file to user-specified location if requested
	if config.OutputFile != "" {
		jsonOutputPath, err := copyOutputFile(tmpFilePath, config.OutputFile)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to copy output file: %w", err)
		}
		fmt.Printf("Scan results saved to: %s\n", jsonOutputPath)
	}

	return output, rawJSON, nil
}

// processResults calculates statistics, optionally writes to a gist, sets outputs, prints summary, and checks fail conditions.
func processResults(config Config, output *GrypeOutput, rawJSON []byte) error {
	stats := calculateStats(output)
	scanMode := determineScanMode(config)

	// Determine JSON output path for GitHub Actions outputs
	jsonOutputPath := ""
	if config.OutputFile != "" {
		resolved, _ := resolveDestinationPath(config.OutputFile)
		jsonOutputPath = resolved
	}

	// Gist integration: write badge JSON + report + raw grype output if configured
	var reportURL string
	var gistBadgeURL string
	if config.GistToken != "" && config.GistID != "" {
		badgeJSON := generateBadgeJSON(stats, output.Descriptor.Version, output.DBBuilt(), scanMode)
		report := generateReport(output, stats, scanMode)

		badgeFile, reportFile, grypeFile := defaultGistFilenames(config.GistFilename, scanMode)

		gistFiles := map[string]string{
			badgeFile:  badgeJSON,
			reportFile: report,
		}
		if len(rawJSON) > 0 {
			gistFiles[grypeFile] = string(rawJSON)
		}

		client := NewGistClient(config.GistToken)
		result, err := client.UpdateGist(config.GistID, badgeFile, reportFile, gistFiles)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to update gist: %v\n", err)
		} else {
			reportURL = result.ReportURL
			gistBadgeURL = result.BadgeURL
			fmt.Printf("Gist updated: %s\n", result.GistURL)
		}
	}

	// Set GitHub Actions outputs (use gist badge URL when available)
	if err := setOutputs(stats, output, jsonOutputPath, scanMode, reportURL, gistBadgeURL); err != nil {
		return fmt.Errorf("failed to set outputs: %w", err)
	}

	// Print compact summary
	printSummary(stats, output)

	// Check if build should fail due to vulnerabilities
	if config.FailBuild && shouldFail(stats, config.SeverityCutoff) {
		return fmt.Errorf("vulnerabilities found at or above %s severity", config.SeverityCutoff)
	}

	return nil
}
