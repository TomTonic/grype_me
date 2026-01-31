// Package main provides Grype scanning functionality.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// determineScanTarget figures out what to scan based on the configuration inputs.
// It validates that only one scan mode is specified and returns the appropriate
// Grype target string along with any temporary directory that was created.
//
// Returns:
//   - target: The Grype scan target (e.g., "alpine:latest", "dir:/path", "sbom:file.json")
//   - tempDir: Path to temporary worktree (empty if none created, caller must clean up)
//   - error: Any error encountered during target determination
func determineScanTarget(config Config) (string, string, error) {
	// Validate mutually exclusive artifact modes
	if err := validateArtifactModes(config); err != nil {
		return "", "", err
	}

	// Handle artifact-based scanning (image, path, sbom)
	target, err := getArtifactTarget(config)
	if err != nil {
		return "", "", err
	}
	if target != "" {
		return target, "", nil
	}

	// Handle repository-based scanning (default mode)
	scanMode := strings.TrimSpace(config.Scan)
	if scanMode == "" {
		scanMode = "latest_release"
	}

	return handleRepoScan(scanMode)
}

// validateArtifactModes checks that only one artifact mode is specified
// and that artifact modes are not combined with repository scan mode.
func validateArtifactModes(config Config) error {
	artifactModeCount := countNonEmpty(config.Image, config.Path, config.SBOM)

	if artifactModeCount > 1 {
		return fmt.Errorf("only one of image, path, or sbom can be specified")
	}

	if artifactModeCount > 0 && config.Scan != "" {
		return fmt.Errorf("scan cannot be used together with image, path, or sbom")
	}

	return nil
}

// countNonEmpty returns the count of non-empty strings in the given arguments.
func countNonEmpty(values ...string) int {
	count := 0
	for _, v := range values {
		if v != "" {
			count++
		}
	}
	return count
}

// getArtifactTarget returns the Grype target string for artifact-based scanning.
// Returns (target, error) where target is empty if no artifact mode is configured.
func getArtifactTarget(config Config) (string, error) {
	if config.Image != "" {
		return config.Image, nil
	}

	if config.Path != "" {
		target, err := buildPathTarget(config.Path)
		if err != nil {
			return "", err
		}
		return target, nil
	}

	if config.SBOM != "" {
		return "sbom:" + config.SBOM, nil
	}

	return "", nil
}

// buildPathTarget creates the appropriate Grype target string for a path.
// Grype uses "dir:" prefix for directories and "file:" for files.
// Returns an error if the path does not exist.
func buildPathTarget(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("path %q not found: %w", path, err)
	}

	if info.IsDir() {
		return "dir:" + path, nil
	}
	return "file:" + path, nil
}

// updateGrypeDB updates the Grype vulnerability database.
// This ensures the scan uses the latest vulnerability data.
func updateGrypeDB() error {
	fmt.Println("Updating Grype vulnerability database...")

	cmd := exec.Command("grype", "db", "update")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("grype db update failed: %w", err)
	}

	fmt.Println("Database update complete")
	return nil
}

// runGrypeScan executes the Grype vulnerability scan and writes results to outputPath.
// The scan is configured based on the provided Config options.
func runGrypeScan(config Config, target, outputPath string) error {
	fmt.Printf("Running grype scan...\n")

	args := buildGrypeArgs(target, outputPath, config)

	cmd := exec.Command("grype", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		// Grype returns non-zero exit code when vulnerabilities are found.
		// Check if output file was created to distinguish from actual errors.
		if _, statErr := os.Stat(outputPath); statErr == nil {
			fmt.Println("Grype scan completed (vulnerabilities found)")
			return nil
		}
		return err
	}

	fmt.Println("Grype scan completed")
	return nil
}

// buildGrypeArgs constructs the command-line arguments for the Grype scan.
func buildGrypeArgs(target, outputPath string, config Config) []string {
	args := []string{target, "-o", "json", "--file", outputPath}

	if config.OnlyFixed {
		args = append(args, "--only-fixed")
	}

	return args
}

// parseGrypeOutput reads and parses the JSON output file from a Grype scan.
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

// calculateStats aggregates vulnerability counts by severity level from scan output.
func calculateStats(output *GrypeOutput) VulnerabilityStats {
	stats := VulnerabilityStats{}

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

// shouldFail determines if the build should fail based on vulnerability stats and severity cutoff.
// Returns true if any vulnerabilities at or above the cutoff severity are found.
func shouldFail(stats VulnerabilityStats, cutoff string) bool {
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
		// Default to medium if cutoff is unknown
		return stats.Critical > 0 || stats.High > 0 || stats.Medium > 0
	}
}
