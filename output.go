// Package main provides output handling for the Grype GitHub Action.
// This includes GitHub Actions outputs, environment variables, file copying, and badge generation.
package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// setOutputs writes scan results to GitHub Actions outputs and environment variables.
// Outputs are written to GITHUB_OUTPUT file, and environment variables (with custom prefix)
// are written to GITHUB_ENV file.
func setOutputs(prefix string, stats VulnerabilityStats, output *GrypeOutput, jsonPath, badgeLabel, scanMode string) error {
	githubOutput := os.Getenv("GITHUB_OUTPUT")
	if githubOutput == "" {
		fmt.Println("Warning: GITHUB_OUTPUT not set, skipping output generation")
		return nil
	}

	outputFile, err := os.OpenFile(githubOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open GITHUB_OUTPUT: %w", err)
	}
	defer func() { _ = outputFile.Close() }()

	// Generate badge URL with auto-generated label if not provided
	label := badgeLabel
	if label == "" {
		label = buildBadgeLabel(scanMode)
	}
	badgeURL := generateBadgeURL(stats, label, output.DBBuilt())

	// Write GitHub Actions step outputs
	if err := writeStepOutputs(outputFile, stats, output, jsonPath, badgeURL); err != nil {
		return err
	}

	// Write prefixed environment variables
	return writeEnvironmentVariables(prefix, stats, output, badgeURL)
}

// writeStepOutputs writes the scan results to GitHub Actions step outputs.
func writeStepOutputs(file *os.File, stats VulnerabilityStats, output *GrypeOutput, jsonPath, badgeURL string) error {
	outputs := map[string]string{
		"grype-version": output.Descriptor.Version,
		"db-version":    output.DBBuilt(),
		"cve-count":     fmt.Sprintf("%d", stats.Total),
		"critical":      fmt.Sprintf("%d", stats.Critical),
		"high":          fmt.Sprintf("%d", stats.High),
		"medium":        fmt.Sprintf("%d", stats.Medium),
		"low":           fmt.Sprintf("%d", stats.Low),
		"badge-url":     badgeURL,
	}

	if jsonPath != "" {
		outputs["json-output"] = jsonPath
	}

	for key, value := range outputs {
		if _, err := fmt.Fprintf(file, "%s=%s\n", key, value); err != nil {
			return fmt.Errorf("failed to write output %s: %w", key, err)
		}
	}

	return nil
}

// writeEnvironmentVariables writes scan results to GITHUB_ENV with the configured prefix.
func writeEnvironmentVariables(prefix string, stats VulnerabilityStats, output *GrypeOutput, badgeURL string) error {
	githubEnv := os.Getenv("GITHUB_ENV")
	if githubEnv == "" {
		return nil // Not in GitHub Actions environment
	}

	envFile, err := os.OpenFile(githubEnv, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open GITHUB_ENV: %w", err)
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
		"BADGE_URL":  badgeURL,
	}

	for key, value := range envVars {
		if _, err := fmt.Fprintf(envFile, "%s%s=%s\n", prefix, key, value); err != nil {
			return fmt.Errorf("failed to write env var %s: %w", key, err)
		}
	}

	return nil
}

// printSummary prints a human-readable summary of the scan results to stdout.
func printSummary(stats VulnerabilityStats, output *GrypeOutput) {
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

// validatePathInWorkspace ensures the destination path is within the workspace directory.
// This prevents path traversal attacks (e.g., "../../../etc/passwd").
func validatePathInWorkspace(destPath, workspace string) error {
	absDest, err := filepath.Abs(filepath.Clean(destPath))
	if err != nil {
		return fmt.Errorf("failed to resolve destination: %w", err)
	}

	absWorkspace, err := filepath.Abs(filepath.Clean(workspace))
	if err != nil {
		return fmt.Errorf("failed to resolve workspace: %w", err)
	}

	relPath, err := filepath.Rel(absWorkspace, absDest)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}

	if strings.HasPrefix(relPath, ".."+string(filepath.Separator)) || relPath == ".." {
		return fmt.Errorf("path traversal detected: %q is outside workspace", destPath)
	}

	return nil
}

// copyOutputFile copies the scan results from a temporary file to the user-specified location.
// It handles relative paths by resolving them against the GitHub workspace.
// Returns the absolute path to the copied file.
func copyOutputFile(srcPath, destPath string) (string, error) {
	resolvedDest, workspace := resolveDestinationPath(destPath)

	// Validate path is within workspace to prevent path traversal
	if workspace != "" {
		if err := validatePathInWorkspace(resolvedDest, workspace); err != nil {
			return "", err
		}
	}

	// Create parent directories if they don't exist
	if err := os.MkdirAll(filepath.Dir(resolvedDest), 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	// Read source file
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("failed to read source: %w", err)
	}

	// Write to destination
	if err := os.WriteFile(resolvedDest, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write destination: %w", err)
	}

	return resolvedDest, nil
}

// resolveDestinationPath converts a relative path to an absolute path.
// It uses the GitHub workspace directory if available.
// Returns (resolvedPath, workspaceUsed) where workspaceUsed is the workspace path if used.
func resolveDestinationPath(destPath string) (string, string) {
	if filepath.IsAbs(destPath) {
		return destPath, ""
	}

	// Try /github/workspace first (Docker environment)
	if _, err := os.Stat("/github/workspace"); err == nil {
		return filepath.Join("/github/workspace", destPath), "/github/workspace"
	}

	// Try GITHUB_WORKSPACE environment variable
	if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" {
		return filepath.Join(workspace, destPath), workspace
	}

	// Fall back to current working directory
	absPath, err := filepath.Abs(destPath)
	if err != nil {
		return destPath, ""
	}
	return absPath, ""
}

// buildBadgeLabel creates a badge label based on the scan mode.
// Format: "grype scan <mode>" (e.g., "grype scan release")
func buildBadgeLabel(scanMode string) string {
	return fmt.Sprintf("grype scan %s", scanMode)
}

// extractDBDate extracts the date portion (YYYY-MM-DD) from a timestamp.
// Expected input format: RFC3339 (e.g., "2026-01-30T12:34:56Z")
func extractDBDate(timestamp string) string {
	if len(timestamp) >= 10 {
		return timestamp[:10]
	}
	return timestamp
}

// generateBadgeURL creates a shields.io badge URL based on scan statistics.
// The badge displays vulnerability counts with colors indicating severity:
//   - Green: No vulnerabilities
//   - Yellow-green: Only low severity
//   - Yellow: Medium severity present
//   - Orange: High severity present
//   - Red: Critical severity present
func generateBadgeURL(stats VulnerabilityStats, label, dbBuilt string) string {
	message := formatBadgeMessage(stats)

	// Append database build date to the message
	if dbBuilt != "" {
		if dbDate := extractDBDate(dbBuilt); dbDate != "" {
			message = fmt.Sprintf("%s (db build %s)", message, dbDate)
		}
	}

	color := determineBadgeColor(stats)

	// shields.io static badge format: https://img.shields.io/badge/{label}-{message}-{color}
	encodedLabel := url.PathEscape(label)
	encodedMessage := url.PathEscape(message)

	return fmt.Sprintf("https://img.shields.io/badge/%s-%s-%s", encodedLabel, encodedMessage, color)
}

// formatBadgeMessage creates the message portion of the badge.
// Shows "none" if no vulnerabilities, otherwise shows counts by severity level.
func formatBadgeMessage(stats VulnerabilityStats) string {
	if stats.Total == 0 {
		return "none"
	}

	var parts []string

	if stats.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", stats.Critical))
	}
	if stats.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", stats.High))
	}
	if stats.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", stats.Medium))
	}
	if stats.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", stats.Low))
	}

	// Handle case where only "other" severities exist
	if len(parts) == 0 && stats.Other > 0 {
		parts = append(parts, fmt.Sprintf("%d other", stats.Other))
	}

	return strings.Join(parts, " | ")
}

// determineBadgeColor returns the shields.io badge color based on the highest severity found.
// Uses a traffic light color scheme for intuitive visual interpretation.
func determineBadgeColor(stats VulnerabilityStats) string {
	switch {
	case stats.Critical > 0:
		return "critical" // Red
	case stats.High > 0:
		return "orange"
	case stats.Medium > 0:
		return "yellow"
	case stats.Low > 0 || stats.Other > 0:
		return "yellowgreen"
	default:
		return "brightgreen"
	}
}
