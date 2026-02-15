// Package main provides output handling for the Grype GitHub Action.
// This includes GitHub Actions outputs, file copying, badge generation, and Markdown reports.
package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// setOutputs writes scan results to GitHub Actions step outputs.
// It generates a badge URL and writes core outputs (counts, versions, badge URL).
// When gistBadgeURL is non-empty, it is used instead of the static badge URL.
func setOutputs(stats VulnerabilityStats, output *GrypeOutput, jsonPath, scanMode string, reportURL, gistBadgeURL string) error {
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

	// Use gist endpoint badge URL when available, otherwise fall back to static URL
	badgeURL := gistBadgeURL
	if badgeURL == "" {
		label := buildBadgeLabel(output.Descriptor.Version)
		badgeURL = generateBadgeURL(stats, label, output.DBBuilt(), scanMode)
	}

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
	if reportURL != "" {
		outputs["report-url"] = reportURL
	}

	for key, value := range outputs {
		if _, err := fmt.Fprintf(outputFile, "%s=%s\n", key, value); err != nil {
			return fmt.Errorf("failed to write output %s: %w", key, err)
		}
	}

	return nil
}

// printSummary prints a compact one-line summary of the scan results to stdout.
func printSummary(stats VulnerabilityStats, output *GrypeOutput) {
	msg := formatBadgeMessage(stats)
	fmt.Printf("✊ grype %s | db %s | %s CVEs\n",
		output.Descriptor.Version,
		extractDBDate(output.DBBuilt()),
		msg)
}

// buildBadgeLabel creates the badge label with the Grype version.
// Format: "✊ grype <version>" (e.g., "✊ grype 0.87.0").
func buildBadgeLabel(grypeVersion string) string {
	return fmt.Sprintf("✊ grype %s", grypeVersion)
}

// extractDBDate extracts the date portion (YYYY-MM-DD) from a timestamp.
// Expected input format: RFC3339 (e.g., "2026-01-30T12:34:56Z").
func extractDBDate(timestamp string) string {
	if len(timestamp) >= 10 {
		return timestamp[:10]
	}
	return timestamp
}

// generateBadgeURL creates a shields.io badge URL based on scan statistics.
// Label: "✊ grype <version>", Message: "db <date>: <counts> CVEs in <scanMode>".
// Colors indicate the highest severity found.
func generateBadgeURL(stats VulnerabilityStats, label, dbBuilt, scanMode string) string {
	counts := formatBadgeMessage(stats)

	message := fmt.Sprintf("%s CVEs in %s", counts, scanMode)
	if dbBuilt != "" {
		if dbDate := extractDBDate(dbBuilt); dbDate != "" {
			dbDate = strings.ReplaceAll(dbDate, "-", "--") // Escape dashes for shields.io
			message = fmt.Sprintf("db %s: %s", dbDate, message)
		}
	}

	color := determineBadgeColor(stats)

	// shields.io static badge format: https://img.shields.io/badge/{label}-{message}-{color}
	encodedLabel := url.PathEscape(label)
	encodedMessage := url.PathEscape(message)

	return fmt.Sprintf("https://img.shields.io/badge/%s-%s-%s", encodedLabel, encodedMessage, color)
}

// formatBadgeMessage creates the count portion of the badge message.
// Returns "0" if no vulnerabilities, otherwise severity counts like "3 critical | 1 high".
func formatBadgeMessage(stats VulnerabilityStats) string {
	if stats.Total == 0 {
		return "0"
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
	if len(parts) == 0 && stats.Other > 0 {
		parts = append(parts, fmt.Sprintf("%d other", stats.Other))
	}

	return strings.Join(parts, " | ")
}

// determineBadgeColor returns the shields.io badge color based on the highest severity found.
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

// generateBadgeJSON creates a shields.io endpoint badge JSON for use with gists.
// This JSON is consumed by shields.io/endpoint to render a dynamic badge.
func generateBadgeJSON(stats VulnerabilityStats, grypeVersion, dbBuilt, scanMode string) string {
	label := buildBadgeLabel(grypeVersion)
	counts := formatBadgeMessage(stats)
	message := fmt.Sprintf("%s CVEs in %s", counts, scanMode)
	if dbBuilt != "" {
		if dbDate := extractDBDate(dbBuilt); dbDate != "" {
			message = fmt.Sprintf("db %s: %s", dbDate, message)
		}
	}
	color := determineBadgeColor(stats)

	// Minimal JSON without external dependencies
	return fmt.Sprintf(`{"schemaVersion":1,"label":"%s","message":"%s","color":"%s"}`,
		escapeJSON(label), escapeJSON(message), escapeJSON(color))
}

// generateReport creates a Markdown vulnerability report suitable for storing in a gist.
// Includes a summary table and a detailed CVE table with package info, fix versions, and data source links.
func generateReport(output *GrypeOutput, stats VulnerabilityStats, scanMode string) string {
	return generateReportAt(output, stats, scanMode, time.Now().UTC())
}

// generateReportAt creates a Markdown report with a specific timestamp (for testability).
func generateReportAt(output *GrypeOutput, stats VulnerabilityStats, scanMode string, now time.Time) string {
	var b strings.Builder

	grypeVersion := output.Descriptor.Version
	dbDate := extractDBDate(output.DBBuilt())

	b.WriteString(fmt.Sprintf("# ✊ grype %s — Vulnerability Scan Report\n\n", grypeVersion))
	b.WriteString(fmt.Sprintf("**Scan mode:** %s  \n", scanMode))
	b.WriteString(fmt.Sprintf("**DB version:** %s  \n", dbDate))
	b.WriteString(fmt.Sprintf("**Scanned:** %s  \n", now.Format("2006-01-02 15:04 UTC")))
	b.WriteString(fmt.Sprintf("**Total CVEs:** %d\n\n", stats.Total))

	// Summary table
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|----------|------:|\n")
	b.WriteString(fmt.Sprintf("| Critical | %d |\n", stats.Critical))
	b.WriteString(fmt.Sprintf("| High | %d |\n", stats.High))
	b.WriteString(fmt.Sprintf("| Medium | %d |\n", stats.Medium))
	b.WriteString(fmt.Sprintf("| Low | %d |\n", stats.Low))
	if stats.Other > 0 {
		b.WriteString(fmt.Sprintf("| Other | %d |\n", stats.Other))
	}
	b.WriteString(fmt.Sprintf("| **Total** | **%d** |\n", stats.Total))

	// Detailed CVE table (only if vulnerabilities found)
	if stats.Total > 0 {
		b.WriteString("\n## Vulnerabilities\n\n")
		b.WriteString("| CVE | Severity | Package | Installed | Fixed | Description | Source |\n")
		b.WriteString("|-----|----------|---------|-----------|-------|-------------|--------|\n")

		sorted := sortMatches(output.Matches)
		for _, m := range sorted {
			fixed := strings.Join(m.Vulnerability.Fix.Versions, ", ")
			if fixed == "" {
				fixed = "—"
			}
			desc := truncate(m.Vulnerability.Description, 80)
			source := ""
			if m.Vulnerability.DataSource != "" {
				source = fmt.Sprintf("[link](%s)", m.Vulnerability.DataSource)
			}
			b.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n",
				m.Vulnerability.ID,
				m.Vulnerability.Severity,
				m.Artifact.Name,
				m.Artifact.Version,
				fixed,
				desc,
				source))
		}
	} else {
		b.WriteString("\n✅ No vulnerabilities found.\n")
	}

	b.WriteString("\n---\n*Generated by [grype_me](https://github.com/TomTonic/grype_me)*\n")

	return b.String()
}

// sortMatches returns a copy of matches sorted by severity (critical first), then by CVE ID.
func sortMatches(matches []GrypeMatch) []GrypeMatch {
	sorted := make([]GrypeMatch, len(matches))
	copy(sorted, matches)
	sort.Slice(sorted, func(i, j int) bool {
		si := severityOrder(sorted[i].Vulnerability.Severity)
		sj := severityOrder(sorted[j].Vulnerability.Severity)
		if si != sj {
			return si < sj
		}
		return sorted[i].Vulnerability.ID < sorted[j].Vulnerability.ID
	})
	return sorted
}

// severityOrder returns a numeric order for severity (lower = more severe).
func severityOrder(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// truncate shortens a string to maxLen characters, appending "…" if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return "…"
	}
	return s[:maxLen-1] + "…"
}

// escapeJSON escapes a string for embedding in a JSON value.
func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
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

	if workspace != "" {
		if err := validatePathInWorkspace(resolvedDest, workspace); err != nil {
			return "", err
		}
	}

	if err := os.MkdirAll(filepath.Dir(resolvedDest), 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("failed to read source: %w", err)
	}

	if err := os.WriteFile(resolvedDest, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write destination: %w", err)
	}

	return resolvedDest, nil
}

// resolveDestinationPath converts a relative path to an absolute path.
// It uses the GitHub workspace directory if available.
func resolveDestinationPath(destPath string) (string, string) {
	if filepath.IsAbs(destPath) {
		return destPath, ""
	}

	if _, err := os.Stat("/github/workspace"); err == nil {
		return filepath.Join("/github/workspace", destPath), "/github/workspace"
	}

	if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" {
		return filepath.Join(workspace, destPath), workspace
	}

	absPath, err := filepath.Abs(destPath)
	if err != nil {
		return destPath, ""
	}
	return absPath, ""
}
