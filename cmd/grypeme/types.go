// Package main provides types and structures for the Grype vulnerability scanner GitHub Action.
package main

// GrypeMatch represents a single vulnerability match found by Grype.
// It contains information about the vulnerability, the affected package, and fix availability.
type GrypeMatch struct {
	Vulnerability struct {
		ID          string `json:"id"`          // CVE or vulnerability identifier (e.g., "CVE-2023-12345")
		Severity    string `json:"severity"`    // Severity level: critical, high, medium, low, or negligible
		Description string `json:"description"` // Human-readable description of the vulnerability
		DataSource  string `json:"dataSource"`  // URL to the vulnerability data source (e.g., NVD)
		Fix         struct {
			Versions []string `json:"versions"` // Versions that fix this vulnerability
			State    string   `json:"state"`    // Fix state: "fixed", "not-fixed", "wont-fix", or "unknown"
		} `json:"fix"`
	} `json:"vulnerability"`
	Artifact struct {
		Name    string `json:"name"`    // Package name (e.g., "openssl", "lodash")
		Version string `json:"version"` // Installed version of the package
		Type    string `json:"type"`    // Package type (e.g., "go-module", "npm", "deb")
	} `json:"artifact"`
}

// GrypeOutput represents the complete JSON output from a Grype scan.
// It contains all vulnerability matches and metadata about the Grype version and database.
type GrypeOutput struct {
	Matches    []GrypeMatch `json:"matches"` // List of all vulnerability matches
	Descriptor struct {
		Version string `json:"version"` // Grype version used for the scan
		DB      struct {
			// Built contains the database build timestamp for older Grype versions (< 0.106).
			// Format: RFC3339 (e.g., "2026-01-30T12:34:56Z")
			Built string `json:"built,omitempty"`
			// Status contains database metadata for newer Grype versions (>= 0.106).
			Status struct {
				Built string `json:"built,omitempty"` // Database build timestamp
			} `json:"status,omitempty"`
		} `json:"db"`
	} `json:"descriptor"`
}

// DBBuilt returns the database build timestamp, handling both old and new Grype output formats.
// Returns an empty string if no build timestamp is available.
func (o *GrypeOutput) DBBuilt() string {
	if o == nil {
		return ""
	}
	// Prefer new format (status.built) over old format (built)
	if built := o.Descriptor.DB.Status.Built; built != "" {
		return built
	}
	return o.Descriptor.DB.Built
}

// Config holds all configuration options for the GitHub Action.
// Values are typically loaded from environment variables (INPUT_* prefix).
type Config struct {
	// Scan modes - these are mutually exclusive with artifact modes
	// Scan specifies the repository scan mode: "latest_release", "head", or a specific tag/branch name
	Scan string

	// Artifact modes - mutually exclusive with each other and with Scan
	Image string // Container image reference to scan (e.g., "alpine:latest")
	Path  string // Local directory or file path to scan
	SBOM  string // Path to an SBOM file to scan (CycloneDX, SPDX, or Syft formats)

	// Scan behavior options
	FailBuild      bool   // If true, exit with error when vulnerabilities exceed severity cutoff
	SeverityCutoff string // Minimum severity to trigger fail-build: critical, high, medium, low, negligible
	OutputFile     string // Path to save the JSON scan results
	OnlyFixed      bool   // If true, only report vulnerabilities that have fixes available
	DBUpdate       bool   // If true, update the Grype vulnerability database before scanning
	Debug          bool   // If true, print debug information including environment variables
	Description    string // Optional free-text description included verbatim in the Markdown report

	// Gist integration (optional)
	GistToken    string // GitHub token with gist scope for writing badge + report to a gist
	GistID       string // ID of the gist to update
	GistFilename string // Base filename for gist files (default: auto-generated from scan mode)
}

// VulnerabilityStats contains aggregated vulnerability counts by severity level.
// Used for generating summaries, badges, and determining fail-build conditions.
type VulnerabilityStats struct {
	Total    int // Total number of vulnerabilities found
	Critical int // Count of critical severity vulnerabilities
	High     int // Count of high severity vulnerabilities
	Medium   int // Count of medium severity vulnerabilities
	Low      int // Count of low severity vulnerabilities
	Other    int // Count of vulnerabilities with unknown/other severity levels
}
