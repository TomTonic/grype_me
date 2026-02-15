package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCopyOutputFile(t *testing.T) {
	srcDir := t.TempDir()
	srcFile := filepath.Join(srcDir, "source.json")
	content := []byte(`{"test": "data"}`)
	if err := os.WriteFile(srcFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	dstDir := t.TempDir()
	dstFile := filepath.Join(dstDir, "dest.json")

	result, err := copyOutputFile(srcFile, dstFile)
	if err != nil {
		t.Fatalf("copyOutputFile() error = %v", err)
	}

	copied, err := os.ReadFile(result)
	if err != nil {
		t.Fatalf("Failed to read copied file: %v", err)
	}
	if string(copied) != string(content) {
		t.Errorf("copied content = %v, want %v", string(copied), string(content))
	}
}

func TestValidatePathInWorkspace(t *testing.T) {
	workspace := "/workspace"

	tests := []struct {
		name    string
		dst     string
		wantErr bool
	}{
		{"valid path", "/workspace/output.json", false},
		{"valid nested path", "/workspace/subdir/output.json", false},
		{"path traversal", "/workspace/../etc/passwd", true},
		{"outside workspace", "/other/path", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePathInWorkspace(tt.dst, workspace)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePathInWorkspace() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateBadgeURL(t *testing.T) {
	tests := []struct {
		name     string
		stats    VulnerabilityStats
		label    string
		dbBuilt  string
		scanMode string
		contains []string
	}{
		{
			name:     "no vulnerabilities",
			stats:    VulnerabilityStats{Total: 0},
			label:    "✊ grype 0.87.0",
			dbBuilt:  "2026-01-30T12:34:56Z",
			scanMode: "release",
			contains: []string{"https://img.shields.io/badge/", "0%20CVEs%20in%20release", "brightgreen"},
		},
		{
			name:     "critical vulnerabilities",
			stats:    VulnerabilityStats{Total: 2, Critical: 2},
			label:    "✊ grype 0.87.0",
			dbBuilt:  "2026-01-30",
			scanMode: "image",
			contains: []string{"2%20critical%20CVEs%20in%20image", "critical"},
		},
		{
			name:     "high vulnerabilities",
			stats:    VulnerabilityStats{Total: 3, High: 3},
			label:    "✊ grype 0.87.0",
			dbBuilt:  "2026-01-30",
			scanMode: "head",
			contains: []string{"high", "orange", "head"},
		},
		{
			name:     "medium vulnerabilities no db",
			stats:    VulnerabilityStats{Total: 5, Medium: 5},
			label:    "✊ grype 0.87.0",
			dbBuilt:  "",
			scanMode: "path",
			contains: []string{"medium", "yellow", "path"},
		},
		{
			name:     "low vulnerabilities",
			stats:    VulnerabilityStats{Total: 10, Low: 10},
			label:    "✊ grype 0.87.0",
			dbBuilt:  "2026-01-30",
			scanMode: "release",
			contains: []string{"low", "yellowgreen"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateBadgeURL(tt.stats, tt.label, tt.dbBuilt, tt.scanMode)
			for _, substr := range tt.contains {
				if !strings.Contains(got, substr) {
					t.Errorf("generateBadgeURL() = %v, want to contain %q", got, substr)
				}
			}
		})
	}
}

func TestFormatBadgeMessage(t *testing.T) {
	tests := []struct {
		name  string
		stats VulnerabilityStats
		want  string
	}{
		{"no vulnerabilities", VulnerabilityStats{Total: 0}, "0"},
		{"only critical", VulnerabilityStats{Total: 2, Critical: 2}, "2 critical"},
		{"only high", VulnerabilityStats{Total: 3, High: 3}, "3 high"},
		{"critical and high", VulnerabilityStats{Total: 5, Critical: 2, High: 3}, "2 critical | 3 high"},
		{"all severities", VulnerabilityStats{Total: 10, Critical: 1, High: 2, Medium: 3, Low: 4}, "1 critical | 2 high | 3 medium | 4 low"},
		{"only other", VulnerabilityStats{Total: 5, Other: 5}, "5 other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatBadgeMessage(tt.stats)
			if got != tt.want {
				t.Errorf("formatBadgeMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetermineBadgeColor(t *testing.T) {
	tests := []struct {
		name  string
		stats VulnerabilityStats
		want  string
	}{
		{"no vulnerabilities", VulnerabilityStats{Total: 0}, "brightgreen"},
		{"critical", VulnerabilityStats{Critical: 1}, "critical"},
		{"high", VulnerabilityStats{High: 1}, "orange"},
		{"medium", VulnerabilityStats{Medium: 1}, "yellow"},
		{"low", VulnerabilityStats{Low: 1}, "yellowgreen"},
		{"other", VulnerabilityStats{Other: 1}, "yellowgreen"},
		{"critical takes precedence", VulnerabilityStats{Critical: 1, High: 2, Medium: 3, Low: 4}, "critical"},
		{"high takes precedence over medium", VulnerabilityStats{High: 1, Medium: 2, Low: 3}, "orange"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineBadgeColor(tt.stats)
			if got != tt.want {
				t.Errorf("determineBadgeColor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildBadgeLabel(t *testing.T) {
	tests := []struct {
		grypeVersion string
		want         string
	}{
		{"0.87.0", "✊ grype 0.87.0"},
		{"0.106.0", "✊ grype 0.106.0"},
		{"1.0.0", "✊ grype 1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.grypeVersion, func(t *testing.T) {
			got := buildBadgeLabel(tt.grypeVersion)
			if got != tt.want {
				t.Errorf("buildBadgeLabel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractDBDate(t *testing.T) {
	tests := []struct {
		timestamp string
		want      string
	}{
		{"2026-01-30T12:34:56Z", "2026-01-30"},
		{"2026-01-30", "2026-01-30"},
		{"2026-01", "2026-01"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.timestamp, func(t *testing.T) {
			got := extractDBDate(tt.timestamp)
			if got != tt.want {
				t.Errorf("extractDBDate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateBadgeJSON(t *testing.T) {
	tests := []struct {
		name     string
		stats    VulnerabilityStats
		version  string
		dbBuilt  string
		scanMode string
		contains []string
	}{
		{
			name:     "no vulnerabilities",
			stats:    VulnerabilityStats{Total: 0},
			version:  "0.87.0",
			dbBuilt:  "2026-01-30T12:00:00Z",
			scanMode: "release",
			contains: []string{`"schemaVersion":1`, `grype 0.87.0`, `0 CVEs in release`, `brightgreen`, `db 2026-01-30`},
		},
		{
			name:     "critical vulnerabilities",
			stats:    VulnerabilityStats{Total: 3, Critical: 3},
			version:  "0.106.0",
			dbBuilt:  "2026-02-15",
			scanMode: "image",
			contains: []string{`3 critical CVEs in image`, `critical`, `grype 0.106.0`},
		},
		{
			name:     "no db date",
			stats:    VulnerabilityStats{Total: 1, High: 1},
			version:  "0.87.0",
			dbBuilt:  "",
			scanMode: "head",
			contains: []string{`1 high CVEs in head`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateBadgeJSON(tt.stats, tt.version, tt.dbBuilt, tt.scanMode)
			for _, substr := range tt.contains {
				if !strings.Contains(got, substr) {
					t.Errorf("generateBadgeJSON() = %v, want to contain %q", got, substr)
				}
			}
		})
	}
}

func TestGenerateReport(t *testing.T) {
	output := &GrypeOutput{
		Matches: []GrypeMatch{
			makeMatch("CVE-2024-0001", "Critical", "openssl", "1.1.1", []string{"1.1.2"}, "Buffer overflow in...", "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"),
			makeMatch("CVE-2024-0002", "High", "curl", "7.80.0", nil, "HTTP redirect issue", ""),
			makeMatch("CVE-2024-0003", "Low", "zlib", "1.2.11", []string{"1.2.13"}, "", "https://nvd.nist.gov/vuln/detail/CVE-2024-0003"),
		},
	}
	output.Descriptor.Version = "0.87.0"
	output.Descriptor.DB.Status.Built = "2026-02-15T08:00:00Z"

	stats := VulnerabilityStats{Total: 3, Critical: 1, High: 1, Low: 1}
	fixedTime := time.Date(2026, 2, 15, 10, 30, 0, 0, time.UTC)
	report := generateReportAt(output, stats, "release", fixedTime)

	checks := []struct {
		desc string
		want string
	}{
		{"grype version header", "# ✊ grype 0.87.0"},
		{"scan mode", "**Scan mode:** release"},
		{"DB version", "**DB version:** 2026-02-15"},
		{"scan timestamp", "2026-02-15 10:30 UTC"},
		{"critical count", "| Critical | 1 |"},
		{"total count", "| **Total** | **3** |"},
		{"CVE ID", "CVE-2024-0001"},
		{"package name", "openssl"},
		{"fix version", "1.1.2"},
		{"data source link", "[link](https://nvd.nist.gov"},
		{"missing fix dash", "—"},
	}

	for _, c := range checks {
		if !strings.Contains(report, c.want) {
			t.Errorf("report missing %s: want %q in report", c.desc, c.want)
		}
	}

	// Check sorting: Critical before High before Low
	critIdx := strings.Index(report, "CVE-2024-0001")
	highIdx := strings.Index(report, "CVE-2024-0002")
	lowIdx := strings.Index(report, "CVE-2024-0003")
	if critIdx > highIdx || highIdx > lowIdx {
		t.Error("CVEs should be sorted by severity (critical first)")
	}
}

func TestGenerateReport_NoVulnerabilities(t *testing.T) {
	output := &GrypeOutput{Matches: []GrypeMatch{}}
	output.Descriptor.Version = "0.87.0"
	output.Descriptor.DB.Status.Built = "2026-02-15T08:00:00Z"

	stats := VulnerabilityStats{Total: 0}
	fixedTime := time.Date(2026, 2, 15, 10, 30, 0, 0, time.UTC)
	report := generateReportAt(output, stats, "head", fixedTime)

	if !strings.Contains(report, "No vulnerabilities found") {
		t.Error("report should indicate no vulnerabilities")
	}
	if strings.Contains(report, "| CVE |") {
		t.Error("report should not contain CVE table when no vulns")
	}
}

func TestSortMatches(t *testing.T) {
	matches := []GrypeMatch{
		makeMatch("CVE-0003", "Low", "pkg3", "1.0", nil, "", ""),
		makeMatch("CVE-0001", "Critical", "pkg1", "1.0", nil, "", ""),
		makeMatch("CVE-0002", "High", "pkg2", "1.0", nil, "", ""),
		makeMatch("CVE-0004", "Critical", "pkg4", "1.0", nil, "", ""),
	}

	sorted := sortMatches(matches)

	expectedOrder := []string{"CVE-0001", "CVE-0004", "CVE-0002", "CVE-0003"}
	for i, expected := range expectedOrder {
		if sorted[i].Vulnerability.ID != expected {
			t.Errorf("sorted[%d].ID = %q, want %q", i, sorted[i].Vulnerability.ID, expected)
		}
	}
	if matches[0].Vulnerability.ID != "CVE-0003" {
		t.Error("sortMatches should not modify the original slice")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is too long", 10, "this is t…"},
		{"", 10, ""},
		{"ab", 1, "…"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := truncate(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestEscapeJSON(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`hello`, `hello`},
		{`say "hi"`, `say \"hi\"`},
		{"line1\nline2", `line1\nline2`},
		{`back\slash`, `back\\slash`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeJSON(tt.input)
			if got != tt.want {
				t.Errorf("escapeJSON(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// makeMatch is a test helper to create a GrypeMatch with all fields populated.
func makeMatch(id, severity, pkg, version string, fixVersions []string, description, dataSource string) GrypeMatch {
	m := GrypeMatch{}
	m.Vulnerability.ID = id
	m.Vulnerability.Severity = severity
	m.Vulnerability.Description = description
	m.Vulnerability.DataSource = dataSource
	m.Vulnerability.Fix.Versions = fixVersions
	if len(fixVersions) > 0 {
		m.Vulnerability.Fix.State = "fixed"
	}
	m.Artifact.Name = pkg
	m.Artifact.Version = version
	return m
}
