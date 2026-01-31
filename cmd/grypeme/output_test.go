package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		contains []string
	}{
		{
			name:     "no vulnerabilities with DB date",
			stats:    VulnerabilityStats{Total: 0},
			label:    "grype scan release",
			dbBuilt:  "2026-01-30T12:34:56Z",
			contains: []string{"https://img.shields.io/badge/", "grype%20scan%20release", "none", "brightgreen"},
		},
		{
			name:     "critical vulnerabilities",
			stats:    VulnerabilityStats{Total: 2, Critical: 2},
			label:    "grype scan image",
			dbBuilt:  "2026-01-30",
			contains: []string{"https://img.shields.io/badge/", "critical"},
		},
		{
			name:     "high vulnerabilities",
			stats:    VulnerabilityStats{Total: 3, High: 3},
			label:    "security",
			dbBuilt:  "2026-01-30",
			contains: []string{"https://img.shields.io/badge/", "security", "high", "orange"},
		},
		{
			name:     "medium vulnerabilities",
			stats:    VulnerabilityStats{Total: 5, Medium: 5},
			label:    "CVEs",
			dbBuilt:  "",
			contains: []string{"https://img.shields.io/badge/", "CVEs", "medium", "yellow"},
		},
		{
			name:     "low vulnerabilities",
			stats:    VulnerabilityStats{Total: 10, Low: 10},
			label:    "scan results",
			dbBuilt:  "2026-01-30",
			contains: []string{"https://img.shields.io/badge/", "low", "yellowgreen"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateBadgeURL(tt.stats, tt.label, tt.dbBuilt)
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
		{"no vulnerabilities", VulnerabilityStats{Total: 0}, "none"},
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
		scanMode string
		want     string
	}{
		{"release", "grype scan release"},
		{"image", "grype scan image"},
		{"head", "grype scan head"},
		{"path", "grype scan path"},
	}

	for _, tt := range tests {
		t.Run(tt.scanMode, func(t *testing.T) {
			got := buildBadgeLabel(tt.scanMode)
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
