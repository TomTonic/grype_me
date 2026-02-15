package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetermineScanTarget(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		config     Config
		wantPrefix string
		wantErr    bool
		errMsg     string
	}{
		{"image mode", Config{Image: "alpine:latest"}, "alpine:latest", false, ""},
		{"path mode directory", Config{Path: tmpDir}, "dir:", false, ""},
		{"path mode file", Config{Path: tmpFile}, "file:", false, ""},
		{"sbom mode", Config{SBOM: "sbom.json"}, "sbom:", false, ""},
		{"multiple artifact modes", Config{Image: "alpine", Path: tmpDir}, "", true, "only one of image, path, or sbom"},
		{"scan with artifact mode", Config{Scan: "head", Image: "alpine"}, "", true, "scan cannot be used together"},
		{"path not found", Config{Path: "/nonexistent/path"}, "", true, "not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, _, err := determineScanTarget(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("determineScanTarget() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %v, want containing %q", err, tt.errMsg)
			}
			if !tt.wantErr && !strings.HasPrefix(target, tt.wantPrefix) {
				t.Errorf("target = %v, want prefix %v", target, tt.wantPrefix)
			}
		})
	}
}

func TestCalculateStats(t *testing.T) {
	tests := []struct {
		name   string
		output *GrypeOutput
		want   VulnerabilityStats
	}{
		{
			name:   "empty output",
			output: &GrypeOutput{Matches: []GrypeMatch{}},
			want:   VulnerabilityStats{Total: 0},
		},
		{
			name: "mixed severities",
			output: &GrypeOutput{
				Matches: []GrypeMatch{
					makeMatch("CVE-1", "Critical", "pkg1", "1.0", nil, "", ""),
					makeMatch("CVE-2", "High", "pkg2", "1.0", nil, "", ""),
					makeMatch("CVE-3", "Medium", "pkg3", "1.0", nil, "", ""),
					makeMatch("CVE-4", "Low", "pkg4", "1.0", nil, "", ""),
				},
			},
			want: VulnerabilityStats{Total: 4, Critical: 1, High: 1, Medium: 1, Low: 1},
		},
		{
			name: "case insensitive",
			output: &GrypeOutput{
				Matches: []GrypeMatch{
					makeMatch("CVE-1", "CRITICAL", "pkg1", "1.0", nil, "", ""),
					makeMatch("CVE-2", "high", "pkg2", "1.0", nil, "", ""),
				},
			},
			want: VulnerabilityStats{Total: 2, Critical: 1, High: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateStats(tt.output)
			if got != tt.want {
				t.Errorf("calculateStats() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestShouldFail(t *testing.T) {
	tests := []struct {
		name   string
		stats  VulnerabilityStats
		cutoff string
		want   bool
	}{
		{"critical cutoff with critical", VulnerabilityStats{Critical: 1}, "critical", true},
		{"critical cutoff without critical", VulnerabilityStats{High: 1}, "critical", false},
		{"high cutoff with high", VulnerabilityStats{High: 1}, "high", true},
		{"high cutoff with critical", VulnerabilityStats{Critical: 1}, "high", true},
		{"medium cutoff with medium", VulnerabilityStats{Medium: 1}, "medium", true},
		{"low cutoff with low", VulnerabilityStats{Low: 1}, "low", true},
		{"negligible cutoff with any", VulnerabilityStats{Other: 1, Total: 1}, "negligible", true},
		{"no vulns", VulnerabilityStats{}, "medium", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldFail(tt.stats, tt.cutoff)
			if got != tt.want {
				t.Errorf("shouldFail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseGrypeOutput(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "grype-output-*.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(tmpFile.Name()) })

	grypeJSON := `{"matches": [{"vulnerability": {"id": "CVE-2021-1234", "severity": "High"}}], "descriptor": {"version": "0.106.0", "db": {"status": {"built": "2024-01-01T00:00:00Z"}}}}`

	if err := os.WriteFile(tmpFile.Name(), []byte(grypeJSON), 0644); err != nil {
		t.Fatal(err)
	}

	output, err := parseGrypeOutput(tmpFile.Name())
	if err != nil {
		t.Fatalf("parseGrypeOutput() error = %v", err)
	}

	if len(output.Matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(output.Matches))
	}
	if output.Descriptor.Version != "0.106.0" {
		t.Errorf("version = %v, want 0.106.0", output.Descriptor.Version)
	}
}

func TestEndToEndWithPath(t *testing.T) {
	if _, err := exec.LookPath("grype"); err != nil {
		t.Skip("grype not installed")
	}

	tmpDir := t.TempDir()
	goMod := "module testmodule\n\ngo 1.21\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	config := Config{
		Path:       tmpDir,
		OutputFile: "",
	}

	target, _, err := determineScanTarget(config)
	if err != nil {
		t.Fatalf("determineScanTarget() error = %v", err)
	}

	if !strings.HasPrefix(target, "dir:") {
		t.Errorf("target = %v, want prefix dir:", target)
	}

	tmpFile, err := os.CreateTemp("", "grype-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(tmpFile.Name()) })
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	err = runGrypeScan(config, target, tmpFile.Name())
	if err != nil {
		t.Fatalf("runGrypeScan() error = %v", err)
	}

	if _, err := os.Stat(tmpFile.Name()); os.IsNotExist(err) {
		t.Error("output file was not created")
	}
}
