package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGetEnv tests the getEnv function
func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		setEnv       bool
		want         string
	}{
		{
			name:         "environment variable set",
			key:          "TEST_VAR",
			defaultValue: "default",
			envValue:     "custom",
			setEnv:       true,
			want:         "custom",
		},
		{
			name:         "environment variable not set",
			key:          "TEST_VAR_UNSET",
			defaultValue: "default",
			envValue:     "",
			setEnv:       false,
			want:         "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			}

			got := getEnv(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDebugEnabled(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     bool
	}{
		{"debug true", "true", true},
		{"debug TRUE", "TRUE", true},
		{"debug false", "false", false},
		{"debug empty", "", false},
		{"debug invalid", "yes", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv("INPUT_DEBUG", tt.envValue)
			}
			got := isDebugEnabled()
			if got != tt.want {
				t.Errorf("isDebugEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLoadConfig tests the loadConfig function
func TestLoadConfig(t *testing.T) {
	t.Setenv("INPUT_SCAN", "latest_release")
	t.Setenv("INPUT_IMAGE", "")
	t.Setenv("INPUT_PATH", "")
	t.Setenv("INPUT_SBOM", "")
	t.Setenv("INPUT_FAIL-BUILD", "true")
	t.Setenv("INPUT_SEVERITY-CUTOFF", "high")
	t.Setenv("INPUT_OUTPUT-FILE", "results.json")
	t.Setenv("INPUT_ONLY-FIXED", "true")
	t.Setenv("INPUT_DEBUG", "false")

	config := loadConfig()

	if config.Scan != "latest_release" {
		t.Errorf("config.Scan = %v, want latest_release", config.Scan)
	}
	if !config.FailBuild {
		t.Error("config.FailBuild should be true")
	}
	if config.SeverityCutoff != "high" {
		t.Errorf("config.SeverityCutoff = %v, want high", config.SeverityCutoff)
	}
	if !config.OnlyFixed {
		t.Error("config.OnlyFixed should be true")
	}
}

// TestDetermineScanTarget tests the determineScanTarget function
func TestDetermineScanTarget(t *testing.T) {
	// Create a temp directory for path tests
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
		{
			name:       "image mode",
			config:     Config{Image: "alpine:latest"},
			wantPrefix: "alpine:latest",
			wantErr:    false,
		},
		{
			name:       "path mode directory",
			config:     Config{Path: tmpDir},
			wantPrefix: "dir:",
			wantErr:    false,
		},
		{
			name:       "path mode file",
			config:     Config{Path: tmpFile},
			wantPrefix: "file:",
			wantErr:    false,
		},
		{
			name:       "sbom mode",
			config:     Config{SBOM: "sbom.json"},
			wantPrefix: "sbom:",
			wantErr:    false,
		},
		{
			name:    "multiple artifact modes",
			config:  Config{Image: "alpine", Path: tmpDir},
			wantErr: true,
			errMsg:  "only one of image, path, or sbom",
		},
		{
			name:    "scan with artifact mode",
			config:  Config{Scan: "head", Image: "alpine"},
			wantErr: true,
			errMsg:  "scan cannot be used together",
		},
		{
			name:    "path not found",
			config:  Config{Path: "/nonexistent/path"},
			wantErr: true,
			errMsg:  "not found",
		},
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

// TestCalculateStats tests the calculateStats function
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
					{Vulnerability: struct {
						ID       string `json:"id"`
						Severity string `json:"severity"`
					}{ID: "CVE-1", Severity: "Critical"}},
					{Vulnerability: struct {
						ID       string `json:"id"`
						Severity string `json:"severity"`
					}{ID: "CVE-2", Severity: "High"}},
					{Vulnerability: struct {
						ID       string `json:"id"`
						Severity string `json:"severity"`
					}{ID: "CVE-3", Severity: "Medium"}},
					{Vulnerability: struct {
						ID       string `json:"id"`
						Severity string `json:"severity"`
					}{ID: "CVE-4", Severity: "Low"}},
				},
			},
			want: VulnerabilityStats{Total: 4, Critical: 1, High: 1, Medium: 1, Low: 1},
		},
		{
			name: "case insensitive",
			output: &GrypeOutput{
				Matches: []GrypeMatch{
					{Vulnerability: struct {
						ID       string `json:"id"`
						Severity string `json:"severity"`
					}{ID: "CVE-1", Severity: "CRITICAL"}},
					{Vulnerability: struct {
						ID       string `json:"id"`
						Severity string `json:"severity"`
					}{ID: "CVE-2", Severity: "high"}},
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

// TestShouldFail tests the shouldFail function
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

// TestValidateRefName tests the validateRefName function
func TestValidateRefName(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{"valid simple ref", "main", false},
		{"valid tag", "v1.0.0", false},
		{"valid branch with slash", "feature/new", false},
		{"empty ref", "", true},
		{"ref with newline", "main\nmalicious", true},
		{"ref with path traversal", "../etc/passwd", true},
		{"ref with tilde", "HEAD~1", true},
		{"ref with space", "main branch", true},
		{"ref starting with dot", ".hidden", true},
		{"ref ending with slash", "branch/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRefName(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRefName(%q) error = %v, wantErr %v", tt.ref, err, tt.wantErr)
			}
		})
	}
}

// TestIsPreReleaseTag tests the isPreReleaseTag function
func TestIsPreReleaseTag(t *testing.T) {
	tests := []struct {
		tag  string
		want bool
	}{
		{"v1.0.0", false},
		{"1.0.0", false},
		{"v1.0.0-alpha", true},
		{"v1.0.0-beta.1", true},
		{"v1.0.0-rc1", true},
		{"v2.0.0-pre", true},
		{"release-1.0", false}, // not a semver pre-release
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			got := isPreReleaseTag(tt.tag)
			if got != tt.want {
				t.Errorf("isPreReleaseTag(%q) = %v, want %v", tt.tag, got, tt.want)
			}
		})
	}
}

// TestParseGrypeOutput tests the parseGrypeOutput function
func TestParseGrypeOutput(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "grype-output-*.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(tmpFile.Name()) })

	grypeJSON := `{
		"matches": [
			{"vulnerability": {"id": "CVE-2021-1234", "severity": "High"}}
		],
		"descriptor": {
			"version": "0.106.0",
			"db": {"status": {"built": "2024-01-01T00:00:00Z"}}
		}
	}`

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

// TestGrypeOutputDBBuilt tests the DBBuilt method
func TestGrypeOutputDBBuilt(t *testing.T) {
	tests := []struct {
		name   string
		output *GrypeOutput
		want   string
	}{
		{
			name:   "nil output",
			output: nil,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.output.DBBuilt()
			if got != tt.want {
				t.Errorf("DBBuilt() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCopyOutputFile tests the copyOutputFile function
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

// TestValidatePathInWorkspace tests path traversal protection
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

// TestConfigureGitSafeDirectory tests git safe directory configuration
func TestConfigureGitSafeDirectory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	err := configureGitSafeDirectory()
	if err != nil {
		t.Errorf("configureGitSafeDirectory() error = %v", err)
	}
}

// TestHandleRepoScanHead tests head mode
func TestHandleRepoScanHead(t *testing.T) {
	target, tempDir, err := handleRepoScan("head")
	if err != nil {
		t.Fatalf("handleRepoScan(head) error = %v", err)
	}
	if target != "dir:." {
		t.Errorf("target = %v, want dir:.", target)
	}
	if tempDir != "" {
		t.Errorf("tempDir = %v, want empty for head mode", tempDir)
	}
}

// TestEndToEndWithPath tests scanning a directory path
func TestEndToEndWithPath(t *testing.T) {
	if _, err := exec.LookPath("grype"); err != nil {
		t.Skip("grype not installed")
	}

	tmpDir := t.TempDir()
	goMod := `module testmodule

go 1.21
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	config := Config{
		Path:           tmpDir,
		OutputFile:     "",
		VariablePrefix: "TEST_",
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

// TestGrypeOutputJSONMarshaling tests JSON marshaling/unmarshaling
func TestGrypeOutputJSONMarshaling(t *testing.T) {
	original := &GrypeOutput{
		Matches: []GrypeMatch{
			{Vulnerability: struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			}{ID: "CVE-2021-1234", Severity: "High"}},
		},
	}
	original.Descriptor.Version = "0.106.0"
	original.Descriptor.DB.Status.Built = "2024-01-01"

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var unmarshaled GrypeOutput
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(unmarshaled.Matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(unmarshaled.Matches))
	}
	if unmarshaled.DBBuilt() != "2024-01-01" {
		t.Errorf("DBBuilt() = %v, want 2024-01-01", unmarshaled.DBBuilt())
	}
}

// TestGenerateBadgeURL tests the badge URL generation
func TestGenerateBadgeURL(t *testing.T) {
	tests := []struct {
		name     string
		stats    VulnerabilityStats
		label    string
		dbBuilt  string
		contains []string
	}{
		{
			name:    "no vulnerabilities with DB date",
			stats:   VulnerabilityStats{Total: 0},
			label:   "grype scan release",
			dbBuilt: "2026-01-30T12:34:56Z",
			contains: []string{
				"https://img.shields.io/badge/",
				"grype%20scan%20release",
				"none",
				"db%20build%202026-01-30",
				"brightgreen",
			},
		},
		{
			name:    "critical vulnerabilities with DB date",
			stats:   VulnerabilityStats{Total: 2, Critical: 2},
			label:   "grype scan image",
			dbBuilt: "2026-01-30",
			contains: []string{
				"https://img.shields.io/badge/",
				"critical",
				"db%20build%202026-01-30",
			},
		},
		{
			name:    "high vulnerabilities",
			stats:   VulnerabilityStats{Total: 3, High: 3},
			label:   "security",
			dbBuilt: "2026-01-30",
			contains: []string{
				"https://img.shields.io/badge/",
				"security",
				"high",
				"orange",
			},
		},
		{
			name:    "medium vulnerabilities",
			stats:   VulnerabilityStats{Total: 5, Medium: 5},
			label:   "CVEs",
			dbBuilt: "",
			contains: []string{
				"https://img.shields.io/badge/",
				"CVEs",
				"medium",
				"yellow",
			},
		},
		{
			name:    "low vulnerabilities",
			stats:   VulnerabilityStats{Total: 10, Low: 10},
			label:   "scan results",
			dbBuilt: "2026-01-30",
			contains: []string{
				"https://img.shields.io/badge/",
				"low",
				"yellowgreen",
			},
		},
		{
			name:    "mixed vulnerabilities",
			stats:   VulnerabilityStats{Total: 10, Critical: 1, High: 2, Medium: 3, Low: 4},
			label:   "vulnerabilities",
			dbBuilt: "2026-01-30",
			contains: []string{
				"https://img.shields.io/badge/",
				"critical",
			},
		},
		{
			name:    "no DB date",
			stats:   VulnerabilityStats{Total: 0},
			label:   "grype scan head",
			dbBuilt: "",
			contains: []string{
				"https://img.shields.io/badge/",
				"grype%20scan%20head",
				"none-brightgreen",
			},
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

// TestFormatBadgeMessage tests the badge message formatting
func TestFormatBadgeMessage(t *testing.T) {
	tests := []struct {
		name  string
		stats VulnerabilityStats
		want  string
	}{
		{
			name:  "no vulnerabilities",
			stats: VulnerabilityStats{Total: 0},
			want:  "none",
		},
		{
			name:  "only critical",
			stats: VulnerabilityStats{Total: 2, Critical: 2},
			want:  "2 critical",
		},
		{
			name:  "only high",
			stats: VulnerabilityStats{Total: 3, High: 3},
			want:  "3 high",
		},
		{
			name:  "critical and high",
			stats: VulnerabilityStats{Total: 5, Critical: 2, High: 3},
			want:  "2 critical | 3 high",
		},
		{
			name:  "all severities",
			stats: VulnerabilityStats{Total: 10, Critical: 1, High: 2, Medium: 3, Low: 4},
			want:  "1 critical | 2 high | 3 medium | 4 low",
		},
		{
			name:  "only other",
			stats: VulnerabilityStats{Total: 5, Other: 5},
			want:  "5 other",
		},
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

// TestDetermineBadgeColor tests the badge color determination
func TestDetermineBadgeColor(t *testing.T) {
	tests := []struct {
		name  string
		stats VulnerabilityStats
		want  string
	}{
		{
			name:  "no vulnerabilities",
			stats: VulnerabilityStats{Total: 0},
			want:  "brightgreen",
		},
		{
			name:  "critical",
			stats: VulnerabilityStats{Critical: 1},
			want:  "critical",
		},
		{
			name:  "high",
			stats: VulnerabilityStats{High: 1},
			want:  "orange",
		},
		{
			name:  "medium",
			stats: VulnerabilityStats{Medium: 1},
			want:  "yellow",
		},
		{
			name:  "low",
			stats: VulnerabilityStats{Low: 1},
			want:  "yellowgreen",
		},
		{
			name:  "other",
			stats: VulnerabilityStats{Other: 1},
			want:  "yellowgreen",
		},
		{
			name:  "critical takes precedence",
			stats: VulnerabilityStats{Critical: 1, High: 2, Medium: 3, Low: 4},
			want:  "critical",
		},
		{
			name:  "high takes precedence over medium",
			stats: VulnerabilityStats{High: 1, Medium: 2, Low: 3},
			want:  "orange",
		},
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

// TestDetermineScanMode tests the scan mode detection for badge labels
func TestDetermineScanMode(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   string
	}{
		{
			name:   "image scan",
			config: Config{Image: "alpine:latest"},
			want:   "image",
		},
		{
			name:   "path scan",
			config: Config{Path: "./src"},
			want:   "path",
		},
		{
			name:   "sbom scan",
			config: Config{SBOM: "sbom.json"},
			want:   "sbom",
		},
		{
			name:   "latest_release scan (explicit)",
			config: Config{Scan: "latest_release"},
			want:   "release",
		},
		{
			name:   "latest_release scan (default)",
			config: Config{Scan: ""},
			want:   "release",
		},
		{
			name:   "head scan",
			config: Config{Scan: "head"},
			want:   "head",
		},
		{
			name:   "specific ref scan",
			config: Config{Scan: "v1.2.3"},
			want:   "ref",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineScanMode(tt.config)
			if got != tt.want {
				t.Errorf("determineScanMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBuildBadgeLabel tests the badge label generation
func TestBuildBadgeLabel(t *testing.T) {
	tests := []struct {
		name     string
		scanMode string
		want     string
	}{
		{
			name:     "release scan",
			scanMode: "release",
			want:     "grype scan release",
		},
		{
			name:     "image scan",
			scanMode: "image",
			want:     "grype scan image",
		},
		{
			name:     "head scan",
			scanMode: "head",
			want:     "grype scan head",
		},
		{
			name:     "path scan",
			scanMode: "path",
			want:     "grype scan path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildBadgeLabel(tt.scanMode)
			if got != tt.want {
				t.Errorf("buildBadgeLabel() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestExtractDBDate tests extracting date from timestamp
func TestExtractDBDate(t *testing.T) {
	tests := []struct {
		name      string
		timestamp string
		want      string
	}{
		{
			name:      "full ISO timestamp",
			timestamp: "2026-01-30T12:34:56Z",
			want:      "2026-01-30",
		},
		{
			name:      "date only",
			timestamp: "2026-01-30",
			want:      "2026-01-30",
		},
		{
			name:      "short timestamp",
			timestamp: "2026-01",
			want:      "2026-01",
		},
		{
			name:      "empty string",
			timestamp: "",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDBDate(tt.timestamp)
			if got != tt.want {
				t.Errorf("extractDBDate() = %v, want %v", got, tt.want)
			}
		})
	}
}
