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
			target, err := determineScanTarget(tt.config)
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
		want   Stats
	}{
		{
			name:   "empty output",
			output: &GrypeOutput{Matches: []GrypeMatch{}},
			want:   Stats{Total: 0},
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
			want: Stats{Total: 4, Critical: 1, High: 1, Medium: 1, Low: 1},
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
			want: Stats{Total: 2, Critical: 1, High: 1},
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
		stats  Stats
		cutoff string
		want   bool
	}{
		{"critical cutoff with critical", Stats{Critical: 1}, "critical", true},
		{"critical cutoff without critical", Stats{High: 1}, "critical", false},
		{"high cutoff with high", Stats{High: 1}, "high", true},
		{"high cutoff with critical", Stats{Critical: 1}, "high", true},
		{"medium cutoff with medium", Stats{Medium: 1}, "medium", true},
		{"low cutoff with low", Stats{Low: 1}, "low", true},
		{"negligible cutoff with any", Stats{Other: 1, Total: 1}, "negligible", true},
		{"no vulns", Stats{}, "medium", false},
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
	target, err := handleRepoScan("head")
	if err != nil {
		t.Fatalf("handleRepoScan(head) error = %v", err)
	}
	if target != "dir:." {
		t.Errorf("target = %v, want dir:.", target)
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

	target, err := determineScanTarget(config)
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
