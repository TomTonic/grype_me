package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// checkoutTestDefaultBranch attempts to checkout the default branch (master or main)
// in the current directory. It returns the name of the branch that was checked out,
// or an error if neither branch exists.
func checkoutTestDefaultBranch(t *testing.T) string {
	t.Helper()

	// Try master first
	if err := exec.Command("git", "checkout", "master").Run(); err == nil {
		return "master"
	}

	// Try main
	if err := exec.Command("git", "checkout", "main").Run(); err == nil {
		return "main"
	}

	t.Fatalf("failed to checkout default branch: neither 'master' nor 'main' exists")
	return ""
}

// checkoutTestDefaultBranchInDir attempts to checkout the default branch in the specified directory.
// Returns the name of the branch that was checked out, or an error if neither branch exists.
func checkoutTestDefaultBranchInDir(t *testing.T, dir string) string {
	t.Helper()

	// Try master first
	cmd := exec.Command("git", "checkout", "master")
	cmd.Dir = dir
	if err := cmd.Run(); err == nil {
		return "master"
	}

	// Try main
	cmd = exec.Command("git", "checkout", "main")
	cmd.Dir = dir
	if err := cmd.Run(); err == nil {
		return "main"
	}

	t.Fatalf("failed to checkout default branch in %s: neither 'master' nor 'main' exists", dir)
	return ""
}

// getTestDefaultBranchName returns the name of the default branch (master or main)
// by checking which one exists. Returns an error if neither exists.
func getTestDefaultBranchName() (string, error) {
	// Try to verify master exists
	if err := exec.Command("git", "rev-parse", "--verify", "refs/heads/master").Run(); err == nil {
		return "master", nil
	}

	// Try to verify main exists
	if err := exec.Command("git", "rev-parse", "--verify", "refs/heads/main").Run(); err == nil {
		return "main", nil
	}

	return "", fmt.Errorf("neither 'master' nor 'main' branch exists")
}

// TestValidateRefName tests the validateRefName function
func TestValidateRefName(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid simple ref",
			ref:     "main",
			wantErr: false,
		},
		{
			name:    "valid tag with version",
			ref:     "v1.0.0",
			wantErr: false,
		},
		{
			name:    "valid branch with slash",
			ref:     "feature/new-feature",
			wantErr: false,
		},
		{
			name:    "empty ref",
			ref:     "",
			wantErr: true,
			errMsg:  "cannot be empty",
		},
		{
			name:    "ref with newline",
			ref:     "main\nmalicious",
			wantErr: true,
			errMsg:  "control character",
		},
		{
			name:    "ref with null byte",
			ref:     "main\x00malicious",
			wantErr: true,
			errMsg:  "control character",
		},
		{
			name:    "ref with tab",
			ref:     "main\tmalicious",
			wantErr: true,
			errMsg:  "control character",
		},
		{
			name:    "ref with carriage return",
			ref:     "main\rmalicious",
			wantErr: true,
			errMsg:  "control character",
		},
		{
			name:    "ref with path traversal",
			ref:     "../etc/passwd",
			wantErr: true,
			errMsg:  "suspicious pattern",
		},
		{
			name:    "ref with tilde",
			ref:     "HEAD~1",
			wantErr: true,
			errMsg:  "suspicious pattern",
		},
		{
			name:    "ref with caret",
			ref:     "HEAD^",
			wantErr: true,
			errMsg:  "suspicious pattern",
		},
		{
			name:    "ref with colon",
			ref:     "branch:file",
			wantErr: true,
			errMsg:  "suspicious pattern",
		},
		{
			name:    "ref with space",
			ref:     "main branch",
			wantErr: true,
			errMsg:  "suspicious pattern",
		},
		{
			name:    "ref with wildcard asterisk",
			ref:     "feature*",
			wantErr: true,
			errMsg:  "suspicious pattern",
		},
		{
			name:    "ref with wildcard question",
			ref:     "feature?",
			wantErr: true,
			errMsg:  "suspicious pattern",
		},
		{
			name:    "ref starting with dot",
			ref:     ".hidden",
			wantErr: true,
			errMsg:  "cannot start or end with a dot",
		},
		{
			name:    "ref ending with dot",
			ref:     "branch.",
			wantErr: true,
			errMsg:  "cannot start or end with a dot",
		},
		{
			name:    "ref starting with slash",
			ref:     "/branch",
			wantErr: true,
			errMsg:  "cannot start or end with a slash",
		},
		{
			name:    "ref ending with slash",
			ref:     "branch/",
			wantErr: true,
			errMsg:  "cannot start or end with a slash",
		},
		{
			name:    "ref with backslash",
			ref:     "branch\\name",
			wantErr: true,
			errMsg:  "suspicious pattern",
		},
		{
			name:    "ref with bracket",
			ref:     "branch[0]",
			wantErr: true,
			errMsg:  "suspicious pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRefName(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRefName(%q) error = %v, wantErr %v", tt.ref, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("validateRefName(%q) error = %v, want error containing %q", tt.ref, err, tt.errMsg)
				}
			}
		})
	}
}

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
		{
			name:         "empty default value",
			key:          "TEST_VAR_EMPTY",
			defaultValue: "",
			envValue:     "",
			setEnv:       false,
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				_ = os.Setenv(tt.key, tt.envValue)
				defer func() {
					_ = os.Unsetenv(tt.key)
				}()
			}

			got := getEnv(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDebugEnabled(t *testing.T) {
	originalValue, originalSet := os.LookupEnv("INPUT_DEBUG")
	defer func() {
		if originalSet {
			_ = os.Setenv("INPUT_DEBUG", originalValue)
		} else {
			_ = os.Unsetenv("INPUT_DEBUG")
		}
	}()

	tests := []struct {
		name     string
		envValue string
		want     bool
	}{
		{
			name:     "debug true uppercase",
			envValue: "TRUE",
			want:     true,
		},
		{
			name:     "debug true",
			envValue: "true",
			want:     true,
		},
		{
			name:     "debug true mixed case",
			envValue: "TrUe",
			want:     true,
		},
		{
			name:     "debug false",
			envValue: "false",
			want:     false,
		},
		{
			name:     "debug false uppercase",
			envValue: "FALSE",
			want:     false,
		},
		{
			name:     "debug invalid value",
			envValue: "yes",
			want:     false,
		},
		{
			name:     "debug whitespace",
			envValue: " true ",
			want:     true,
		},
		{
			name:     "debug empty",
			envValue: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv("INPUT_DEBUG", tt.envValue)
			} else {
				_ = os.Unsetenv("INPUT_DEBUG")
			}

			got := isDebugEnabled()
			if got != tt.want {
				t.Errorf("isDebugEnabled() = %v, want %v", got, tt.want)
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
			name: "empty output",
			output: &GrypeOutput{
				Matches: []GrypeMatch{},
			},
			want: Stats{
				Total:    0,
				Critical: 0,
				High:     0,
				Medium:   0,
				Low:      0,
				Other:    0,
			},
		},
		{
			name: "single critical vulnerability",
			output: &GrypeOutput{
				Matches: []GrypeMatch{
					{
						Vulnerability: struct {
							ID       string `json:"id"`
							Severity string `json:"severity"`
						}{
							ID:       "CVE-2021-1234",
							Severity: "Critical",
						},
					},
				},
			},
			want: Stats{
				Total:    1,
				Critical: 1,
				High:     0,
				Medium:   0,
				Low:      0,
				Other:    0,
			},
		},
		{
			name: "mixed severities",
			output: &GrypeOutput{
				Matches: []GrypeMatch{
					{
						Vulnerability: struct {
							ID       string `json:"id"`
							Severity string `json:"severity"`
						}{
							ID:       "CVE-2021-1234",
							Severity: "Critical",
						},
					},
					{
						Vulnerability: struct {
							ID       string `json:"id"`
							Severity string `json:"severity"`
						}{
							ID:       "CVE-2021-5678",
							Severity: "High",
						},
					},
					{
						Vulnerability: struct {
							ID       string `json:"id"`
							Severity string `json:"severity"`
						}{
							ID:       "CVE-2021-9012",
							Severity: "Medium",
						},
					},
					{
						Vulnerability: struct {
							ID       string `json:"id"`
							Severity string `json:"severity"`
						}{
							ID:       "CVE-2021-3456",
							Severity: "Low",
						},
					},
				},
			},
			want: Stats{
				Total:    4,
				Critical: 1,
				High:     1,
				Medium:   1,
				Low:      1,
				Other:    0,
			},
		},
		{
			name: "case insensitive severity",
			output: &GrypeOutput{
				Matches: []GrypeMatch{
					{
						Vulnerability: struct {
							ID       string `json:"id"`
							Severity string `json:"severity"`
						}{
							ID:       "CVE-2021-1234",
							Severity: "CRITICAL",
						},
					},
					{
						Vulnerability: struct {
							ID       string `json:"id"`
							Severity string `json:"severity"`
						}{
							ID:       "CVE-2021-5678",
							Severity: "high",
						},
					},
				},
			},
			want: Stats{
				Total:    2,
				Critical: 1,
				High:     1,
				Medium:   0,
				Low:      0,
				Other:    0,
			},
		},
		{
			name: "unknown severity",
			output: &GrypeOutput{
				Matches: []GrypeMatch{
					{
						Vulnerability: struct {
							ID       string `json:"id"`
							Severity string `json:"severity"`
						}{
							ID:       "CVE-2021-1234",
							Severity: "Unknown",
						},
					},
				},
			},
			want: Stats{
				Total:    1,
				Critical: 0,
				High:     0,
				Medium:   0,
				Low:      0,
				Other:    1,
			},
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

// TestParseGrypeOutput tests the parseGrypeOutput function
func TestParseGrypeOutput(t *testing.T) {
	tests := []struct {
		name       string
		jsonData   string
		wantErr    bool
		wantOutput *GrypeOutput
	}{
		{
			name: "valid grype output",
			jsonData: `{
				"matches": [
					{
						"vulnerability": {
							"id": "CVE-2021-1234",
							"severity": "High"
						}
					}
				],
				"descriptor": {
					"version": "0.65.0",
					"db": {
						"status": {
							"built": "2024-01-30T10:00:00Z"
						}
					}
				}
			}`,
			wantErr: false,
			wantOutput: &GrypeOutput{
				Matches: []GrypeMatch{
					{
						Vulnerability: struct {
							ID       string `json:"id"`
							Severity string `json:"severity"`
						}{
							ID:       "CVE-2021-1234",
							Severity: "High",
						},
					},
				},
				Descriptor: struct {
					Version string `json:"version"`
					DB      struct {
						Built  string `json:"built,omitempty"`
						Status struct {
							Built string `json:"built,omitempty"`
						} `json:"status,omitempty"`
					} `json:"db"`
				}{
					Version: "0.65.0",
					DB: struct {
						Built  string `json:"built,omitempty"`
						Status struct {
							Built string `json:"built,omitempty"`
						} `json:"status,omitempty"`
					}{
						Status: struct {
							Built string `json:"built,omitempty"`
						}{
							Built: "2024-01-30T10:00:00Z",
						},
					},
				},
			},
		},
		{
			name:       "invalid json",
			jsonData:   `{"invalid json`,
			wantErr:    true,
			wantOutput: nil,
		},
		{
			name:       "empty json object",
			jsonData:   `{}`,
			wantErr:    false,
			wantOutput: &GrypeOutput{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file with the test data
			tmpFile, err := os.CreateTemp("", "grype-test-*.json")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer func() {
				_ = os.Remove(tmpFile.Name())
			}()

			if _, err := tmpFile.WriteString(tt.jsonData); err != nil {
				t.Fatalf("Failed to write to temp file: %v", err)
			}
			if err := tmpFile.Close(); err != nil {
				t.Fatalf("Failed to close temp file: %v", err)
			}

			got, err := parseGrypeOutput(tmpFile.Name())
			if (err != nil) != tt.wantErr {
				t.Errorf("parseGrypeOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.wantOutput != nil {
				if len(got.Matches) != len(tt.wantOutput.Matches) {
					t.Errorf("parseGrypeOutput() matches count = %d, want %d",
						len(got.Matches), len(tt.wantOutput.Matches))
				}
				if got.Descriptor.Version != tt.wantOutput.Descriptor.Version {
					t.Errorf("parseGrypeOutput() version = %s, want %s",
						got.Descriptor.Version, tt.wantOutput.Descriptor.Version)
				}
			}
		})
	}
}

// TestParseGrypeOutputFileNotFound tests parseGrypeOutput with non-existent file
func TestParseGrypeOutputFileNotFound(t *testing.T) {
	_, err := parseGrypeOutput("/nonexistent/file.json")
	if err == nil {
		t.Error("parseGrypeOutput() expected error for non-existent file, got nil")
	}
}

// TestCopyOutputFile tests the copyOutputFile function
func TestCopyOutputFile(t *testing.T) {
	// Create a temporary source file
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "source.json")
	testData := []byte(`{"test": "data"}`)

	if err := os.WriteFile(srcFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	tests := []struct {
		name    string
		src     string
		dst     string
		wantErr bool
	}{
		{
			name:    "successful copy",
			src:     srcFile,
			dst:     filepath.Join(tmpDir, "destination.json"),
			wantErr: false,
		},
		{
			name:    "copy to nested directory",
			src:     srcFile,
			dst:     filepath.Join(tmpDir, "subdir", "output.json"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := copyOutputFile(tt.src, tt.dst)
			if (err != nil) != tt.wantErr {
				t.Errorf("copyOutputFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify the file was copied
				if _, err := os.Stat(got); os.IsNotExist(err) {
					t.Errorf("copyOutputFile() did not create destination file")
				}

				// Verify content
				copiedData, err := os.ReadFile(got)
				if err != nil {
					t.Errorf("Failed to read copied file: %v", err)
				}
				if string(copiedData) != string(testData) {
					t.Errorf("copyOutputFile() content mismatch")
				}
			}
		})
	}
}

// TestCopyOutputFileSourceNotFound tests copyOutputFile with non-existent source
func TestCopyOutputFileSourceNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := copyOutputFile("/nonexistent/source.json", filepath.Join(tmpDir, "dest.json"))
	if err == nil {
		t.Error("copyOutputFile() expected error for non-existent source, got nil")
	}
}

// TestCopyOutputFileWithGitHubWorkspace tests copyOutputFile with GITHUB_WORKSPACE set
func TestCopyOutputFileWithGitHubWorkspace(t *testing.T) {
	// Create a temporary source file
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "source.json")
	testData := []byte(`{"test": "workspace data"}`)

	if err := os.WriteFile(srcFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Create a mock workspace directory
	workspaceDir := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		t.Fatalf("Failed to create workspace directory: %v", err)
	}

	// Set GITHUB_WORKSPACE environment variable
	oldWorkspace := os.Getenv("GITHUB_WORKSPACE")
	defer func() {
		if oldWorkspace != "" {
			_ = os.Setenv("GITHUB_WORKSPACE", oldWorkspace)
		} else {
			_ = os.Unsetenv("GITHUB_WORKSPACE")
		}
	}()
	if err := os.Setenv("GITHUB_WORKSPACE", workspaceDir); err != nil {
		t.Fatalf("Failed to set GITHUB_WORKSPACE: %v", err)
	}

	// Test with relative path (should use GITHUB_WORKSPACE)
	dstFile := "output.json"
	got, err := copyOutputFile(srcFile, dstFile)
	if err != nil {
		t.Fatalf("copyOutputFile() error = %v", err)
	}

	expectedPath := filepath.Join(workspaceDir, dstFile)
	if got != expectedPath {
		t.Errorf("copyOutputFile() = %v, want %v", got, expectedPath)
	}

	// Verify the file was created in the workspace
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("copyOutputFile() did not create file in workspace")
	}

	// Verify content
	copiedData, err := os.ReadFile(got)
	if err != nil {
		t.Errorf("Failed to read copied file: %v", err)
	}
	if string(copiedData) != string(testData) {
		t.Errorf("copyOutputFile() content mismatch")
	}
}

// TestCopyOutputFileWithDockerWorkspace tests copyOutputFile with Docker workspace
func TestCopyOutputFileWithDockerWorkspace(t *testing.T) {
	// Create a temporary source file
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "source.json")
	testData := []byte(`{"test": "docker data"}`)

	if err := os.WriteFile(srcFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Create a mock /github/workspace directory (simulating Docker environment)
	dockerWorkspaceDir := filepath.Join(tmpDir, "github", "workspace")
	if err := os.MkdirAll(dockerWorkspaceDir, 0755); err != nil {
		t.Fatalf("Failed to create docker workspace directory: %v", err)
	}

	// Test with relative path - mock Docker environment by temporarily changing the logic
	// Since we can't actually create /github/workspace in tests, we'll test the logic indirectly
	// This test verifies that absolute paths work correctly
	dstFile := filepath.Join(dockerWorkspaceDir, "output.json")
	got, err := copyOutputFile(srcFile, dstFile)
	if err != nil {
		t.Fatalf("copyOutputFile() error = %v", err)
	}

	if got != dstFile {
		t.Errorf("copyOutputFile() = %v, want %v", got, dstFile)
	}

	// Verify the file was created
	if _, err := os.Stat(got); os.IsNotExist(err) {
		t.Errorf("copyOutputFile() did not create destination file")
	}

	// Verify content
	copiedData, err := os.ReadFile(got)
	if err != nil {
		t.Errorf("Failed to read copied file: %v", err)
	}
	if string(copiedData) != string(testData) {
		t.Errorf("copyOutputFile() content mismatch")
	}
}

// TestCopyOutputFilePathTraversal tests that path traversal attacks are prevented
func TestCopyOutputFilePathTraversal(t *testing.T) {
	// Create source file
	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "source.json")
	testData := []byte(`{"test": "data"}`)
	if err := os.WriteFile(srcFile, testData, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Create a workspace directory
	workspace := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(workspace, 0755); err != nil {
		t.Fatalf("Failed to create workspace: %v", err)
	}

	// Set GITHUB_WORKSPACE environment variable
	oldWorkspace := os.Getenv("GITHUB_WORKSPACE")
	defer func() {
		if oldWorkspace != "" {
			_ = os.Setenv("GITHUB_WORKSPACE", oldWorkspace)
		} else {
			_ = os.Unsetenv("GITHUB_WORKSPACE")
		}
	}()
	if err := os.Setenv("GITHUB_WORKSPACE", workspace); err != nil {
		t.Fatalf("Failed to set GITHUB_WORKSPACE: %v", err)
	}

	// Test cases with path traversal attempts
	tests := []struct {
		name    string
		dst     string
		wantErr bool
	}{
		{
			name:    "valid relative path",
			dst:     "output.json",
			wantErr: false,
		},
		{
			name:    "valid nested path",
			dst:     "subdir/output.json",
			wantErr: false,
		},
		{
			name:    "path traversal with ../",
			dst:     "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "path traversal to parent",
			dst:     "../output.json",
			wantErr: true,
		},
		{
			name:    "path traversal with mixed separators",
			dst:     "subdir/../../outside.json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := copyOutputFile(srcFile, tt.dst)
			if (err != nil) != tt.wantErr {
				t.Errorf("copyOutputFile() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.wantErr {
				// Verify the error message mentions path traversal
				if !strings.Contains(err.Error(), "path traversal") {
					t.Errorf("Expected path traversal error, got: %v", err)
				}
			}
		})
	}
}

// TestGrypeOutputJSONMarshaling tests that GrypeOutput can be marshaled and unmarshaled
func TestGrypeOutputJSONMarshaling(t *testing.T) {
	original := &GrypeOutput{
		Matches: []GrypeMatch{
			{
				Vulnerability: struct {
					ID       string `json:"id"`
					Severity string `json:"severity"`
				}{
					ID:       "CVE-2021-1234",
					Severity: "High",
				},
			},
		},
		Descriptor: struct {
			Version string `json:"version"`
			DB      struct {
				Built  string `json:"built,omitempty"`
				Status struct {
					Built string `json:"built,omitempty"`
				} `json:"status,omitempty"`
			} `json:"db"`
		}{
			Version: "0.65.0",
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Failed to marshal GrypeOutput: %v", err)
	}

	// Unmarshal back
	var decoded GrypeOutput
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal GrypeOutput: %v", err)
	}

	// Verify
	if len(decoded.Matches) != len(original.Matches) {
		t.Errorf("Unmarshaled matches count = %d, want %d",
			len(decoded.Matches), len(original.Matches))
	}
	if decoded.Descriptor.Version != original.Descriptor.Version {
		t.Errorf("Unmarshaled version = %s, want %s",
			decoded.Descriptor.Version, original.Descriptor.Version)
	}
}

// TestEndToEndGrypeScan is an end-to-end integration test that runs an actual grype scan
// This test requires grype to be installed and available in PATH
func TestEndToEndGrypeScan(t *testing.T) {
	// Find and setup grype
	if !setupGrype(t) {
		return // Test was skipped
	}

	// Create a temporary directory for test output
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "grype-results.json")

	// Test scanning the current directory (our Go project)
	// This is a real end-to-end test scanning actual code
	err := runGrypeScan(".", outputFile)

	// Check if the scan failed due to missing database
	if err != nil {
		// Read the output file to see if it contains any data
		if _, statErr := os.Stat(outputFile); os.IsNotExist(statErr) {
			t.Skipf("Grype scan failed (likely database not available): %v", err)
		}
	}

	// Verify output file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		t.Skipf("Output file was not created (grype database may not be available): %s", outputFile)
	}

	// Check if the file has content
	fileInfo, err := os.Stat(outputFile)
	if err != nil {
		t.Fatalf("Failed to stat output file: %v", err)
	}
	if fileInfo.Size() == 0 {
		t.Skip("Output file is empty (grype database may not be available)")
	}

	// Parse the output
	output, err := parseGrypeOutput(outputFile)
	if err != nil {
		// If parsing fails, it might be due to incomplete scan
		content, _ := os.ReadFile(outputFile)
		t.Logf("Output file content: %s", string(content))
		t.Skipf("Failed to parse grype output (scan may have been incomplete): %v", err)
	}

	// Verify output structure
	if output == nil {
		t.Fatal("Parsed output is nil")
	}

	// Verify descriptor has version information
	if output.Descriptor.Version == "" {
		t.Error("Grype version is empty")
	} else {
		t.Logf("Grype version: %s", output.Descriptor.Version)
	}

	if output.DBBuilt() == "" {
		t.Logf("Database built info not available (this is expected in some environments)")
	} else {
		t.Logf("Database built: %s", output.DBBuilt())
	}

	// Calculate statistics
	stats := calculateStats(output)

	// Log the results
	t.Logf("Scan results for current project:")
	t.Logf("  Total vulnerabilities: %d", stats.Total)
	t.Logf("  Critical: %d", stats.Critical)
	t.Logf("  High: %d", stats.High)
	t.Logf("  Medium: %d", stats.Medium)
	t.Logf("  Low: %d", stats.Low)
	t.Logf("  Other: %d", stats.Other)

	// Verify stats are consistent
	expectedTotal := stats.Critical + stats.High + stats.Medium + stats.Low + stats.Other
	if stats.Total != expectedTotal {
		t.Errorf("Total count mismatch: got %d, expected %d (sum of individual counts)",
			stats.Total, expectedTotal)
	}

	// Test passes if we got this far - the scan ran successfully
	t.Logf("End-to-end test completed successfully with grype version %s", output.Descriptor.Version)
}

// TestEndToEndGrypeScanWithDockerImage tests scanning a Docker image
func TestEndToEndGrypeScanWithDockerImage(t *testing.T) {
	// Find and setup grype
	if !setupGrype(t) {
		return // Test was skipped
	}

	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "docker-scan-results.json")

	// Test scanning alpine:3.7 Docker image (known to have vulnerabilities)
	// Note: This test may be skipped in CI environments without Docker daemon
	err := runGrypeScan("alpine:3.7", outputFile)

	// If the scan fails (e.g., no Docker daemon or database), skip the test
	if err != nil {
		if _, statErr := os.Stat(outputFile); os.IsNotExist(statErr) {
			t.Skipf("Docker image scan failed (likely no Docker daemon or grype database available): %v", err)
		}
	}

	// Check if output file exists and has content
	fileInfo, err := os.Stat(outputFile)
	if err != nil || fileInfo.Size() == 0 {
		t.Skip("Docker image scan did not produce output (Docker daemon or grype database may not be available)")
	}

	// Parse the output
	output, err := parseGrypeOutput(outputFile)
	if err != nil {
		t.Skipf("Failed to parse grype output: %v", err)
	}

	// Verify we got valid output
	if output.Descriptor.Version == "" {
		t.Error("Grype version is empty")
	}

	stats := calculateStats(output)
	t.Logf("Docker image scan completed: found %d vulnerabilities", stats.Total)
}

// setupGrype finds grype and sets up the PATH for testing
// Returns false if grype is not available (and skips the test)
func setupGrype(t *testing.T) bool {
	t.Helper()

	// Check if grype is available in standard locations
	grypeCmd := os.Getenv("GRYPE_PATH")
	if grypeCmd == "" {
		// Try to find grype in PATH first
		if path, err := exec.LookPath("grype"); err == nil {
			grypeCmd = path
		} else if _, err := os.Stat("/tmp/bin/grype"); err == nil {
			// Fall back to /tmp/bin/grype
			grypeCmd = "/tmp/bin/grype"
		} else {
			t.Skip("Grype not available. Set GRYPE_PATH or install grype to /tmp/bin/grype or PATH")
			return false
		}
	}

	// If using /tmp/bin/grype, add to PATH
	if grypeCmd == "/tmp/bin/grype" {
		oldPath := os.Getenv("PATH")
		_ = os.Setenv("PATH", "/tmp/bin:"+oldPath)
		t.Cleanup(func() {
			_ = os.Setenv("PATH", oldPath)
		})
	}

	return true
}

// TestIntegrationWithMockGrypeOutput tests the integration flow with pre-generated grype output
// This test doesn't require grype to be installed and simulates a realistic scan result
func TestIntegrationWithMockGrypeOutput(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	mockOutputFile := filepath.Join(tmpDir, "mock-grype-output.json")

	// Create realistic mock grype output (simulating a real scan result)
	mockGrypeOutput := `{
		"matches": [
			{
				"vulnerability": {
					"id": "CVE-2023-1234",
					"severity": "Critical"
				},
				"artifact": {
					"name": "libssl",
					"version": "1.0.2"
				}
			},
			{
				"vulnerability": {
					"id": "CVE-2023-5678",
					"severity": "High"
				},
				"artifact": {
					"name": "bash",
					"version": "4.3.0"
				}
			},
			{
				"vulnerability": {
					"id": "CVE-2023-9012",
					"severity": "Medium"
				},
				"artifact": {
					"name": "curl",
					"version": "7.47.0"
				}
			}
		],
		"descriptor": {
			"version": "0.107.0",
			"db": {
				"status": {
					"built": "2024-01-30T10:00:00Z",
					"schemaVersion": 6
				}
			}
		}
	}`

	// Write mock output to file
	if err := os.WriteFile(mockOutputFile, []byte(mockGrypeOutput), 0644); err != nil {
		t.Fatalf("Failed to write mock output: %v", err)
	}

	// Test the complete integration flow from parsing to stats
	t.Run("parse_mock_output", func(t *testing.T) {
		output, err := parseGrypeOutput(mockOutputFile)
		if err != nil {
			t.Fatalf("Failed to parse mock output: %v", err)
		}

		// Verify descriptor
		if output.Descriptor.Version != "0.107.0" {
			t.Errorf("Expected version 0.107.0, got %s", output.Descriptor.Version)
		}

		if output.DBBuilt() != "2024-01-30T10:00:00Z" {
			t.Errorf("Expected DB built time 2024-01-30T10:00:00Z, got %s", output.DBBuilt())
		}

		// Verify matches
		if len(output.Matches) != 3 {
			t.Errorf("Expected 3 matches, got %d", len(output.Matches))
		}
	})

	t.Run("calculate_stats_from_mock", func(t *testing.T) {
		output, err := parseGrypeOutput(mockOutputFile)
		if err != nil {
			t.Fatalf("Failed to parse mock output: %v", err)
		}

		stats := calculateStats(output)

		// Verify stats match the mock data
		if stats.Total != 3 {
			t.Errorf("Expected 3 total vulnerabilities, got %d", stats.Total)
		}
		if stats.Critical != 1 {
			t.Errorf("Expected 1 critical vulnerability, got %d", stats.Critical)
		}
		if stats.High != 1 {
			t.Errorf("Expected 1 high vulnerability, got %d", stats.High)
		}
		if stats.Medium != 1 {
			t.Errorf("Expected 1 medium vulnerability, got %d", stats.Medium)
		}
		if stats.Low != 0 {
			t.Errorf("Expected 0 low vulnerabilities, got %d", stats.Low)
		}
	})

	t.Run("copy_output_file", func(t *testing.T) {
		destPath := filepath.Join(tmpDir, "copied-output.json")
		copiedPath, err := copyOutputFile(mockOutputFile, destPath)
		if err != nil {
			t.Fatalf("Failed to copy output file: %v", err)
		}

		// Verify the file was copied
		if _, err := os.Stat(copiedPath); os.IsNotExist(err) {
			t.Error("Copied file does not exist")
		}

		// Verify content matches
		originalContent, _ := os.ReadFile(mockOutputFile)
		copiedContent, _ := os.ReadFile(copiedPath)
		if string(originalContent) != string(copiedContent) {
			t.Error("Copied file content does not match original")
		}
	})

	t.Logf("Integration test with mock data completed successfully")
}

// TestHandleScanTarget tests the handleScanTarget function in a git repository
func TestHandleScanTarget(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping test")
	}

	// Create a temporary git repository for testing
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Configure git user for commits
	cmd = exec.Command("git", "config", "user.email", "test@test.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git email: %v", err)
	}
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git name: %v", err)
	}

	// Create initial commit
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "initial commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Create a tag
	cmd = exec.Command("git", "tag", "v1.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create tag: %v", err)
	}

	// Create a branch
	cmd = exec.Command("git", "branch", "feature-branch")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create branch: %v", err)
	}

	// Save original directory and change to temp dir
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(origDir)
	}()

	tests := []struct {
		name    string
		scan    string
		wantErr bool
	}{
		{
			name:    "head checkout",
			scan:    "head",
			wantErr: false,
		},
		{
			name:    "HEAD uppercase checkout",
			scan:    "HEAD",
			wantErr: false,
		},
		{
			name:    "tag checkout",
			scan:    "v1.0.0",
			wantErr: false,
		},
		{
			name:    "branch checkout",
			scan:    "feature-branch",
			wantErr: false,
		},
		{
			name:    "empty scan defaults to latest_release",
			scan:    "",
			wantErr: false,
		},
		{
			name:    "whitespace scan defaults to latest_release",
			scan:    "  ",
			wantErr: false,
		},
		{
			name:    "non-existent ref",
			scan:    "non-existent-ref-xyz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset to default branch before each test
			checkoutTestDefaultBranch(t)

			err := handleScanTarget(tt.scan)
			if (err != nil) != tt.wantErr {
				t.Errorf("handleScanTarget(%q) error = %v, wantErr %v", tt.scan, err, tt.wantErr)
			}
		})
	}
}

// TestGetDefaultBranch tests the getDefaultBranch function
func TestGetDefaultBranch(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping test")
	}

	// Create a temporary git repository for testing
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Configure git user for commits
	cmd = exec.Command("git", "config", "user.email", "test@test.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git email: %v", err)
	}
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git name: %v", err)
	}

	// Create initial commit (this creates the default branch)
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "initial commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Save original directory and change to temp dir
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(origDir)
	}()

	// Test getDefaultBranch
	branch, err := getDefaultBranch()
	if err != nil {
		t.Errorf("getDefaultBranch() error = %v", err)
	}
	// Should be either "main" or "master" depending on git version
	if branch != "main" && branch != "master" {
		t.Errorf("getDefaultBranch() = %q, want 'main' or 'master'", branch)
	}
}

// TestGetLatestReleaseTag tests the getLatestReleaseTag function
func TestGetLatestReleaseTag(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping test")
	}

	// Create a temporary git repository for testing
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Configure git user for commits
	cmd = exec.Command("git", "config", "user.email", "test@test.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git email: %v", err)
	}
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git name: %v", err)
	}

	// Create initial commit
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "initial commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Save original directory and change to temp dir
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(origDir)
	}()

	// Test with no tags
	t.Run("no tags", func(t *testing.T) {
		_, err := getLatestReleaseTag()
		if err == nil {
			t.Error("getLatestReleaseTag() expected error when no tags exist, got nil")
		}
	})

	// Create some tags
	cmd = exec.Command("git", "tag", "v1.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create tag v1.0.0: %v", err)
	}

	// Make another commit and tag
	if err := os.WriteFile(testFile, []byte("updated content"), 0644); err != nil {
		t.Fatalf("Failed to update test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	_ = cmd.Run()
	cmd = exec.Command("git", "commit", "-m", "second commit")
	cmd.Dir = tmpDir
	_ = cmd.Run()
	cmd = exec.Command("git", "tag", "v2.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create tag v2.0.0: %v", err)
	}

	// Test with multiple tags
	t.Run("multiple tags", func(t *testing.T) {
		tag, err := getLatestReleaseTag()
		if err != nil {
			t.Errorf("getLatestReleaseTag() error = %v", err)
		}
		// With version sorting, v2.0.0 should come first
		if tag != "v2.0.0" {
			t.Errorf("getLatestReleaseTag() = %q, want 'v2.0.0'", tag)
		}
	})
}

// TestCheckoutRef tests the checkoutRef function
func TestCheckoutRef(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping test")
	}

	// Create a temporary git repository for testing
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Configure git user for commits
	cmd = exec.Command("git", "config", "user.email", "test@test.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git email: %v", err)
	}
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git name: %v", err)
	}

	// Create initial commit
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "initial commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Create a tag
	cmd = exec.Command("git", "tag", "v1.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create tag: %v", err)
	}

	// Create a branch
	cmd = exec.Command("git", "branch", "test-branch")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create branch: %v", err)
	}

	// Save original directory and change to temp dir
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(origDir)
	}()

	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{
			name:    "checkout tag",
			ref:     "v1.0.0",
			wantErr: false,
		},
		{
			name:    "checkout branch",
			ref:     "test-branch",
			wantErr: false,
		},
		{
			name:    "checkout non-existent ref",
			ref:     "non-existent-ref",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkoutRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkoutRef(%q) error = %v, wantErr %v", tt.ref, err, tt.wantErr)
			}
		})
	}
}

// TestHandleScanTargetLatestRelease tests the latest_release functionality
func TestHandleScanTargetLatestRelease(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping test")
	}

	// Create a temporary git repository for testing
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Configure git user for commits
	cmd = exec.Command("git", "config", "user.email", "test@test.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git email: %v", err)
	}
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git name: %v", err)
	}

	// Create initial commit
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "initial commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Save original directory and change to temp dir
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(origDir)
	}()

	// Test latest_release with no tags (should fail)
	t.Run("no tags", func(t *testing.T) {
		err := handleScanTarget("latest_release")
		if err == nil {
			t.Error("handleScanTarget('latest_release') expected error when no tags exist")
		}
	})

	// Create a tag
	cmd = exec.Command("git", "tag", "v1.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create tag: %v", err)
	}

	// Test latest_release with a tag
	// Note: This test verifies error handling only. Content verification
	// (ensuring the correct tag is checked out) is done in TestScanLatestRelease.
	t.Run("with tag", func(t *testing.T) {
		err := handleScanTarget("latest_release")
		if err != nil {
			t.Errorf("handleScanTarget('latest_release') error = %v", err)
		}
	})

	// Test LATEST_RELEASE (case insensitive)
	t.Run("case insensitive", func(t *testing.T) {
		err := handleScanTarget("LATEST_RELEASE")
		if err != nil {
			t.Errorf("handleScanTarget('LATEST_RELEASE') error = %v", err)
		}
	})
}

// TestScanBranch verifies that scanning a branch checks out the correct content
func TestScanBranch(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping test")
	}

	// Create a temporary git repository for testing
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Configure git user for commits
	cmd = exec.Command("git", "config", "user.email", "test@test.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git email: %v", err)
	}
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git name: %v", err)
	}

	// Create initial commit on main/master branch
	testFile := filepath.Join(tmpDir, "version.txt")
	if err := os.WriteFile(testFile, []byte("main-content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "initial commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Create a feature branch with different content
	cmd = exec.Command("git", "checkout", "-b", "feature-branch")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create feature branch: %v", err)
	}
	if err := os.WriteFile(testFile, []byte("feature-branch-content"), 0644); err != nil {
		t.Fatalf("Failed to update test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "feature branch commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Go back to default branch
	checkoutTestDefaultBranchInDir(t, tmpDir)

	// Save original directory and change to temp dir
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(origDir)
	}()

	// Scan the feature branch
	err = handleScanTarget("feature-branch")
	if err != nil {
		t.Fatalf("handleScanTarget('feature-branch') error = %v", err)
	}

	// Verify we're on the feature branch by checking file content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}
	if string(content) != "feature-branch-content" {
		t.Errorf("Expected 'feature-branch-content', got '%s'", string(content))
	}
}

// TestScanTag verifies that scanning a tag checks out the correct content
func TestScanTag(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping test")
	}

	// Create a temporary git repository for testing
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Configure git user for commits
	cmd = exec.Command("git", "config", "user.email", "test@test.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git email: %v", err)
	}
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git name: %v", err)
	}

	// Create initial commit
	testFile := filepath.Join(tmpDir, "version.txt")
	if err := os.WriteFile(testFile, []byte("v1.0.0-content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "release v1.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Create a tag at this commit
	cmd = exec.Command("git", "tag", "v1.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create tag: %v", err)
	}

	// Make another commit with different content (simulating ongoing development)
	if err := os.WriteFile(testFile, []byte("development-content"), 0644); err != nil {
		t.Fatalf("Failed to update test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "development commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Save original directory and change to temp dir
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(origDir)
	}()

	// Scan the tag
	err = handleScanTarget("v1.0.0")
	if err != nil {
		t.Fatalf("handleScanTarget('v1.0.0') error = %v", err)
	}

	// Verify we're at the tag by checking file content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}
	if string(content) != "v1.0.0-content" {
		t.Errorf("Expected 'v1.0.0-content', got '%s'", string(content))
	}
}

// TestScanLatestRelease verifies that scanning latest_release checks out the latest tag
func TestScanLatestRelease(t *testing.T) {
	// Skip if git is not available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping test")
	}

	// Create a temporary git repository for testing
	tmpDir := t.TempDir()

	// Initialize git repo
	cmd := exec.Command("git", "init")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to init git repo: %v", err)
	}

	// Configure git user for commits
	cmd = exec.Command("git", "config", "user.email", "test@test.com")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git email: %v", err)
	}
	cmd = exec.Command("git", "config", "user.name", "Test User")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to configure git name: %v", err)
	}

	// Create initial commit for v1.0.0
	testFile := filepath.Join(tmpDir, "version.txt")
	if err := os.WriteFile(testFile, []byte("v1.0.0-content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "release v1.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Create tag v1.0.0
	cmd = exec.Command("git", "tag", "v1.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create tag v1.0.0: %v", err)
	}

	// Create commit for v2.0.0
	if err := os.WriteFile(testFile, []byte("v2.0.0-content"), 0644); err != nil {
		t.Fatalf("Failed to update test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "release v2.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Create tag v2.0.0 (the latest release)
	cmd = exec.Command("git", "tag", "v2.0.0")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to create tag v2.0.0: %v", err)
	}

	// Make another commit (simulating ongoing development after the release)
	if err := os.WriteFile(testFile, []byte("development-content"), 0644); err != nil {
		t.Fatalf("Failed to update test file: %v", err)
	}
	cmd = exec.Command("git", "add", ".")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git add: %v", err)
	}
	cmd = exec.Command("git", "commit", "-m", "development commit")
	cmd.Dir = tmpDir
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to git commit: %v", err)
	}

	// Save original directory and change to temp dir
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change to temp directory: %v", err)
	}
	defer func() {
		_ = os.Chdir(origDir)
	}()

	// Scan latest_release
	err = handleScanTarget("latest_release")
	if err != nil {
		t.Fatalf("handleScanTarget('latest_release') error = %v", err)
	}

	// Verify we're at the latest release (v2.0.0) by checking file content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}
	if string(content) != "v2.0.0-content" {
		t.Errorf("Expected 'v2.0.0-content', got '%s'", string(content))
	}
}
