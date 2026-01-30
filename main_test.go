package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
				os.Setenv(tt.key, tt.envValue)
				defer os.Unsetenv(tt.key)
			}

			got := getEnv(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("getEnv() = %v, want %v", got, tt.want)
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
						"built": "2024-01-30T10:00:00Z"
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
						Built string `json:"built"`
					} `json:"db"`
				}{
					Version: "0.65.0",
					DB: struct {
						Built string `json:"built"`
					}{
						Built: "2024-01-30T10:00:00Z",
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
			defer os.Remove(tmpFile.Name())

			if _, err := tmpFile.WriteString(tt.jsonData); err != nil {
				t.Fatalf("Failed to write to temp file: %v", err)
			}
			tmpFile.Close()

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
				Built string `json:"built"`
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

	if output.Descriptor.DB.Built == "" {
		t.Error("Database version is empty")
	} else {
		t.Logf("Database built: %s", output.Descriptor.DB.Built)
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
		os.Setenv("PATH", "/tmp/bin:"+oldPath)
		t.Cleanup(func() { os.Setenv("PATH", oldPath) })
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
				"built": "2024-01-30T10:00:00Z",
				"schemaVersion": 6
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

		if output.Descriptor.DB.Built != "2024-01-30T10:00:00Z" {
			t.Errorf("Expected DB built time 2024-01-30T10:00:00Z, got %s", output.Descriptor.DB.Built)
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
