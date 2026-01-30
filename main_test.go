package main

import (
	"encoding/json"
	"os"
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
