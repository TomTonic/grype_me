package main

import (
	"testing"
)

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

func TestParseBoolEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		envValue     string
		defaultValue bool
		setEnv       bool
		want         bool
	}{
		{"true value", "TEST_BOOL", "true", false, true, true},
		{"TRUE value", "TEST_BOOL", "TRUE", false, true, true},
		{"false value", "TEST_BOOL", "false", true, true, false},
		{"empty uses default true", "TEST_BOOL_EMPTY", "", true, false, true},
		{"empty uses default false", "TEST_BOOL_EMPTY", "", false, false, false},
		{"invalid value", "TEST_BOOL", "yes", false, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(tt.key, tt.envValue)
			}
			got := parseBoolEnv(tt.key, tt.defaultValue)
			if got != tt.want {
				t.Errorf("parseBoolEnv() = %v, want %v", got, tt.want)
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
	t.Setenv("INPUT_GIST-TOKEN", "ghp_test123")
	t.Setenv("INPUT_GIST-ID", "abc123def")
	t.Setenv("INPUT_GIST-FILENAME", "my-scan")

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
	if config.GistToken != "ghp_test123" {
		t.Errorf("config.GistToken = %v, want ghp_test123", config.GistToken)
	}
	if config.GistID != "abc123def" {
		t.Errorf("config.GistID = %v, want abc123def", config.GistID)
	}
	if config.GistFilename != "my-scan" {
		t.Errorf("config.GistFilename = %v, want my-scan", config.GistFilename)
	}
}

func TestDetermineScanMode(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   string
	}{
		{"image scan", Config{Image: "alpine:latest"}, "image"},
		{"path scan", Config{Path: "./src"}, "path"},
		{"sbom scan", Config{SBOM: "sbom.json"}, "sbom"},
		{"latest_release scan (explicit)", Config{Scan: "latest_release"}, "release"},
		{"latest_release scan (default)", Config{Scan: ""}, "release"},
		{"head scan", Config{Scan: "head"}, "head"},
		{"specific ref scan", Config{Scan: "v1.2.3"}, "ref"},
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
