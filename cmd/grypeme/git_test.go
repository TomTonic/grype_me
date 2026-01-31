package main

import (
	"os/exec"
	"testing"
)

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
		{"release-1.0", false},
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

func TestConfigureGitSafeDirectory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	err := configureGitSafeDirectory()
	if err != nil {
		t.Errorf("configureGitSafeDirectory() error = %v", err)
	}
}

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
