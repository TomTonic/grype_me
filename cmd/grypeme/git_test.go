package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
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

func TestCompareTagsDesc(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want int // negative => a before b, positive => b before a
	}{
		{"higher major first", "v2.0.0", "v1.9.9", -1},
		{"higher minor first", "v1.10.0", "v1.2.0", -1},
		{"higher patch first", "v1.2.4", "v1.2.3", -1},
		{"stable before prerelease", "v1.2.3", "v1.2.3-rc1", -1},
		{"semver before non-semver", "v1.2.3", "release-2026", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareTagsDesc(tt.a, tt.b)
			if (tt.want < 0 && got >= 0) || (tt.want > 0 && got <= 0) {
				t.Fatalf("compareTagsDesc(%q, %q) = %d, want sign %d", tt.a, tt.b, got, tt.want)
			}
		})
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

func TestGetLatestReleaseTagPrefersStable(t *testing.T) {
	repoDir := setupTestRepoWithTags(t)
	oldWD, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}

	tag, err := getLatestReleaseTag()
	if err != nil {
		t.Fatalf("getLatestReleaseTag() error = %v", err)
	}
	if tag != "v1.10.0" {
		t.Fatalf("getLatestReleaseTag() = %q, want %q", tag, "v1.10.0")
	}
}

func TestCheckoutToWorktreeByTag(t *testing.T) {
	repoDir := setupTestRepoWithTags(t)
	oldWD, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	if err := os.Chdir(repoDir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}

	worktreeDir, err := checkoutToWorktree("v1.0.0")
	if err != nil {
		t.Fatalf("checkoutToWorktree() error = %v", err)
	}
	t.Cleanup(func() { cleanupWorktree(worktreeDir) })

	if _, err := os.Stat(filepath.Join(worktreeDir, "README.md")); err != nil {
		t.Fatalf("expected checked out file missing: %v", err)
	}
}

func setupTestRepoWithTags(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit failed: %v", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree failed: %v", err)
	}

	writeAndCommit := func(content string, tag string) {
		file := filepath.Join(dir, "README.md")
		if err := os.WriteFile(file, []byte(content), 0644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
		if _, err := wt.Add("README.md"); err != nil {
			t.Fatalf("Add failed: %v", err)
		}
		hash, err := wt.Commit("commit "+tag, &git.CommitOptions{
			Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
		})
		if err != nil {
			t.Fatalf("Commit failed: %v", err)
		}
		if _, err := repo.CreateTag(tag, hash, nil); err != nil {
			t.Fatalf("CreateTag failed: %v", err)
		}
	}

	writeAndCommit("alpha", "v1.0.0-alpha")
	writeAndCommit("stable", "v1.0.0")
	writeAndCommit("higher minor", "v1.10.0")

	return dir
}
