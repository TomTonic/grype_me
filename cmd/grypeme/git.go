// Package main provides Git operations for repository-based scanning.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// getLatestReleaseTag returns the latest stable release tag from the repository.
// Tags are sorted by semantic version (descending), and pre-release tags are excluded
// unless all tags are pre-releases.
func getLatestReleaseTag() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	repo, err := git.PlainOpenWithOptions(cwd, &git.PlainOpenOptions{
		DetectDotGit:          true,
		EnableDotGitCommonDir: true,
	})
	if err != nil {
		return "", fmt.Errorf("failed to open git repository: %w", err)
	}

	// Fetch all tags to ensure we have the latest
	fmt.Println("Fetching tags...")
	err = repo.Fetch(&git.FetchOptions{
		RefSpecs: []config.RefSpec{"refs/tags/*:refs/tags/*"},
		Force:    true,
		Tags:     git.AllTags,
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		fmt.Printf("Warning: Could not fetch tags: %v\n", err)
	}

	// Get all tags
	tagRefs, err := repo.Tags()
	if err != nil {
		return "", fmt.Errorf("failed to list tags: %w", err)
	}

	var tagNames []string
	err = tagRefs.ForEach(func(ref *plumbing.Reference) error {
		tagNames = append(tagNames, ref.Name().Short())
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("failed to iterate tags: %w", err)
	}

	if len(tagNames) == 0 {
		return "", fmt.Errorf("no release tags found in repository. Use 'scan: head' to scan the current checkout, or create a semver tag (e.g., v1.0.0)")
	}

	// Sort tags by semver-aware order (descending), then lexical fallback.
	sort.Slice(tagNames, func(i, j int) bool {
		return compareTagsDesc(tagNames[i], tagNames[j]) < 0
	})

	// Find the first stable (non-pre-release) tag
	for _, tag := range tagNames {
		if !isPreReleaseTag(tag) {
			return tag, nil
		}
	}

	// If all tags are pre-release, use the highest one with a warning
	fmt.Printf("Warning: All tags appear to be pre-release. Using: %s\n", tagNames[0])
	return tagNames[0], nil
}

// compareTagsDesc compares two tags for descending sort order.
// Returns <0 when a should come before b, >0 when b before a, 0 when equal.
func compareTagsDesc(a, b string) int {
	av, aok := parseTagVersion(a)
	bv, bok := parseTagVersion(b)

	if aok && bok {
		if av.major != bv.major {
			return bv.major - av.major
		}
		if av.minor != bv.minor {
			return bv.minor - av.minor
		}
		if av.patch != bv.patch {
			return bv.patch - av.patch
		}
		// Stable releases sort before pre-releases.
		if av.pre == "" && bv.pre != "" {
			return -1
		}
		if av.pre != "" && bv.pre == "" {
			return 1
		}
		if av.pre != bv.pre {
			if av.pre > bv.pre {
				return -1
			}
			return 1
		}
		return 0
	}

	if aok && !bok {
		return -1
	}
	if !aok && bok {
		return 1
	}

	if a > b {
		return -1
	}
	if a < b {
		return 1
	}
	return 0
}

type tagVersion struct {
	major int
	minor int
	patch int
	pre   string
}

func parseTagVersion(tag string) (tagVersion, bool) {
	normalized := strings.TrimPrefix(strings.TrimPrefix(tag, "v"), "V")
	parts := strings.SplitN(normalized, "-", 2)
	core := parts[0]
	pre := ""
	if len(parts) == 2 {
		pre = parts[1]
	}

	nums := strings.Split(core, ".")
	if len(nums) == 0 || len(nums) > 3 {
		return tagVersion{}, false
	}

	values := []int{0, 0, 0}
	for i := 0; i < len(nums); i++ {
		if nums[i] == "" {
			return tagVersion{}, false
		}
		n, err := strconv.Atoi(nums[i])
		if err != nil {
			return tagVersion{}, false
		}
		values[i] = n
	}

	return tagVersion{major: values[0], minor: values[1], patch: values[2], pre: pre}, true
}

// isPreReleaseTag checks if a tag follows pre-release versioning conventions.
// A tag is considered pre-release if it contains a hyphen after the version number
// (e.g., "v1.0.0-alpha", "1.2.3-rc.1").
func isPreReleaseTag(tag string) bool {
	// Remove version prefix (v or V)
	normalized := strings.TrimPrefix(strings.TrimPrefix(tag, "v"), "V")

	parts := strings.SplitN(normalized, "-", 2)
	if len(parts) < 2 {
		return false // No hyphen, not a pre-release
	}

	// Verify the first part looks like a version number (digits and dots only)
	versionPart := parts[0]
	for _, char := range versionPart {
		if char != '.' && (char < '0' || char > '9') {
			return false // Not a valid version format
		}
	}

	// Must have both a valid version part and a pre-release identifier
	return len(versionPart) > 0 && len(parts[1]) > 0
}

// validateRefName validates a Git reference name for safety and correctness.
// It checks for invalid characters and patterns that could cause issues or security problems.
func validateRefName(ref string) error {
	if ref == "" {
		return fmt.Errorf("ref name cannot be empty")
	}

	// Check for control characters
	for position, char := range ref {
		if char < 32 || char == 127 {
			return fmt.Errorf("ref contains invalid control character at position %d", position)
		}
	}

	// Check for patterns that are invalid in Git ref names
	invalidPatterns := []string{"..", "~", "^", ":", "?", "*", "[", "\\", " "}
	for _, pattern := range invalidPatterns {
		if strings.Contains(ref, pattern) {
			return fmt.Errorf("ref contains invalid pattern %q", pattern)
		}
	}

	// Check for invalid start/end characters
	if strings.HasPrefix(ref, ".") || strings.HasSuffix(ref, ".") ||
		strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/") {
		return fmt.Errorf("ref cannot start or end with . or /")
	}

	return nil
}

// checkoutToWorktree creates a temporary Git worktree for the given ref.
// This allows scanning a specific tag or branch without modifying the user's workspace state.
// Returns the path to the temporary worktree directory.
func checkoutToWorktree(ref string) (string, error) {
	if err := validateRefName(ref); err != nil {
		return "", fmt.Errorf("invalid ref %q: %w", ref, err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	repo, err := git.PlainOpen(cwd)
	if err != nil {
		return "", fmt.Errorf("failed to open git repository: %w", err)
	}

	// Create a temporary directory for the worktree
	tmpDir, err := os.MkdirTemp("", "grype-scan-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	fmt.Printf("Creating temporary worktree at %s for ref %s\n", tmpDir, ref)

	// Resolve the ref to a hash
	hash, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to resolve ref %q: %w", ref, err)
	}

	commit, err := repo.CommitObject(*hash)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to load commit for %q: %w", ref, err)
	}

	err = materializeCommitToDir(commit, tmpDir)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to materialize worktree: %w", err)
	}

	return tmpDir, nil
}

// materializeCommitToDir writes a commit's tracked files into targetDir.
// This avoids invoking a system `git` binary, which is unavailable in scratch images.
func materializeCommitToDir(commit *object.Commit, targetDir string) error {
	tree, err := commit.Tree()
	if err != nil {
		return fmt.Errorf("failed to get commit tree: %w", err)
	}

	err = tree.Files().ForEach(func(file *object.File) error {
		destination := filepath.Join(targetDir, file.Name)
		if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			return fmt.Errorf("failed to create directory for %q: %w", file.Name, err)
		}

		switch file.Mode {
		case filemode.Submodule:
			// Submodule entries don't carry file content in-tree; skip gracefully.
			return nil
		case filemode.Symlink:
			target, err := file.Contents()
			if err != nil {
				return fmt.Errorf("failed to read symlink target for %q: %w", file.Name, err)
			}
			if err := os.Symlink(target, destination); err != nil {
				return fmt.Errorf("failed to create symlink %q: %w", file.Name, err)
			}
			return nil
		default:
			reader, err := file.Reader()
			if err != nil {
				return fmt.Errorf("failed to open file reader for %q: %w", file.Name, err)
			}
			defer func() { _ = reader.Close() }()

			output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, modeToPermissions(file.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file %q: %w", file.Name, err)
			}
			defer func() { _ = output.Close() }()

			if _, err := io.Copy(output, reader); err != nil {
				return fmt.Errorf("failed to write file %q: %w", file.Name, err)
			}
			return nil
		}
	})
	if err != nil {
		return err
	}

	return nil
}

func modeToPermissions(mode filemode.FileMode) os.FileMode {
	if mode == filemode.Executable {
		return 0755
	}
	return 0644
}

// cleanupWorktree removes a temporary Git worktree and its directory.
// This should be called (typically via defer) after scanning is complete.
func cleanupWorktree(worktreeDir string) {
	if worktreeDir == "" {
		return
	}

	fmt.Printf("Cleaning up temporary worktree at %s\n", worktreeDir)

	// Simply remove the directory (it's a standalone clone)
	if err := os.RemoveAll(worktreeDir); err != nil {
		fmt.Printf("Warning: failed to remove worktree directory: %v\n", err)
	}
}

// handleRepoScan handles repository-based scanning (latest_release, head, or specific ref).
// Returns (target, tempDir, error) where tempDir is set if a temporary worktree was created.
func handleRepoScan(scanMode string) (string, string, error) {
	fmt.Printf("Repository scan mode: %s\n", scanMode)

	switch strings.ToLower(scanMode) {
	case "head":
		// Scan current working directory as-is - no Git operations needed
		// The user has already checked out what they want via actions/checkout
		fmt.Println("Scanning current working directory (head mode)")
		return "dir:.", "", nil

	case "latest_release":
		// Get the latest release tag and checkout to a temporary worktree
		latestTag, err := getLatestReleaseTag()
		if err != nil {
			return "", "", fmt.Errorf("could not determine latest release: %w", err)
		}
		fmt.Printf("Found latest release: %s\n", latestTag)

		scanDir, err := checkoutToWorktree(latestTag)
		if err != nil {
			return "", "", fmt.Errorf("failed to checkout %s: %w", latestTag, err)
		}
		return "dir:" + scanDir, scanDir, nil

	default:
		// Treat as a specific tag or branch name
		fmt.Printf("Checking out ref: %s\n", scanMode)

		scanDir, err := checkoutToWorktree(scanMode)
		if err != nil {
			return "", "", fmt.Errorf("failed to checkout %s: %w", scanMode, err)
		}
		return "dir:" + scanDir, scanDir, nil
	}
}
