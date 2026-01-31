// Package main provides Git operations for repository-based scanning.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// configureGitSafeDirectory adds the current working directory to Git's safe.directory config.
// This is necessary when running in a Docker container where the workspace may be owned
// by a different user than the Git process.
func configureGitSafeDirectory() error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Add current directory to safe.directory
	cmd := exec.Command("git", "config", "--global", "--add", "safe.directory", cwd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure git safe.directory: %w", err)
	}

	// Also add GITHUB_WORKSPACE if in GitHub Actions Docker environment
	if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" && workspace != cwd {
		cmd = exec.Command("git", "config", "--global", "--add", "safe.directory", workspace)
		_ = cmd.Run() // Non-fatal if this fails
	}

	return nil
}

// getLatestReleaseTag returns the latest stable release tag from the repository.
// Tags are sorted by semantic version (descending), and pre-release tags are excluded
// unless all tags are pre-releases.
func getLatestReleaseTag() (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git not found: %w", err)
	}

	// Fetch all tags to ensure we have the latest
	fmt.Println("Fetching tags...")
	fetchCmd := exec.Command("git", "fetch", "--tags", "--force")
	fetchCmd.Stdout = os.Stdout
	fetchCmd.Stderr = os.Stderr
	if err := fetchCmd.Run(); err != nil {
		fmt.Printf("Warning: Could not fetch tags: %v\n", err)
	}

	// Get all tags sorted by version (descending)
	listCmd := exec.Command("git", "tag", "--sort=-v:refname")
	output, err := listCmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to list tags: %w", err)
	}

	tags := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(tags) == 0 || tags[0] == "" {
		return "", fmt.Errorf("no release tags found in repository. Use 'scan: head' to scan the current checkout, or create a semver tag (e.g., v1.0.0)")
	}

	// Find the first stable (non-pre-release) tag
	for _, tag := range tags {
		if !isPreReleaseTag(tag) {
			return tag, nil
		}
	}

	// If all tags are pre-release, use the highest one with a warning
	fmt.Printf("Warning: All tags appear to be pre-release. Using: %s\n", tags[0])
	return tags[0], nil
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

	// Create a temporary directory for the worktree
	tmpDir, err := os.MkdirTemp("", "grype-scan-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	fmt.Printf("Creating temporary worktree at %s for ref %s\n", tmpDir, ref)

	// Add the worktree in detached HEAD mode
	worktreeCmd := exec.Command("git", "worktree", "add", "--detach", tmpDir, ref)
	worktreeCmd.Stdout = os.Stdout
	worktreeCmd.Stderr = os.Stderr
	if err := worktreeCmd.Run(); err != nil {
		// Clean up temp dir on failure
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("failed to create worktree: %w", err)
	}

	return tmpDir, nil
}

// cleanupWorktree removes a temporary Git worktree and its directory.
// This should be called (typically via defer) after scanning is complete.
func cleanupWorktree(worktreeDir string) {
	if worktreeDir == "" {
		return
	}

	fmt.Printf("Cleaning up temporary worktree at %s\n", worktreeDir)

	// Remove the worktree from Git's tracking
	removeCmd := exec.Command("git", "worktree", "remove", "--force", worktreeDir)
	if err := removeCmd.Run(); err != nil {
		fmt.Printf("Warning: git worktree remove failed: %v\n", err)
	}

	// Ensure the directory is removed even if git worktree remove failed
	if err := os.RemoveAll(worktreeDir); err != nil {
		fmt.Printf("Warning: failed to remove worktree directory: %v\n", err)
	}
}

// handleRepoScan handles repository-based scanning (latest_release, head, or specific ref).
// Returns (target, tempDir, error) where tempDir is set if a temporary worktree was created.
func handleRepoScan(scanMode string) (string, string, error) {
	// Configure Git safe directories for Docker container environment
	if err := configureGitSafeDirectory(); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

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
