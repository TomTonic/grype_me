// Package main provides privilege management for secure container runtime.
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

var (
	getUID     = os.Getuid
	getEUID    = os.Geteuid
	statFn     = os.Stat
	chownFn    = os.Chown
	setgidFn   = syscall.Setgid
	setuidFn   = syscall.Setuid
	getenvFn   = os.Getenv
	openFileFn = os.OpenFile

	preopenedGitHubOutput *os.File

	// runtimePrivilegeMode describes effective runtime privilege handling.
	// Values: already-non-root, dropped, root-fallback.
	runtimePrivilegeMode = "unknown"
	// runtimePrivilegeDetail contains diagnostic context for fallback decisions.
	runtimePrivilegeDetail = ""
)

const (
	// NonPrivilegedUID is the UID for the unprivileged runtime user.
	NonPrivilegedUID = 10001
	// NonPrivilegedGID is the GID for the unprivileged runtime user.
	NonPrivilegedGID = 10001
)

// dropPrivileges reduces process privileges for security hardening.
// If running as root (UID 0), it:
// 1. Ensures /github/workspace is writable for the unprivileged user
// 2. Drops to the unprivileged UID/GID (10001:10001)
// This prevents privilege escalation and limits the attack surface.
func dropPrivileges() error {
	currentUID := getUID()

	// If not running as root, no privilege drop needed
	if currentUID != 0 {
		runtimePrivilegeMode = "already-non-root"
		return nil
	}

	fmt.Printf("Running as root (UID 0), preparing to drop privileges to UID %d\n", NonPrivilegedUID)

	strictPrivilegeDrop := parseBoolEnvVar(getenvFn("INPUT_STRICT-PRIVILEGE-DROP")) ||
		parseBoolEnvVar(getenvFn("GRYPE_STRICT_PRIVILEGE_DROP"))

	if err := prepareGitHubOutputForPostDrop(); err != nil {
		reason := fmt.Sprintf("cannot pre-open GITHUB_OUTPUT before drop (%v)", err)
		runtimePrivilegeDetail = reason
		if strictPrivilegeDrop {
			return fmt.Errorf("strict privilege drop enabled; cannot drop privileges safely: %s", reason)
		}
		runtimePrivilegeMode = "root-fallback"
		fmt.Printf("Warning: Could not pre-open GITHUB_OUTPUT for post-drop writes. Continuing as root to preserve GitHub Actions outputs.\n")
		if reason != "" {
			fmt.Printf("Warning: privilege fallback reason: %s\n", reason)
		}
		return nil
	}

	// Ensure /github/workspace exists and is writable for the unprivileged user.
	// We intentionally avoid mutating GitHub file-command mount ownership
	// (e.g., GITHUB_OUTPUT parent dirs), which can break runner post-steps.
	workspaceDir := "/github/workspace"
	if _, err := statFn(workspaceDir); err == nil {
		// Fix ownership of workspace directory if it exists
		if err := chownFn(workspaceDir, NonPrivilegedUID, NonPrivilegedGID); err != nil {
			// Non-fatal: log warning and continue
			fmt.Printf("Warning: Could not chown %s: %v\n", workspaceDir, err)
		}
	}

	// Drop group privileges first (must be done before dropping user privileges)
	if err := setgidFn(NonPrivilegedGID); err != nil {
		return fmt.Errorf("failed to set GID %d: %w", NonPrivilegedGID, err)
	}

	// Drop user privileges
	if err := setuidFn(NonPrivilegedUID); err != nil {
		return fmt.Errorf("failed to set UID %d: %w", NonPrivilegedUID, err)
	}

	// Verify the drop was successful
	if getUID() != NonPrivilegedUID || getEUID() != NonPrivilegedUID {
		return fmt.Errorf("privilege drop verification failed: UID is %d (expected %d)", getUID(), NonPrivilegedUID)
	}

	runtimePrivilegeMode = "dropped"
	fmt.Printf("Successfully dropped privileges to UID %d, GID %d\n", NonPrivilegedUID, NonPrivilegedGID)
	return nil
}

func prepareGitHubOutputForPostDrop() error {
	outputPath := getenvFn("GITHUB_OUTPUT")
	if outputPath == "" {
		return nil
	}

	if preopenedGitHubOutput != nil {
		return nil
	}

	fileHandle, err := openFileFn(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	preopenedGitHubOutput = fileHandle
	return nil
}

func parseBoolEnvVar(value string) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func getRuntimePrivilegeInfo() (string, string) {
	return runtimePrivilegeMode, runtimePrivilegeDetail
}

func getGitHubOutputWriter(outputPath string) (*os.File, bool, error) {
	if preopenedGitHubOutput != nil {
		return preopenedGitHubOutput, true, nil
	}

	fileHandle, err := openFileFn(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, false, err
	}

	return fileHandle, false, nil
}
