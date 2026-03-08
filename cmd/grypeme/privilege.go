// Package main provides privilege management for secure container runtime.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	getUID   = os.Getuid
	getEUID  = os.Geteuid
	statFn   = os.Stat
	chownFn  = os.Chown
	setgidFn = syscall.Setgid
	setuidFn = syscall.Setuid
	getenvFn = os.Getenv

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

	shouldSkip, reason := shouldSkipDropForOutputPath()
	if shouldSkip {
		runtimePrivilegeDetail = reason
		if strictPrivilegeDrop {
			return fmt.Errorf("strict privilege drop enabled; cannot drop privileges safely: %s", reason)
		}
		runtimePrivilegeMode = "root-fallback"
		fmt.Printf("Warning: Could not prepare GITHUB_OUTPUT for UID %d. Continuing as root to preserve GitHub Actions outputs.\n", NonPrivilegedUID)
		if reason != "" {
			fmt.Printf("Warning: privilege fallback reason: %s\n", reason)
		}
		return nil
	}

	// Ensure /github/workspace exists and is writable for the unprivileged user
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

// shouldSkipDropForOutputPath returns true when privilege dropping would break
// writing GitHub step outputs due to ownership restrictions on the mounted
// GITHUB_OUTPUT file/dir (common on some runner/container combinations).
func shouldSkipDropForOutputPath() (bool, string) {
	outputPath := getenvFn("GITHUB_OUTPUT")
	if outputPath == "" {
		return false, ""
	}

	paths := []string{filepath.Dir(outputPath), outputPath}
	for _, path := range paths {
		if _, err := statFn(path); err != nil {
			continue
		}
		if err := chownFn(path, NonPrivilegedUID, NonPrivilegedGID); err != nil {
			fmt.Printf("Warning: Could not chown %s: %v\n", path, err)
			return true, fmt.Sprintf("cannot chown %s to %d:%d (%v)", path, NonPrivilegedUID, NonPrivilegedGID, err)
		}
	}

	return false, ""
}

func parseBoolEnvVar(value string) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func getRuntimePrivilegeInfo() (string, string) {
	return runtimePrivilegeMode, runtimePrivilegeDetail
}
