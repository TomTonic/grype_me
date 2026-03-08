// Package main provides privilege management for secure container runtime.
package main

import (
	"fmt"
	"os"
	"syscall"
)

var (
	getUID   = os.Getuid
	getEUID  = os.Geteuid
	statFn   = os.Stat
	chownFn  = os.Chown
	setgidFn = syscall.Setgid
	setuidFn = syscall.Setuid
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
		return nil
	}

	fmt.Printf("Running as root (UID 0), preparing to drop privileges to UID %d\n", NonPrivilegedUID)

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

	fmt.Printf("Successfully dropped privileges to UID %d, GID %d\n", NonPrivilegedUID, NonPrivilegedGID)
	return nil
}
