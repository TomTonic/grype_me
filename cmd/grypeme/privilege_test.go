package main

import (
	"errors"
	"os"
	"testing"
)

func resetPrivilegeFns() {
	getUID = os.Getuid
	getEUID = os.Geteuid
	statFn = os.Stat
	chownFn = os.Chown
	setgidFn = func(int) error { return nil }
	setuidFn = func(int) error { return nil }
	getenvFn = os.Getenv
	runtimePrivilegeMode = "unknown"
	runtimePrivilegeDetail = ""
}

func TestDropPrivilegesNonRootNoop(t *testing.T) {
	defer resetPrivilegeFns()

	calledSetgid := false
	calledSetuid := false
	getUID = func() int { return 1000 }
	getEUID = func() int { return 1000 }
	setgidFn = func(int) error {
		calledSetgid = true
		return nil
	}
	setuidFn = func(int) error {
		calledSetuid = true
		return nil
	}

	if err := dropPrivileges(); err != nil {
		t.Fatalf("dropPrivileges() unexpected error: %v", err)
	}
	if calledSetgid || calledSetuid {
		t.Fatalf("dropPrivileges() should not call setgid/setuid for non-root")
	}
}

func TestDropPrivilegesSetgidFailure(t *testing.T) {
	defer resetPrivilegeFns()

	getUID = func() int { return 0 }
	getEUID = func() int { return 0 }
	statFn = func(string) (os.FileInfo, error) { return nil, errors.New("not found") }
	setgidFn = func(int) error { return errors.New("setgid failed") }
	setuidFn = func(int) error { return nil }

	err := dropPrivileges()
	if err == nil || err.Error() == "" {
		t.Fatal("dropPrivileges() expected setgid error")
	}
}

func TestDropPrivilegesSetuidFailure(t *testing.T) {
	defer resetPrivilegeFns()

	getUID = func() int { return 0 }
	getEUID = func() int { return 0 }
	statFn = func(string) (os.FileInfo, error) { return nil, errors.New("not found") }
	setgidFn = func(int) error { return nil }
	setuidFn = func(int) error { return errors.New("setuid failed") }

	err := dropPrivileges()
	if err == nil || err.Error() == "" {
		t.Fatal("dropPrivileges() expected setuid error")
	}
}

func TestDropPrivilegesVerificationFailure(t *testing.T) {
	defer resetPrivilegeFns()

	uid := 0
	getUID = func() int { return uid }
	getEUID = func() int { return 0 }
	statFn = func(string) (os.FileInfo, error) { return nil, errors.New("not found") }
	setgidFn = func(int) error { return nil }
	setuidFn = func(int) error {
		// Simulate failure to actually switch UID.
		return nil
	}

	err := dropPrivileges()
	if err == nil {
		t.Fatal("dropPrivileges() expected verification failure")
	}
}

func TestDropPrivilegesSuccessPath(t *testing.T) {
	defer resetPrivilegeFns()

	uid := 0
	euid := 0
	getUID = func() int { return uid }
	getEUID = func() int { return euid }
	statFn = func(string) (os.FileInfo, error) { return nil, errors.New("not found") }
	setgidFn = func(int) error { return nil }
	setuidFn = func(int) error {
		uid = NonPrivilegedUID
		euid = NonPrivilegedUID
		return nil
	}

	if err := dropPrivileges(); err != nil {
		t.Fatalf("dropPrivileges() unexpected error: %v", err)
	}

	mode, detail := getRuntimePrivilegeInfo()
	if mode != "dropped" || detail != "" {
		t.Fatalf("runtime privilege info = (%q, %q), want (%q, %q)", mode, detail, "dropped", "")
	}
}

func TestDropPrivilegesSkipsWhenGitHubOutputCannotBePrepared(t *testing.T) {
	defer resetPrivilegeFns()

	uid := 0
	euid := 0
	calledSetgid := false
	calledSetuid := false

	getUID = func() int { return uid }
	getEUID = func() int { return euid }
	getenvFn = func(key string) string {
		if key == "GITHUB_OUTPUT" {
			return "/github/file_commands/set_output_test"
		}
		return ""
	}
	statFn = func(path string) (os.FileInfo, error) {
		if path == "/github/file_commands" || path == "/github/file_commands/set_output_test" || path == "/github/workspace" {
			return nil, nil
		}
		return nil, errors.New("not found")
	}
	chownFn = func(path string, uid int, gid int) error {
		if path == "/github/file_commands/set_output_test" {
			return errors.New("operation not permitted")
		}
		return nil
	}
	setgidFn = func(int) error {
		calledSetgid = true
		return nil
	}
	setuidFn = func(int) error {
		calledSetuid = true
		return nil
	}

	if err := dropPrivileges(); err != nil {
		t.Fatalf("dropPrivileges() unexpected error: %v", err)
	}

	if calledSetgid || calledSetuid {
		t.Fatalf("dropPrivileges() should skip setgid/setuid when GITHUB_OUTPUT cannot be prepared")
	}
	if uid != 0 || euid != 0 {
		t.Fatalf("expected to remain root, got uid=%d euid=%d", uid, euid)
	}

	mode, detail := getRuntimePrivilegeInfo()
	if mode != "root-fallback" || detail == "" {
		t.Fatalf("runtime privilege info = (%q, %q), want root-fallback with detail", mode, detail)
	}
}

func TestDropPrivilegesPreparesGitHubOutputAndDrops(t *testing.T) {
	defer resetPrivilegeFns()

	uid := 0
	euid := 0
	calledSetgid := false
	calledSetuid := false
	chowned := map[string]bool{}

	getUID = func() int { return uid }
	getEUID = func() int { return euid }
	getenvFn = func(key string) string {
		if key == "GITHUB_OUTPUT" {
			return "/github/file_commands/set_output_test"
		}
		return ""
	}
	statFn = func(path string) (os.FileInfo, error) {
		if path == "/github/file_commands" || path == "/github/file_commands/set_output_test" || path == "/github/workspace" {
			return nil, nil
		}
		return nil, errors.New("not found")
	}
	chownFn = func(path string, uid int, gid int) error {
		chowned[path] = true
		return nil
	}
	setgidFn = func(int) error {
		calledSetgid = true
		return nil
	}
	setuidFn = func(int) error {
		calledSetuid = true
		uid = NonPrivilegedUID
		euid = NonPrivilegedUID
		return nil
	}

	if err := dropPrivileges(); err != nil {
		t.Fatalf("dropPrivileges() unexpected error: %v", err)
	}

	if !calledSetgid || !calledSetuid {
		t.Fatalf("dropPrivileges() should call setgid/setuid when output paths are prepared")
	}
	if !chowned["/github/file_commands"] || !chowned["/github/file_commands/set_output_test"] {
		t.Fatalf("expected chown on GITHUB_OUTPUT dir and file, got: %#v", chowned)
	}

	mode, detail := getRuntimePrivilegeInfo()
	if mode != "dropped" || detail != "" {
		t.Fatalf("runtime privilege info = (%q, %q), want (%q, %q)", mode, detail, "dropped", "")
	}
}

func TestDropPrivilegesStrictModeFailsOnOutputPrepError(t *testing.T) {
	defer resetPrivilegeFns()

	getUID = func() int { return 0 }
	getEUID = func() int { return 0 }
	getenvFn = func(key string) string {
		switch key {
		case "GITHUB_OUTPUT":
			return "/github/file_commands/set_output_test"
		case "INPUT_STRICT-PRIVILEGE-DROP":
			return "true"
		default:
			return ""
		}
	}
	statFn = func(path string) (os.FileInfo, error) {
		if path == "/github/file_commands" || path == "/github/file_commands/set_output_test" {
			return nil, nil
		}
		return nil, errors.New("not found")
	}
	chownFn = func(string, int, int) error {
		return errors.New("operation not permitted")
	}

	err := dropPrivileges()
	if err == nil {
		t.Fatal("dropPrivileges() expected strict mode failure")
	}

	mode, detail := getRuntimePrivilegeInfo()
	if mode != "unknown" || detail == "" {
		t.Fatalf("runtime privilege info = (%q, %q), want unknown with detail", mode, detail)
	}
}

func TestParseBoolEnvVar(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"true", "true", true},
		{"TRUE", "TRUE", true},
		{"one", "1", true},
		{"yes", "yes", true},
		{"on", "on", true},
		{"false", "false", false},
		{"zero", "0", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseBoolEnvVar(tt.input); got != tt.want {
				t.Fatalf("parseBoolEnvVar(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
