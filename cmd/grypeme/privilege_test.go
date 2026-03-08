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
}
