package main

import (
	"path"
	"strings"
	"testing"
)

// containsControl reports whether the string has ASCII control characters.
func containsControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] == 127 {
			return true
		}
	}
	return false
}

// hasInvalidPattern reports whether the ref includes characters that Git forbids.
func hasInvalidPattern(ref string) bool {
	forbidden := []string{"..", "~", "^", ":", "?", "*", "[", "\\", " "}
	for _, pat := range forbidden {
		if strings.Contains(ref, pat) {
			return true
		}
	}
	return false
}

func FuzzValidateRefName(f *testing.F) {
	seeds := []string{
		"main",
		"v1.0.0",
		"feature/new",
		"../etc/passwd",
		"branch with space",
		"heads~1",
		"tag^invalid",
		"leading.",
		"trailing/",
		"line\nbreak",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, ref string) {
		err := validateRefName(ref)

		invalid := ref == "" || containsControl(ref) || hasInvalidPattern(ref) ||
			strings.HasPrefix(ref, ".") || strings.HasSuffix(ref, ".") ||
			strings.HasPrefix(ref, "/") || strings.HasSuffix(ref, "/")

		if invalid && err == nil {
			t.Fatalf("validateRefName(%q) expected error for invalid ref", ref)
		}
	})
}

// anchorRuneAllowed checks gist anchor characters stay within the expected safe set.
func anchorRuneAllowed(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
}

func FuzzBuildGistFileAnchor(f *testing.F) {
	seeds := []string{
		"grype-release.md",
		"My Report.md",
		"notes.TXT",
		"",
		"file_with_underscores.MD",
		"contains spaces.md",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, name string) {
		anchor := buildGistFileAnchor(name)

		if name == "" {
			if anchor != "" {
				t.Fatalf("empty filename should produce empty anchor, got %q", anchor)
			}
			return
		}

		if anchor == "" {
			t.Fatalf("anchor should not be empty for %q", name)
		}
		if anchor != strings.ToLower(anchor) {
			t.Fatalf("anchor must be lower-case: %q", anchor)
		}
		if !strings.HasPrefix(anchor, "file-") {
			t.Fatalf("anchor must start with file-: %q", anchor)
		}
		for _, r := range anchor {
			if !anchorRuneAllowed(r) {
				t.Fatalf("anchor contains invalid rune %q for input %q", r, name)
			}
		}
	})
}

func FuzzStripCommitHash(f *testing.F) {
	seeds := []string{
		"https://gist.githubusercontent.com/user/id/raw/abcdef/badge.json",
		"https://gist.githubusercontent.com/user/id/raw/badge.json",
		"https://example.com/other/url",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, rawURL string) {
		got := stripCommitHash(rawURL)

		if strings.Contains(rawURL, "/raw/") {
			if !strings.Contains(got, "/raw/") {
				t.Fatalf("result lost raw segment: %q", got)
			}
			if path.Base(got) != path.Base(rawURL) {
				t.Fatalf("expected base %q to be preserved, got %q", path.Base(rawURL), path.Base(got))
			}
		}
	})
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func FuzzDetermineBadgeColor(f *testing.F) {
	f.Add(0, 0, 0, 0, 0)
	f.Add(1, 0, 0, 0, 0)
	f.Add(0, 2, 0, 0, 0)
	f.Add(0, 0, 3, 0, 0)
	f.Add(0, 0, 0, 4, 0)

	allowed := map[string]struct{}{
		"critical":    {},
		"orange":      {},
		"yellow":      {},
		"yellowgreen": {},
		"brightgreen": {},
	}

	f.Fuzz(func(t *testing.T, critical, high, medium, low, other int) {
		stats := VulnerabilityStats{
			Critical: absInt(critical % 50),
			High:     absInt(high % 50),
			Medium:   absInt(medium % 50),
			Low:      absInt(low % 50),
			Other:    absInt(other % 50),
		}

		color := determineBadgeColor(stats)
		if _, ok := allowed[color]; !ok {
			t.Fatalf("unexpected color %q", color)
		}

		switch {
		case stats.Critical > 0 && color != "critical":
			t.Fatalf("critical present, color must be critical (got %q)", color)
		case stats.Critical == 0 && stats.High > 0 && color != "orange":
			t.Fatalf("high present without critical, color must be orange (got %q)", color)
		case stats.Critical == 0 && stats.High == 0 && stats.Medium > 0 && color != "yellow":
			t.Fatalf("medium present without higher severities, color must be yellow (got %q)", color)
		case stats.Critical == 0 && stats.High == 0 && stats.Medium == 0 && (stats.Low > 0 || stats.Other > 0) && color != "yellowgreen":
			t.Fatalf("only low/other present, color must be yellowgreen (got %q)", color)
		case stats.Critical == 0 && stats.High == 0 && stats.Medium == 0 && stats.Low == 0 && stats.Other == 0 && color != "brightgreen":
			t.Fatalf("no vulnerabilities, color must be brightgreen (got %q)", color)
		}
	})
}
