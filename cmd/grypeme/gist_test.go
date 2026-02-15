package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewGistClient(t *testing.T) {
	c := NewGistClient("test-token")
	if c.Token != "test-token" {
		t.Errorf("Token = %q, want %q", c.Token, "test-token")
	}
	if c.BaseURL != "https://api.github.com" {
		t.Errorf("BaseURL = %q, want %q", c.BaseURL, "https://api.github.com")
	}
	if c.HTTPClient == nil {
		t.Error("HTTPClient should not be nil")
	}
}

func TestUpdateGist_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method and path
		if r.Method != http.MethodPatch {
			t.Errorf("method = %s, want PATCH", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/gists/abc123") {
			t.Errorf("path = %s, want /gists/abc123", r.URL.Path)
		}

		// Verify authorization header
		auth := r.Header.Get("Authorization")
		if auth != "token test-token" {
			t.Errorf("Authorization = %q, want %q", auth, "token test-token")
		}

		// Verify request body
		var req gistUpdateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if _, ok := req.Files["grype-release.json"]; !ok {
			t.Error("missing badge file in request")
		}
		if _, ok := req.Files["grype-release.md"]; !ok {
			t.Error("missing report file in request")
		}

		// Return mock response
		resp := gistResponse{
			HTMLURL: "https://gist.github.com/user/abc123",
			Files: map[string]gistFileInfo{
				"grype-release.json": {RawURL: "https://gist.githubusercontent.com/user/abc123/raw/deadbeef/grype-release.json"},
				"grype-release.md":   {RawURL: "https://gist.githubusercontent.com/user/abc123/raw/deadbeef/grype-release.md"},
			},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &GistClient{
		Token:      "test-token",
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}

	result, err := client.UpdateGist("abc123", "grype-release.json", "grype-release.md", map[string]string{
		"grype-release.json": `{"test":"badge"}`,
		"grype-release.md":   "# Report",
	})
	if err != nil {
		t.Fatalf("UpdateGist() error = %v", err)
	}

	if result.GistURL != "https://gist.github.com/user/abc123" {
		t.Errorf("GistURL = %q, want %q", result.GistURL, "https://gist.github.com/user/abc123")
	}
	if !strings.Contains(result.BadgeURL, "img.shields.io/endpoint") {
		t.Errorf("BadgeURL = %q, want shields.io endpoint URL", result.BadgeURL)
	}
	if !strings.Contains(result.BadgeURL, "grype-release.json") {
		t.Errorf("BadgeURL = %q, should contain badge filename", result.BadgeURL)
	}
	// Verify commit hash was stripped
	if strings.Contains(result.BadgeURL, "deadbeef") {
		t.Errorf("BadgeURL = %q, should not contain commit hash", result.BadgeURL)
	}
	if result.ReportURL == "" {
		t.Error("ReportURL should not be empty")
	}
	if result.ReportURL != "https://gist.github.com/user/abc123#file-grype-release-md" {
		t.Errorf("ReportURL = %q, want rendered gist anchor URL", result.ReportURL)
	}
}

func TestUpdateGist_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if _, err := fmt.Fprint(w, `{"message":"Not Found"}`); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer server.Close()

	client := &GistClient{
		Token:      "bad-token",
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}

	_, err := client.UpdateGist("nonexistent", "badge.json", "report.md", map[string]string{
		"badge.json": "{}",
		"report.md":  "# Report",
	})
	if err == nil {
		t.Fatal("UpdateGist() should return error for 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error = %v, want containing '404'", err)
	}
}

func TestUpdateGist_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := fmt.Fprint(w, `{"message":"Bad credentials"}`); err != nil {
			t.Fatalf("failed to write response: %v", err)
		}
	}))
	defer server.Close()

	client := &GistClient{
		Token:      "invalid",
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}

	_, err := client.UpdateGist("abc123", "badge.json", "report.md", map[string]string{
		"badge.json": "{}",
		"report.md":  "# Report",
	})
	if err == nil {
		t.Fatal("UpdateGist() should return error for 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error = %v, want containing '401'", err)
	}
}

func TestStripCommitHash(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard gist raw URL",
			input: "https://gist.githubusercontent.com/user/abc123/raw/deadbeef/file.json",
			want:  "https://gist.githubusercontent.com/user/abc123/raw/file.json",
		},
		{
			name:  "no raw segment",
			input: "https://example.com/other/url",
			want:  "https://example.com/other/url",
		},
		{
			name:  "raw with no hash",
			input: "https://gist.githubusercontent.com/user/abc123/raw/file.json",
			want:  "https://gist.githubusercontent.com/user/abc123/raw/file.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripCommitHash(tt.input)
			if got != tt.want {
				t.Errorf("stripCommitHash() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildEndpointBadgeURL(t *testing.T) {
	rawURL := "https://gist.githubusercontent.com/user/abc123/raw/deadbeef/badge.json"
	got := buildEndpointBadgeURL(rawURL)

	if !strings.HasPrefix(got, "https://img.shields.io/endpoint?url=") {
		t.Errorf("got %q, want shields.io endpoint prefix", got)
	}
	if strings.Contains(got, "deadbeef") {
		t.Errorf("got %q, should not contain commit hash", got)
	}
	if !strings.Contains(got, "badge.json") {
		t.Errorf("got %q, should contain filename", got)
	}
}

func TestDefaultGistFilenames(t *testing.T) {
	tests := []struct {
		customBase string
		scanMode   string
		wantBadge  string
		wantReport string
		wantGrype  string
	}{
		{"", "release", "grype-release.json", "grype-release.md", "grype-release-grype.json"},
		{"", "image", "grype-image.json", "grype-image.md", "grype-image-grype.json"},
		{"my-scan", "release", "my-scan.json", "my-scan.md", "my-scan-grype.json"},
		{"custom", "head", "custom.json", "custom.md", "custom-grype.json"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.customBase, tt.scanMode), func(t *testing.T) {
			badge, report, grype := defaultGistFilenames(tt.customBase, tt.scanMode)
			if badge != tt.wantBadge {
				t.Errorf("badge = %q, want %q", badge, tt.wantBadge)
			}
			if report != tt.wantReport {
				t.Errorf("report = %q, want %q", report, tt.wantReport)
			}
			if grype != tt.wantGrype {
				t.Errorf("grype = %q, want %q", grype, tt.wantGrype)
			}
		})
	}
}

func TestBuildGistFileAnchor(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "basic md", in: "grype-release.md", want: "file-grype-release-md"},
		{name: "underscores", in: "grype_me-action_release.md", want: "file-grype-me-action-release-md"},
		{name: "mixed chars", in: "My Report (Nightly).md", want: "file-my-report-nightly-md"},
		{name: "empty", in: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildGistFileAnchor(tt.in)
			if got != tt.want {
				t.Errorf("buildGistFileAnchor(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestUpdateGist_VerifiesRequestHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify all required headers
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("Accept = %q, want %q", got, "application/vnd.github+json")
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/json")
		}
		if got := r.Header.Get("X-GitHub-Api-Version"); got != "2022-11-28" {
			t.Errorf("X-GitHub-Api-Version = %q, want %q", got, "2022-11-28")
		}

		resp := gistResponse{
			HTMLURL: "https://gist.github.com/user/abc",
			Files:   map[string]gistFileInfo{},
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := &GistClient{
		Token:      "tok",
		HTTPClient: server.Client(),
		BaseURL:    server.URL,
	}

	_, err := client.UpdateGist("abc", "b.json", "r.md", map[string]string{
		"b.json": "{}",
		"r.md":   "# R",
	})
	if err != nil {
		t.Fatalf("UpdateGist() error = %v", err)
	}
}
