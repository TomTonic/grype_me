// Package main provides GitHub Gist integration for the Grype GitHub Action.
// It allows writing badge JSON and scan reports directly to a GitHub Gist
// via the GitHub API, eliminating the need for external badge actions.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GistClient handles communication with the GitHub Gist API.
type GistClient struct {
	Token      string       // GitHub token with gist scope
	HTTPClient *http.Client // HTTP client (injectable for testing)
	BaseURL    string       // API base URL (default: https://api.github.com)
}

// NewGistClient creates a GistClient with the given token and sensible defaults.
func NewGistClient(token string) *GistClient {
	return &GistClient{
		Token:      token,
		HTTPClient: http.DefaultClient,
		BaseURL:    "https://api.github.com",
	}
}

// GistFile represents a single file in a gist update request.
type GistFile struct {
	Content string `json:"content"`
}

// gistUpdateRequest is the request body for PATCH /gists/{gist_id}.
type gistUpdateRequest struct {
	Files map[string]GistFile `json:"files"`
}

// gistResponse is a minimal representation of the GitHub API gist response.
type gistResponse struct {
	HTMLURL string                  `json:"html_url"`
	Files   map[string]gistFileInfo `json:"files"`
}

// gistFileInfo contains per-file metadata from the gist response.
type gistFileInfo struct {
	RawURL string `json:"raw_url"`
}

// GistResult contains the URLs returned after a successful gist update.
type GistResult struct {
	GistURL   string // HTML URL of the gist (e.g., https://gist.github.com/user/abc123)
	BadgeURL  string // shields.io endpoint URL pointing to the badge JSON in the gist
	ReportURL string // Raw URL of the Markdown report file in the gist
}

// UpdateGist writes files to a GitHub Gist and returns the resulting URLs.
// The badgeFilename and reportFilename parameters identify which files in
// the map should be used for badge and report URL extraction.
//
// Parameters:
//   - gistID: The ID of the gist to update (must already exist)
//   - badgeFilename: Key in files map for the shields.io badge JSON
//   - reportFilename: Key in files map for the Markdown report
//   - files: Map of filename → content for all files to write to the gist
func (c *GistClient) UpdateGist(gistID, badgeFilename, reportFilename string, files map[string]string) (*GistResult, error) {
	gistFiles := make(map[string]GistFile, len(files))
	for name, content := range files {
		gistFiles[name] = GistFile{Content: content}
	}

	reqBody := gistUpdateRequest{
		Files: gistFiles,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal gist request: %w", err)
	}

	apiURL := fmt.Sprintf("%s/gists/%s", c.BaseURL, gistID)
	req, err := http.NewRequest(http.MethodPatch, apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "token "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gist API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read gist response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gist API returned %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var gistResp gistResponse
	if err := json.Unmarshal(respBody, &gistResp); err != nil {
		return nil, fmt.Errorf("failed to parse gist response: %w", err)
	}

	result := &GistResult{
		GistURL: gistResp.HTMLURL,
	}

	// Extract raw URLs for badge and report files
	if fi, ok := gistResp.Files[badgeFilename]; ok {
		// Strip commit hash from raw URL for a stable endpoint
		result.BadgeURL = buildEndpointBadgeURL(fi.RawURL)
	}
	if fi, ok := gistResp.Files[reportFilename]; ok {
		result.ReportURL = fi.RawURL
	}

	return result, nil
}

// buildEndpointBadgeURL creates a shields.io endpoint URL from a gist raw URL.
// It strips the commit hash from the raw URL so the badge always shows the latest content.
// Input:  https://gist.githubusercontent.com/user/id/raw/commithash/file.json
// Output: https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/user/id/raw/file.json
func buildEndpointBadgeURL(rawURL string) string {
	// Strip the commit hash segment: .../raw/<hash>/<file> → .../raw/<file>
	stableURL := stripCommitHash(rawURL)
	return fmt.Sprintf("https://img.shields.io/endpoint?url=%s", stableURL)
}

// stripCommitHash removes the commit hash from a gist raw URL.
// Input:  https://gist.githubusercontent.com/user/gistid/raw/abc123def/filename.json
// Output: https://gist.githubusercontent.com/user/gistid/raw/filename.json
func stripCommitHash(rawURL string) string {
	// Find "/raw/" and strip the path segment after it (the commit hash)
	idx := strings.Index(rawURL, "/raw/")
	if idx < 0 {
		return rawURL
	}
	prefix := rawURL[:idx+len("/raw/")]
	rest := rawURL[idx+len("/raw/"):]

	// rest is "<commithash>/<filename>" — strip the hash
	if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
		return prefix + rest[slashIdx+1:]
	}
	return rawURL
}

// defaultGistFilenames returns the badge, report, and raw grype JSON filenames
// based on scan mode. If a custom base filename is provided, it is used;
// otherwise one is auto-generated from the scan mode.
func defaultGistFilenames(customBase, scanMode string) (badgeFilename, reportFilename, grypeFilename string) {
	base := customBase
	if base == "" {
		base = fmt.Sprintf("grype-%s", scanMode)
	}
	return base + ".json", base + ".md", base + "-grype.json"
}
