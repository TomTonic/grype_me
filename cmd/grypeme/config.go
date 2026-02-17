// Package main provides configuration loading for the Grype GitHub Action.
package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// loadConfig reads all action inputs from environment variables and returns a Config struct.
// GitHub Actions passes inputs as environment variables with the INPUT_ prefix.
// For example, the "scan" input becomes "INPUT_SCAN".
func loadConfig() Config {
	return Config{
		Scan:           getEnv("INPUT_SCAN", ""),
		Image:          getEnv("INPUT_IMAGE", ""),
		Path:           getEnv("INPUT_PATH", ""),
		SBOM:           getEnv("INPUT_SBOM", ""),
		FailBuild:      parseBoolEnv("INPUT_FAIL-BUILD", false),
		SeverityCutoff: strings.ToLower(getEnv("INPUT_SEVERITY-CUTOFF", "medium")),
		OutputFile:     getEnv("INPUT_OUTPUT-FILE", ""),
		OnlyFixed:      parseBoolEnv("INPUT_ONLY-FIXED", false),
		DBUpdate:       parseBoolEnv("INPUT_DB-UPDATE", false),
		Debug:          parseBoolEnv("INPUT_DEBUG", false),
		Description:    getEnv("INPUT_DESCRIPTION", ""),
		GistToken:      getEnv("INPUT_GIST-TOKEN", ""),
		GistID:         getEnv("INPUT_GIST-ID", ""),
		GistFilename:   getEnv("INPUT_GIST-FILENAME", ""),
	}
}

// getEnv retrieves an environment variable value, returning defaultValue if not set or empty.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseBoolEnv parses a boolean environment variable (case-insensitive "true" check).
// Returns defaultValue if the variable is not set or empty.
func parseBoolEnv(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return strings.EqualFold(value, "true")
}

// isDebugEnabled checks if debug mode is enabled via the INPUT_DEBUG environment variable.
// This is a convenience function that can be called without loading the full config.
func isDebugEnabled() bool {
	return parseBoolEnv("INPUT_DEBUG", false)
}

// printDebugEnv prints all relevant environment variables for debugging purposes.
// Only variables with INPUT_ or GITHUB_ prefixes are printed (sorted alphabetically).
func printDebugEnv() {
	fmt.Println("=== Environment Variables (sorted) ===")

	var relevantVars []string
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "INPUT_") || strings.HasPrefix(env, "GITHUB_") {
			relevantVars = append(relevantVars, env)
		}
	}

	sort.Strings(relevantVars)
	for _, envVar := range relevantVars {
		fmt.Println(envVar)
	}

	fmt.Println("======================================")
}

// determineScanMode returns a human-readable scan mode string for display and badge labels.
// It determines the mode based on which config options are set.
func determineScanMode(config Config) string {
	switch {
	case config.Image != "":
		return "image"
	case config.Path != "":
		return "path"
	case config.SBOM != "":
		return "sbom"
	default:
		// Repository scan mode
		scan := config.Scan
		if scan == "" {
			scan = "latest_release"
		}
		switch scan {
		case "latest_release":
			return "release"
		case "head":
			return "head"
		default:
			return "ref"
		}
	}
}
