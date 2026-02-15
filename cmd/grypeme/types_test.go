package main

import (
	"encoding/json"
	"testing"
)

func TestGrypeOutputDBBuilt(t *testing.T) {
	tests := []struct {
		name   string
		output *GrypeOutput
		want   string
	}{
		{
			name:   "nil output",
			output: nil,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.output.DBBuilt()
			if got != tt.want {
				t.Errorf("DBBuilt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGrypeOutputJSONMarshaling(t *testing.T) {
	original := &GrypeOutput{
		Matches: []GrypeMatch{
			makeMatch("CVE-2021-1234", "High", "openssl", "1.1.1", []string{"1.1.2"}, "Buffer overflow", "https://nvd.nist.gov"),
		},
	}
	original.Descriptor.Version = "0.106.0"
	original.Descriptor.DB.Status.Built = "2024-01-01"

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var unmarshaled GrypeOutput
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if len(unmarshaled.Matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(unmarshaled.Matches))
	}
	if unmarshaled.DBBuilt() != "2024-01-01" {
		t.Errorf("DBBuilt() = %v, want 2024-01-01", unmarshaled.DBBuilt())
	}
	m := unmarshaled.Matches[0]
	if m.Vulnerability.ID != "CVE-2021-1234" {
		t.Errorf("ID = %v, want CVE-2021-1234", m.Vulnerability.ID)
	}
	if m.Artifact.Name != "openssl" {
		t.Errorf("Artifact.Name = %v, want openssl", m.Artifact.Name)
	}
	if m.Vulnerability.Description != "Buffer overflow" {
		t.Errorf("Description = %v, want Buffer overflow", m.Vulnerability.Description)
	}
}

func TestGrypeMatchStructure(t *testing.T) {
	jsonData := `{
		"vulnerability": {
			"id": "CVE-2023-45678",
			"severity": "Critical",
			"description": "A serious flaw",
			"dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2023-45678",
			"fix": {"versions": ["2.0.1"], "state": "fixed"}
		},
		"artifact": {
			"name": "libfoo",
			"version": "1.9.0",
			"type": "deb"
		}
	}`

	var match GrypeMatch
	if err := json.Unmarshal([]byte(jsonData), &match); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if match.Vulnerability.ID != "CVE-2023-45678" {
		t.Errorf("ID = %v, want CVE-2023-45678", match.Vulnerability.ID)
	}
	if match.Vulnerability.Severity != "Critical" {
		t.Errorf("Severity = %v, want Critical", match.Vulnerability.Severity)
	}
	if match.Vulnerability.Description != "A serious flaw" {
		t.Errorf("Description = %v, want A serious flaw", match.Vulnerability.Description)
	}
	if match.Vulnerability.DataSource != "https://nvd.nist.gov/vuln/detail/CVE-2023-45678" {
		t.Errorf("DataSource = %v, want NVD URL", match.Vulnerability.DataSource)
	}
	if len(match.Vulnerability.Fix.Versions) != 1 || match.Vulnerability.Fix.Versions[0] != "2.0.1" {
		t.Errorf("Fix.Versions = %v, want [2.0.1]", match.Vulnerability.Fix.Versions)
	}
	if match.Artifact.Name != "libfoo" {
		t.Errorf("Artifact.Name = %v, want libfoo", match.Artifact.Name)
	}
	if match.Artifact.Version != "1.9.0" {
		t.Errorf("Artifact.Version = %v, want 1.9.0", match.Artifact.Version)
	}
}

func TestVulnerabilityStatsZeroValue(t *testing.T) {
	stats := VulnerabilityStats{}

	if stats.Total != 0 {
		t.Errorf("Total = %v, want 0", stats.Total)
	}
	if stats.Critical != 0 {
		t.Errorf("Critical = %v, want 0", stats.Critical)
	}
	if stats.High != 0 {
		t.Errorf("High = %v, want 0", stats.High)
	}
	if stats.Medium != 0 {
		t.Errorf("Medium = %v, want 0", stats.Medium)
	}
	if stats.Low != 0 {
		t.Errorf("Low = %v, want 0", stats.Low)
	}
	if stats.Other != 0 {
		t.Errorf("Other = %v, want 0", stats.Other)
	}
}
