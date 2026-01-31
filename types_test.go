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
			{Vulnerability: struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			}{ID: "CVE-2021-1234", Severity: "High"}},
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
}

func TestGrypeMatchStructure(t *testing.T) {
	jsonData := `{"vulnerability": {"id": "CVE-2023-45678", "severity": "Critical"}}`

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
