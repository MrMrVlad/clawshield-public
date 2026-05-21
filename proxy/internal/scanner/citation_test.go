package scanner

import (
	"encoding/json"
	"testing"
)

func TestCitationScanner_UngroundedDOI(t *testing.T) {
	c := NewCitationScanner(&CitationScanConfig{Enabled: true, ScanResponses: true, Rules: []string{"doi"}})
	toolOut := json.RawMessage(`{"summary": "no papers"}`)
	resp := "See DOI 10.1234/example.5678 for details."
	findings := c.ScanResponse(resp, toolOut)
	if len(findings) == 0 {
		t.Fatal("expected ungrounded DOI finding")
	}
	if findings[0].Rule != "doi" {
		t.Fatalf("got rule %s", findings[0].Rule)
	}
}

func TestCitationScanner_GroundedDOI(t *testing.T) {
	c := NewCitationScanner(&CitationScanConfig{Enabled: true, ScanResponses: true, Rules: []string{"doi"}})
	toolOut := json.RawMessage(`{"doi": "10.1234/example.5678"}`)
	resp := "The paper 10.1234/example.5678 confirms this."
	if len(c.ScanResponse(resp, toolOut)) != 0 {
		t.Fatal("expected no findings when DOI in tool output")
	}
}
