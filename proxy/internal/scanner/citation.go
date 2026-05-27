package scanner

import (
	"encoding/json"
	"regexp"
	"strings"
)

// CitationScanConfig configures citation/reference hallucination detection on responses.
type CitationScanConfig struct {
	Enabled        bool     `yaml:"enabled"`
	ScanResponses  bool     `yaml:"scan_responses"`
	Rules          []string `yaml:"rules"` // doi, isbn, arxiv, pmid, url_not_in_tool
}

// CitationScanner detects bibliographic references not grounded in tool output.
type CitationScanner struct {
	scanResponses bool
	rules         map[string]bool

	doiPat   *regexp.Regexp
	isbnPat  *regexp.Regexp
	arxivPat *regexp.Regexp
	pmidPat  *regexp.Regexp
	urlPat   *regexp.Regexp
}

// CitationFinding is a single detected ungrounded reference.
type CitationFinding struct {
	Rule       string  `json:"rule"`
	Reference  string  `json:"reference"`
	Confidence float64 `json:"confidence"`
}

// NewCitationScanner creates a scanner from policy config.
func NewCitationScanner(cfg *CitationScanConfig) *CitationScanner {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	rules := map[string]bool{"doi": true, "isbn": true, "arxiv": true, "pmid": true, "url_not_in_tool": true}
	if len(cfg.Rules) > 0 {
		rules = make(map[string]bool)
		for _, r := range cfg.Rules {
			rules[r] = true
		}
	}
	return &CitationScanner{
		scanResponses: cfg.ScanResponses,
		rules:         rules,
		doiPat:        regexp.MustCompile(`(?i)\b10\.\d{4,9}/[-._;()/:A-Z0-9]+\b`),
		isbnPat:       regexp.MustCompile(`(?i)\b(?:ISBN[- ]?(?:1[03])?:? )?(?:\d[- ]?){9}[\dX]\b`),
		arxivPat:      regexp.MustCompile(`(?i)\barxiv:\d{4}\.\d{4,5}(?:v\d+)?\b`),
		pmidPat:       regexp.MustCompile(`(?i)\bPMID:\s*\d{6,9}\b`),
		urlPat:        regexp.MustCompile(`https?://[^\s"'<>]+`),
	}
}

// ScanResponse checks agent text against optional tool output JSON for grounding.
func (c *CitationScanner) ScanResponse(responseText string, toolOutput json.RawMessage) []CitationFinding {
	if c == nil || !c.scanResponses {
		return nil
	}
	ground := strings.ToLower(string(toolOutput))
	lower := strings.ToLower(responseText)
	var findings []CitationFinding

	if c.rules["doi"] {
		for _, m := range c.doiPat.FindAllString(lower, 20) {
			if !strings.Contains(ground, strings.ToLower(m)) {
				findings = append(findings, CitationFinding{Rule: "doi", Reference: m, Confidence: 0.85})
			}
		}
	}
	if c.rules["isbn"] {
		for _, m := range c.isbnPat.FindAllString(responseText, 10) {
			if !strings.Contains(ground, strings.ToLower(m)) {
				findings = append(findings, CitationFinding{Rule: "isbn", Reference: m, Confidence: 0.8})
			}
		}
	}
	if c.rules["arxiv"] {
		for _, m := range c.arxivPat.FindAllString(lower, 10) {
			if !strings.Contains(ground, strings.ToLower(m)) {
				findings = append(findings, CitationFinding{Rule: "arxiv", Reference: m, Confidence: 0.85})
			}
		}
	}
	if c.rules["pmid"] {
		for _, m := range c.pmidPat.FindAllString(lower, 10) {
			if !strings.Contains(ground, strings.ToLower(m)) {
				findings = append(findings, CitationFinding{Rule: "pmid", Reference: m, Confidence: 0.8})
			}
		}
	}
	if c.rules["url_not_in_tool"] && len(toolOutput) > 0 {
		for _, u := range c.urlPat.FindAllString(lower, 30) {
			if len(u) > 2048 {
				u = u[:2048]
			}
			if !strings.Contains(ground, u) {
				findings = append(findings, CitationFinding{Rule: "url_not_in_tool", Reference: u, Confidence: 0.65})
			}
		}
	}
	return findings
}
