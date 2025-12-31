package detector

import (
	"fmt"
	"testing"

	"github.com/ahmedtouahria/waf-detector/scanner"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("NewDetector returned nil")
	}
	if len(d.signatures) == 0 {
		t.Error("Detector should have signatures loaded")
	}
}

func TestDetectNoProbes(t *testing.T) {
	d := NewDetector()
	probes := make(map[scanner.ProbeType]*scanner.ProbeResult)

	result := d.Detect(probes)
	if result.WAFDetected {
		t.Error("Should not detect WAF with no probes")
	}
}

func TestDetectNormalProbeError(t *testing.T) {
	d := NewDetector()
	probes := map[scanner.ProbeType]*scanner.ProbeResult{
		scanner.ProbeNormal: {
			Error: fmt.Errorf("connection error"),
		},
	}

	result := d.Detect(probes)
	if result.WAFDetected {
		t.Error("Should not detect WAF when normal probe fails")
	}
	if result.Details != "Unable to establish baseline connection" {
		t.Errorf("Unexpected details: %s", result.Details)
	}
}

func TestDetectNoWAFBehavior(t *testing.T) {
	d := NewDetector()
	probes := map[scanner.ProbeType]*scanner.ProbeResult{
		scanner.ProbeNormal: {
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/html"}},
			Body:       "Normal response",
		},
		scanner.ProbeSQLi: {
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/html"}},
			Body:       "Normal response",
		},
		scanner.ProbeXSS: {
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/html"}},
			Body:       "Normal response",
		},
		scanner.ProbeMalformed: {
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"text/html"}},
			Body:       "Normal response",
		},
	}

	result := d.Detect(probes)
	if result.WAFDetected {
		t.Error("Should not detect WAF with identical responses")
	}
}

func TestDetectWAFBehaviorStatusCodeChange(t *testing.T) {
	d := NewDetector()
	probes := map[scanner.ProbeType]*scanner.ProbeResult{
		scanner.ProbeNormal: {
			StatusCode: 200,
			Headers:    map[string][]string{},
			Body:       "Normal",
		},
		scanner.ProbeSQLi: {
			StatusCode: 403,
			Headers:    map[string][]string{},
			Body:       "Forbidden",
		},
		scanner.ProbeXSS: {
			StatusCode: 403,
			Headers:    map[string][]string{},
			Body:       "Blocked",
		},
	}

	result := d.Detect(probes)
	if !result.WAFDetected {
		t.Error("Should detect WAF behavior with status code change")
	}
}
