package detector

import (
	"strings"

	"github.com/wafw00f/waf-detector/scanner"
	"github.com/wafw00f/waf-detector/signatures"
)

type Detection struct {
	WAFDetected bool
	WAFName     string
	Confidence  float64
	Details     string
}

type Detector struct {
	signatures []signatures.Signature
}

func NewDetector() *Detector {
	return &Detector{
		signatures: signatures.GetAllSignatures(),
	}
}

func (d *Detector) Detect(probes map[scanner.ProbeType]*scanner.ProbeResult) Detection {
	normal := probes[scanner.ProbeNormal]
	sqli := probes[scanner.ProbeSQLi]
	xss := probes[scanner.ProbeXSS]
	malformed := probes[scanner.ProbeMalformed]

	if normal == nil || normal.Error != nil {
		return Detection{
			WAFDetected: false,
			Details:     "Unable to establish baseline connection",
		}
	}

	wafDetected := d.detectWAFBehavior(normal, sqli, xss, malformed)

	if !wafDetected {
		return Detection{
			WAFDetected: false,
			Details:     "No WAF-like behavior detected",
		}
	}

	wafName, confidence := d.fingerprint(probes)

	details := "WAF behavior detected"
	if wafName != "" {
		details = "WAF identified based on response patterns"
	}

	return Detection{
		WAFDetected: true,
		WAFName:     wafName,
		Confidence:  confidence,
		Details:     details,
	}
}

func (d *Detector) detectWAFBehavior(normal, sqli, xss, malformed *scanner.ProbeResult) bool {
	blockingIndicators := 0

	if sqli != nil && sqli.Error == nil {
		if d.isBlocked(sqli, normal) {
			blockingIndicators++
		}
	}

	if xss != nil && xss.Error == nil {
		if d.isBlocked(xss, normal) {
			blockingIndicators++
		}
	}

	if malformed != nil && malformed.Error == nil {
		if d.isBlocked(malformed, normal) {
			blockingIndicators++
		}
	}

	return blockingIndicators >= 2
}

func (d *Detector) isBlocked(probe, baseline *scanner.ProbeResult) bool {
	if probe.StatusCode == 403 || probe.StatusCode == 406 || probe.StatusCode == 419 || probe.StatusCode == 429 {
		return true
	}

	if probe.StatusCode >= 500 && probe.StatusCode <= 599 && baseline.StatusCode < 400 {
		return true
	}

	if probe.StatusCode != baseline.StatusCode {
		blockKeywords := []string{
			"blocked", "forbidden", "access denied", "security",
			"firewall", "not acceptable", "rejected", "suspicious",
		}

		bodyLower := strings.ToLower(probe.Body)
		for _, keyword := range blockKeywords {
			if strings.Contains(bodyLower, keyword) {
				return true
			}
		}
	}

	return false
}

func (d *Detector) fingerprint(probes map[scanner.ProbeType]*scanner.ProbeResult) (string, float64) {
	var bestMatch string
	var bestConfidence float64

	for _, sig := range d.signatures {
		confidence := sig.Match(probes)
		if confidence > bestConfidence {
			bestConfidence = confidence
			bestMatch = sig.Name()
		}
	}

	if bestConfidence < 0.3 {
		return "Unknown WAF", 0.0
	}

	return bestMatch, bestConfidence
}
